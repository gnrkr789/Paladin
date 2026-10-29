"""Root observer. Project stdout and project-returned objects are never evidence."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time

sys.path.insert(0, '/opt/paladin')
from trace_grammar import TRACED, parse_trace  # noqa: E402

OBSERVER_ID = 'docker-strace-execve-v3'
PID_TIMEOUT_SECONDS = 60
TRACE_TIMEOUT_SECONDS = 18
# -I ignores PYTHONDONTWRITEBYTECODE; -B keeps imports from writing bytecode in /work.
LAUNCHER = b'python\x00-I\x00-B\x00/opt/paladin/target.py\x00'


def checked(argv, cwd=None):
    return subprocess.run(argv, cwd=cwd, check=True, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE, timeout=20)


def fixtures():
    # Fixture creation precedes all target execution and is outside its trace.
    for kind in ('hg', 'git'):
        repo = Path('/fixtures/' + kind + 'source')
        repo.mkdir(parents=True)
        checked([kind, 'init'], repo)
        (repo / 'README').write_text('Local checkout fixture.\n', encoding='ascii')
        if kind == 'hg':
            checked(['hg', 'add', 'README'], repo)
            checked(['hg', 'commit', '-u', 'Paladin <fixture@example.invalid>', '-m', 'initial'], repo)
            checked(['hg', 'branch', 'stable'], repo)
            checked(['hg', 'commit', '-u', 'Paladin <fixture@example.invalid>', '-m', 'stable'], repo)
            checked(['hg', 'branch', '--', '--literal-branch'], repo)
            checked(['hg', 'commit', '-u', 'Paladin <fixture@example.invalid>', '-m', 'literal'], repo)
            checked(['hg', 'update', 'stable'], repo)
        else:
            checked(['git', '-c', 'user.name=Paladin', '-c', 'user.email=fixture@example.invalid',
                     'add', 'README'], repo)
            checked(['git', '-c', 'user.name=Paladin', '-c', 'user.email=fixture@example.invalid',
                     'commit', '-m', 'initial'], repo)
            checked(['git', 'branch', 'stable'], repo)
    for path in Path('/fixtures').rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)


# Root replay runs only fixed Paladin argv in root-owned clones with a clean
# environment; it never reads files or configuration the target could write.
REPLAY_ROOT = '/observer/replay'
REPLAY_ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/observer', 'HGRCPATH': '/dev/null',
              'HGRCSKIPREPO': '1', 'HGPLAIN': '1', 'GIT_CONFIG_NOSYSTEM': '1',
              'GIT_CONFIG_GLOBAL': '/opt/paladin/gitconfig', 'LC_ALL': 'C'}


def replayable_argv(adapter, kind, value):
    """The only checkout argv shapes a root replay may execute (ordinary and repaired)."""
    if adapter == 'cookiecutter':
        shapes = [[kind, 'checkout', value]]
        return shapes + ([[kind, 'checkout', '--', value]] if kind == 'hg' else [])
    return [['hg', 'update', '--quiet', '-r', value], ['hg', 'update', '--quiet', '--rev=' + value]]


def decisive_checkout(calls, kind):
    checkout = '/work/case/' + kind + 'source'
    found = [call for call in calls if call['argv'][1:2] in (['checkout'], ['update'])]
    if (len(found) != 1 or found[0]['exec_path'] != '/usr/bin/' + kind or found[0]['argv'][0] != kind
            or found[0]['cwd'] != checkout or found[0]['exit_code'] != 0):
        return None
    return found[0]


def replay_branch(adapter, case, calls):
    """Re-run the observed checkout argv in a fresh root clone; return the resulting branch."""
    kind, value = case['kind'], case['value']
    call = decisive_checkout(calls, kind)
    if case['role'] == 'risk' or call is None or call['argv'] not in replayable_argv(adapter, kind, value):
        return None, None
    destination = REPLAY_ROOT + '/' + kind + 'source'
    Path(REPLAY_ROOT).mkdir(mode=0o700)
    clone = ([kind, 'clone', '--noupdate', '--quiet'] if adapter == 'pip-mercurial' else [kind, 'clone', '--quiet'])
    subprocess.run(clone + ['/fixtures/' + kind + 'source', destination], env=REPLAY_ENV, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    replay = subprocess.run(call['argv'], cwd=destination, env=REPLAY_ENV, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=30, check=False)
    if replay.returncode != 0:
        return call['argv'], None
    query = ['hg', 'branch'] if kind == 'hg' else ['git', 'symbolic-ref', '--short', 'HEAD']
    result = subprocess.run(query, cwd=destination, env=REPLAY_ENV, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=30, check=False)
    branch = result.stdout.decode('ascii', 'replace').strip() if result.returncode == 0 else None
    return call['argv'], branch


def checkout_directory_is_real(kind):
    """After every traced process ended, the checkout path must be real directories."""
    path = Path('/work')
    for part in ('case', kind + 'source'):
        path = path / part
        try:
            info = path.lstat()
        except OSError:
            return False
        if not stat.S_ISDIR(info.st_mode):
            return False
    return True


def seccomp_state(status):
    mode = re.search(r'^Seccomp:\s+(\d+)$', status, re.M)
    count = re.search(r'^Seccomp_filters:\s+(\d+)$', status, re.M)
    return (int(mode[1]) if mode else None, int(count[1]) if count else None)


def wait_for_target():
    """Accept only an atomically published PID of the trusted launcher."""
    deadline = time.monotonic() + PID_TIMEOUT_SECONDS
    while time.monotonic() <= deadline:
        try:
            text = Path('/work/target.pid').read_text(encoding='ascii')
        except (OSError, UnicodeError):
            text = ''
        if re.fullmatch(r'[1-9][0-9]{0,9}', text):
            try:
                if Path('/proc/' + text + '/cmdline').read_bytes() == LAUNCHER:
                    return int(text)
            except OSError:
                pass
            raise ValueError('invalid_target_process')
        time.sleep(0.01)
    raise TimeoutError('target_not_started')


def target_credentials(pid):
    status = Path('/proc/' + str(pid) + '/status').read_text(encoding='ascii')
    uid = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)', status, re.M)
    caps = re.search(r'^CapEff:\s+(\w+)', status, re.M)
    privileges = re.search(r'^NoNewPrivs:\s+(\d+)', status, re.M)
    if (not uid or set(uid.groups()) != {'65534'} or not caps or int(caps[1], 16) != 0
            or not privileges or privileges[1] != '1'):
        raise ValueError('invalid_target_credentials')
    # The launcher adds exactly one filter on top of the container profile.
    own = seccomp_state(Path('/proc/self/status').read_text(encoding='ascii'))
    mode, filters = seccomp_state(status)
    if mode != 2 or own[1] is None or filters != own[1] + 1:
        raise ValueError('target_seccomp_missing')
    return {'target_uid': 65534, 'target_cap_eff': 0, 'target_no_new_privs': True,
            'target_seccomp_filters': filters, 'container_seccomp_filters': own[1]}


def main():
    os.umask(0o077)
    request = json.loads(sys.stdin.buffer.read(2_000_000))
    source = base64.b64decode(request['source'], validate=True)
    case = request['case']
    adapter = request.get('adapter', 'cookiecutter')
    Path('/observer').mkdir(exist_ok=True)
    fixtures()
    for name, content in (('source.py', source), ('case.json', json.dumps(case).encode('ascii')),
                          ('adapter', adapter.encode('ascii'))):
        path = Path('/work') / name
        path.write_bytes(content)
        path.chmod(0o444)
    Path('/observer/ready').write_text('ready', encoding='ascii')
    pid = wait_for_target()
    credentials = target_credentials(pid)
    root_cwd = os.readlink('/proc/' + str(pid) + '/cwd')
    trace_path = Path('/observer/trace')
    tracer = subprocess.Popen(['strace', '-f', '-xx', '-s', '65535', '-e', 'trace=' + TRACED,
                               '-o', str(trace_path), '-p', str(pid)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    # strace confirms attach before the immutable launcher loads source bytes.
    selector = selectors.DefaultSelector()
    selector.register(tracer.stderr, selectors.EVENT_READ)
    if not selector.select(5):
        tracer.kill()
        raise ValueError('observer_attach_timeout')
    attached = tracer.stderr.readline()
    if b'attached' not in attached:
        raise ValueError('observer_attach_failed:' + attached.decode('ascii', 'replace'))
    Path('/work/start').write_text('start', encoding='ascii')
    try:
        tracer.communicate(timeout=TRACE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        tracer.kill()
        tracer.communicate()
        raise ValueError('target_timeout')
    trace = trace_path.read_text(encoding='ascii')
    if len(trace) > 1_000_000 or tracer.returncode != 0:
        raise ValueError('invalid_or_overflow_trace')
    parsed = parse_trace(trace, pid, root_cwd)
    exit_code = parsed['target_exit_code']
    replayed_argv, branch = replay_branch(adapter, case, parsed['calls'])
    real_checkout = checkout_directory_is_real(case['kind'])
    row = dict(case, calls=parsed['calls'], target_exit_code=exit_code, target_pid=pid,
               target_cwd=root_cwd, path_alias_created=parsed['path_alias_created'],
               checkout_directory_real=real_checkout,
               error=None if exit_code == 0 else 'target_execution_failed',
               safe_ok=bool(exit_code == 0 and branch == case['value'] and real_checkout
                            and not parsed['path_alias_created']),
               replayed_argv=replayed_argv, replay_branch=branch, trace=trace,
               trace_sha256=hashlib.sha256(trace.encode('ascii')).hexdigest())
    print(json.dumps({'observation': row, 'observer': dict(
        credentials, id=OBSERVER_ID, trace_owner_uid=trace_path.stat().st_uid,
        trace_mode=oct(trace_path.stat().st_mode & 0o777),
        source_sha256=hashlib.sha256(source).hexdigest(), adapter=adapter,
        target_stdout_used=False)}, ensure_ascii=True))


if __name__ == '__main__':
    main()
