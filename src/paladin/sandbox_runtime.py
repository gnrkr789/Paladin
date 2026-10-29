"""Private-alpha Docker execution with a separate privileged syscall observer.

Only Docker CLI commands run on the host. There is deliberately no local target
execution fallback. Images are addressed by immutable local image ID after build.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

OBSERVER_ID = 'docker-strace-execve-v3'
# Exceeds the observer's own PID wait (60 s) plus trace limit (18 s) so its reason survives.
CASE_TIMEOUT_SECONDS = 120
INFRASTRUCTURE_ATTEMPTS = 3
RETRYABLE = {'sandbox_execution_failed', 'sandbox_docker_unavailable_or_timeout'}
ASSETS = Path(__file__).parent / 'resources' / 'sandbox'
ASSET_NAMES = ('Dockerfile', 'observer.py', 'target.py', 'trace_grammar.py')
IMAGE_PATTERN = re.compile(r'sha256:[0-9a-f]{64}\Z')


def trace_grammar():
    """Load the exact grammar module that is copied into the observer image."""
    spec = importlib.util.spec_from_file_location('paladin_trace_grammar', ASSETS / 'trace_grammar.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _docker(arguments, *, payload=None, timeout=40):
    try:
        result = subprocess.run(['docker', *arguments], input=payload, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('sandbox_docker_unavailable_or_timeout') from exc
    if result.returncode:
        raise ValueError('sandbox_docker_failed:' + result.stderr.decode('utf-8', 'replace')[-2000:])
    return result.stdout


def _record(directory, name, content):
    if directory is not None:
        destination = Path(directory)
        destination.mkdir(parents=True, exist_ok=True)
        (destination / name).write_bytes(content)


def build_runtime(evidence_dir=None):
    """Build explicitly requested Linux dependencies; return immutable identity."""
    assets = [ASSETS / name for name in ASSET_NAMES]
    if any(not path.is_file() or path.is_symlink() for path in assets):
        raise ValueError('sandbox_missing_or_linked_build_asset')
    context = b''.join(path.name.encode('ascii') + b'\0' + path.read_bytes() for path in assets)
    with tempfile.TemporaryDirectory(prefix='paladin-image-identity-') as temporary:
        identity_file = Path(temporary) / 'image.id'
        try:
            result = subprocess.run(['docker', 'build', '--progress=plain', '--iidfile',
                                    str(identity_file), str(ASSETS)], stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=600, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError('sandbox_build_unavailable_or_timeout') from exc
        built_identity = identity_file.read_text(encoding='ascii').strip() if identity_file.exists() else ''
    _record(evidence_dir, 'build.log', result.stdout)
    if result.returncode:
        raise ValueError('sandbox_image_build_failed')
    # Docker writes the build result ID independently of its human-readable log.
    if not IMAGE_PATTERN.fullmatch(built_identity):
        raise ValueError('sandbox_build_image_identity_missing')
    identity = _docker(['image', 'inspect', '--format={{.Id}}', built_identity]).decode('ascii').strip()
    if not IMAGE_PATTERN.fullmatch(identity):
        raise ValueError('sandbox_build_invalid_image_identity')
    return {'image_id': identity, 'observer_id': OBSERVER_ID,
            'build_context_sha256': _sha(context), 'build_log_sha256': _sha(result.stdout)}


def container_arguments(image_id, name):
    """The reviewed container boundary; no host paths are mounted."""
    if not IMAGE_PATTERN.fullmatch(image_id):
        raise ValueError('sandbox_requires_immutable_image_id')
    return ['create', '--name', name, '--interactive', '--network=none', '--read-only',
            '--cap-drop=ALL', '--cap-add=SYS_PTRACE', '--security-opt=no-new-privileges:true',
            '--pids-limit=64', '--memory=256m', '--memory-swap=256m', '--cpus=1',
            '--ulimit=nofile=128:128', '--ulimit=fsize=2097152:2097152',
            '--tmpfs=/work:rw,nosuid,nodev,noexec,size=32m,mode=1777',
            '--tmpfs=/observer:rw,nosuid,nodev,noexec,size=8m,mode=0700',
            '--tmpfs=/fixtures:rw,nosuid,nodev,noexec,size=32m,mode=0755',
            '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=8m,mode=1777', image_id]


def validate_output(output, source, case, adapter):
    """Host checks of one observer payload; parsed calls are re-derived from the trace."""
    observer = output['observer']
    if (observer['id'] != OBSERVER_ID or observer['target_uid'] != 65534
            or observer['target_cap_eff'] != 0 or observer['trace_owner_uid'] != 0
            or observer['target_no_new_privs'] is not True or observer['adapter'] != adapter
            or observer['target_seccomp_filters'] != observer['container_seccomp_filters'] + 1
            or observer['trace_mode'] != '0o600' or observer['target_stdout_used'] is not False
            or observer['source_sha256'] != _sha(source)):
        raise ValueError('sandbox_invalid_observer_credentials')
    row = output['observation']
    if any(row.get(key) != case[key] for key in ('kind', 'value', 'role')):
        raise ValueError('sandbox_invalid_case_identity')
    if row['trace_sha256'] != _sha(row['trace'].encode('ascii')):
        raise ValueError('sandbox_trace_integrity_failed')
    parsed = trace_grammar().parse_trace(row['trace'], row['target_pid'], row['target_cwd'])
    if any(parsed[key] != row[key] for key in ('calls', 'target_exit_code', 'path_alias_created')):
        raise ValueError('sandbox_trace_parse_disagrees')
    return output


def _one_case(source, image_id, case, adapter):
    name = 'paladin-observer-' + uuid.uuid4().hex
    container = _docker(container_arguments(image_id, name), timeout=120).decode('ascii').strip()
    start = None
    target = None
    try:
        start = subprocess.Popen(['docker', 'start', '--attach', '--interactive', container],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        request = json.dumps({'source': base64.b64encode(source).decode('ascii'),
                              'case': case, 'adapter': adapter}).encode('ascii')
        start.stdin.write(request)
        start.stdin.close()
        start.stdin = None
        deadline = time.monotonic() + 60
        while True:
            ready = subprocess.run(['docker', 'exec', '--user=0:0', container,
                                    'test', '-f', '/observer/ready'], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=20, check=False)
            if ready.returncode == 0:
                break
            if start.poll() is not None or time.monotonic() > deadline:
                _, error = start.communicate(timeout=5)
                raise ValueError('sandbox_observer_not_ready:' + error.decode('utf-8', 'replace')[-2000:])
            time.sleep(0.1)
        # Docker daemon changes credentials; the observer retains only PTRACE.
        # Target output cannot enter the trusted observer protocol.
        target = subprocess.Popen(['docker', 'exec', '--user=65534:65534', container,
                                   'python', '-I', '-B', '/opt/paladin/target.py'],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        stdout, stderr = start.communicate(timeout=CASE_TIMEOUT_SECONDS)
        target.wait(timeout=30)
        if start.returncode != 0 or len(stdout) > 2_000_000:
            raise ValueError('sandbox_observation_failed:' + stderr.decode('utf-8', 'replace')[-2000:])
        return validate_output(json.loads(stdout), source, case, adapter)
    except (subprocess.TimeoutExpired, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError('sandbox_execution_failed') from exc
    finally:
        # Removing the container kills the complete target process tree even if
        # target code forked or the attached Docker CLI hit its timeout.
        for _ in range(3):
            try:
                _docker(['rm', '--force', container], timeout=60)
                break
            except ValueError:
                continue  # Never mask the original error; the CLI processes are killed below.
        for process in (target, start):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def run_observed(source_bytes, image_id, cases, evidence_dir=None, *, adapter='cookiecutter'):
    """Execute each case in a fresh container; return root-observed execve data."""
    if not isinstance(source_bytes, bytes) or len(source_bytes) > 1_000_000:
        raise ValueError('sandbox_invalid_source')
    if not IMAGE_PATTERN.fullmatch(image_id):
        raise ValueError('sandbox_requires_immutable_image_id')
    if not isinstance(cases, list) or not 1 <= len(cases) <= 12:
        raise ValueError('sandbox_invalid_cases')
    if adapter not in {'cookiecutter', 'pip-mercurial'}:
        raise ValueError('sandbox_invalid_adapter')
    for case in cases:
        if (set(case) != {'kind', 'value', 'role'} or case['kind'] not in {'hg', 'git'}
                or not isinstance(case['value'], str) or len(case['value']) > 200
                or case['role'] not in {'risk', 'ordinary', 'literal'}
                or not case['value'].isascii() or any(ord(c) < 32 for c in case['value'])):
            raise ValueError('sandbox_invalid_case')
    outcomes, retries = [], 0
    for index, case in enumerate(cases):
        for attempt in range(INFRASTRUCTURE_ATTEMPTS):
            try:
                observed = _one_case(source_bytes, image_id, case, adapter)
                break
            except ValueError as exc:
                # Only Docker CLI timeouts/unavailability retry, each in a fresh container.
                # Observer verdicts, trace rejections and credential failures never retry.
                if (str(exc).split(':', 1)[0] not in RETRYABLE
                        or attempt == INFRASTRUCTURE_ATTEMPTS - 1):
                    raise
                retries += 1
        outcomes.append(observed['observation'])
        _record(evidence_dir, str(index) + '.json', json.dumps(observed, indent=2).encode('ascii'))
        _record(evidence_dir, str(index) + '.trace', observed['observation']['trace'].encode('ascii'))
    return {'observations': outcomes, 'observer': dict(observed['observer'], image_id=image_id,
            boundary={'network': 'none', 'rootfs_readonly': True, 'host_mounts': False,
                      'capabilities': ['SYS_PTRACE'], 'no_new_privileges': True,
                      'target_seccomp': 'deny clone CLONE_UNTRACED (EPERM), clone3 (ENOSYS)',
                      'pids_limit': 64, 'memory_bytes': 268435456, 'cpus': 1,
                      'per_case_timeout_seconds': CASE_TIMEOUT_SECONDS, 'target_execution_timeout_seconds': 18}),
            'trace_sha256': _sha(''.join(row['trace_sha256'] for row in outcomes).encode('ascii')),
            'infrastructure_retries': retries}


def run_boundary_checks(image_id, evidence_dir=None):
    """Execute fixed adversarial controls, separate from project verification."""
    case = [{'kind': 'hg', 'value': 'stable', 'role': 'ordinary'}]
    forged = run_observed(b'print(\'{"safe_ok": true, "observations": []}\')\nraise SystemExit(0)\n',
                          image_id, case,
                          None if evidence_dir is None else Path(evidence_dir) / 'forged-output')
    controls_source = b'''import ctypes, os, signal, socket, subprocess
def mark(label):
    subprocess.run(['/bin/true', 'paladin-control-' + label], check=True)
libc = ctypes.CDLL(None, use_errno=True)
clone_number = {'x86_64': 56, 'aarch64': 220}[os.uname().machine]
child = libc.syscall(clone_number, 0x00800000 | 17, 0, 0, 0, 0)
if child == 0:
    os.execv('/bin/true', ['/bin/true', 'paladin-control-untraced-escape'])
elif child < 0 and ctypes.get_errno() == 1:
    mark('untraced-clone-blocked')
else:
    os.waitpid(child, 0)
if libc.syscall(435, 0, 0) < 0 and ctypes.get_errno() == 38:
    mark('clone3-unavailable')
for path, label in [('/opt/paladin/observer.py', 'readonly'), ('/observer/trace', 'observer-private')]:
    try:
        open(path, 'w').write('tampered')
    except OSError:
        mark(label)
try:
    os.kill(1, signal.SIGTERM)
except PermissionError:
    mark('observer-signal-protected')
try:
    socket.create_connection(('1.1.1.1', 443), timeout=0.5).close()
except OSError:
    mark('network-unreachable')
status = open('/proc/self/status').read()
if os.getuid() == 65534 and 'NoNewPrivs:\\t1' in status:
    mark('unprivileged')
raise SystemExit(0)
'''
    controls = run_observed(controls_source, image_id, case,
                            None if evidence_dir is None else Path(evidence_dir) / 'controls')
    markers = {call['argv'][1] for call in controls['observations'][0]['calls']
               if len(call['argv']) == 2 and call['argv'][0] == '/bin/true' and call['exit_code'] == 0}
    expected = {'paladin-control-' + name for name in ('readonly', 'observer-private',
                'observer-signal-protected', 'network-unreachable', 'unprivileged',
                'untraced-clone-blocked', 'clone3-unavailable')}
    forged_row = forged['observations'][0]
    # The escape marker is a sanity assertion only: an untraced child is invisible
    # by construction. The decisive control is 'untraced-clone-blocked'.
    return {'passed': expected <= markers and forged_row['calls'] == []
            and 'paladin-control-untraced-escape' not in markers
            and forged_row['target_exit_code'] == 0 and forged_row['safe_ok'] is False,
            'executed_controls': sorted(markers), 'forged_output_ignored': not forged_row['calls'],
            'controls': controls, 'forged_output': forged}
