"""Unit-only observer rows built from synthetic strace text; no Docker executes."""
import hashlib

from paladin.sandbox_runtime import trace_grammar

ROOT_PID = 10


def encoded(value):
    return '"' + ''.join('\\x%02x' % byte for byte in value.encode('ascii')) + '"'


def exec_line(pid, exec_path, argv):
    return (str(pid) + ' execve(' + encoded(exec_path) + ', [' + ', '.join(map(encoded, argv))
            + '], 0x7ffd /* 3 vars */) = 0')


def trace_for(calls, root_exit=0):
    """calls: (argv, exec_path, cwd or None, exit_code), each in a fresh vfork child."""
    lines, pid = [], ROOT_PID + 1
    for argv, exec_path, cwd, exit_code in calls:
        lines.append('%d vfork() = %d' % (ROOT_PID, pid))
        if cwd is not None:
            lines.append('%d chdir(%s) = 0' % (pid, encoded(cwd)))
        lines.append(exec_line(pid, exec_path, argv))
        lines.append('%d +++ exited with %d +++' % (pid, exit_code))
        pid += 1
    lines.append('%d +++ exited with %d +++' % (ROOT_PID, root_exit))
    return '\n'.join(lines) + '\n'


def row_from_trace(case, trace, *, safe_ok, root_cwd='/'):
    """Model the observer: a safe row carries the root replay of its checkout argv."""
    parsed = trace_grammar().parse_trace(trace, ROOT_PID, root_cwd)
    checkout = [call['argv'] for call in parsed['calls'] if call['argv'][1:2] in (['checkout'], ['update'])]
    replayed = checkout[0] if safe_ok and len(checkout) == 1 else None
    return dict(case, calls=parsed['calls'], target_exit_code=parsed['target_exit_code'],
                replayed_argv=replayed, replay_branch=case['value'] if replayed else None,
                target_pid=ROOT_PID, target_cwd=root_cwd, path_alias_created=parsed['path_alias_created'],
                checkout_directory_real=True, safe_ok=safe_ok, trace=trace,
                trace_sha256=hashlib.sha256(trace.encode('ascii')).hexdigest())


def adapter_calls(adapter, kind, checkout_argv, exit_code):
    tool = '/usr/bin/' + kind
    checkout = (checkout_argv, tool, '/work/case/' + kind + 'source', exit_code)
    if adapter == 'cookiecutter':
        return [([kind, 'clone', '/fixtures/' + kind + 'source'], tool, '/work/case', 0), checkout]
    return [(['hg', 'clone', '--noupdate', '--quiet', '/fixtures/hgsource', '/work/case/hgsource'],
             tool, None, 0), checkout]


def checkout_argv(adapter, kind, value, repaired):
    if adapter == 'cookiecutter':
        return [kind, 'checkout'] + (['--'] if repaired and kind == 'hg' else []) + [value]
    return ['hg', 'update', '--quiet'] + (['--rev=' + value] if repaired else ['-r', value])


def observed_row(adapter, case, repaired):
    """Model a real run: risk values fail, ordinary values and protected literals succeed."""
    kind, value, role = case['kind'], case['value'], case['role']
    safe = role == 'ordinary' or (repaired and role == 'literal')
    exit_code = 0 if safe else 255
    calls = adapter_calls(adapter, kind, checkout_argv(adapter, kind, value, repaired), exit_code)
    return row_from_trace(case, trace_for(calls, root_exit=0 if safe else 1), safe_ok=safe)
