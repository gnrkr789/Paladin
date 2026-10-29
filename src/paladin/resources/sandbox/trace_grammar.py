"""Strict strace grammar shared by the in-container observer and the host.

Only the exact line shapes produced by
`strace -f -xx -s 65535 -e trace=<TRACED>` are accepted. Any other shape,
including truncated strings, elided arrays, unfinished records at the end of a
trace or unexpected syscalls, rejects the whole trace. The working directory of
every successful exec is derived from observed chdir calls and process creation;
when it cannot be derived exactly it is reported as None.
"""
import hashlib
import posixpath
import re

TRACED = ('execve,execveat,chdir,fchdir,clone,clone3,fork,vfork,symlink,symlinkat,'
          'rename,renameat,renameat2,link,linkat')
MAX_ARGV = 256
CLONE_FS = 'CLONE_FS'
CLONE_THREAD = 'CLONE_THREAD'
CLONE_UNTRACED = 'CLONE_UNTRACED'
# Version-control tools create lock symlinks and rename temporary files; only path
# aliasing (symlink, rename, hard link) by a non-tool process image is flagged.
TOOL_IMAGES = frozenset({'/usr/bin/hg', '/usr/bin/git'})
LAUNCHER_IMAGE = 'launcher'

_STRING = r'"((?:\\x[0-9a-f]{2})*)"'
_RETURN = re.compile(r'(.*)\) += (?:(0|[1-9][0-9]{0,9})|-1 ([A-Z][A-Z0-9]*) \([A-Za-z0-9 ,.\'/-]*\))\Z', re.S)
_LINE = re.compile(r'([1-9][0-9]{0,9}) +(.*)\Z', re.S)
_START = re.compile(r'([a-z0-9]+)\((.*)\Z', re.S)
_UNFINISHED = ' <unfinished ...>'
_RESUMED = re.compile(r'<\.\.\. ([a-z0-9]+) resumed>(.*)\Z', re.S)
_EXITED = re.compile(r'\+\+\+ (?:exited with ([0-9]{1,3})|killed by SIG[A-Z0-9]+(?: \(core dumped\))?) \+\+\+\Z')
_SIGNAL = re.compile(r'--- SIG[A-Z0-9]+ \{si_signo=SIG[A-Z0-9]+, [ -~]*\} ---\Z')
_ENCODED = r'"(?:\\x[0-9a-f]{2})*"'
_LIST = r'\[((?:' + _ENCODED + r'(?:, ' + _ENCODED + r')*)?)\]'
# With strace -v the environment is a full string array; a pointer form has no env.
_EXECVE = re.compile(_STRING + r', ' + _LIST + r', (?:' + _LIST
                     + r'|NULL|0x[0-9a-f]+(?: /\* [0-9]+ vars? \*/)?)\Z')
_ITEM = re.compile(_STRING)
_CHDIR = re.compile(_STRING + r'\Z')
_FCHDIR = re.compile(r'[0-9]{1,9}\Z')
_CLONE = re.compile(r'child_stack=(?:NULL|0x[0-9a-f]+), flags=([A-Z0-9_|]+)'
                    r'(?:, [a-z_]+=(?:NULL|0x[0-9a-f]+|\[[0-9]+\]))*\Z')
_FLAG = re.compile(r'(?:CLONE_[A-Z_]+|SIG[A-Z0-9]+)\Z')
_SYMLINK = re.compile(_STRING + r', (?:(?:AT_FDCWD|[0-9]{1,9}), )?' + _STRING + r'\Z')
_FD = r'(?:AT_FDCWD|[0-9]{1,9})'
_RENAME = re.compile(r'(?:' + _FD + r', )?' + _STRING + r', (?:' + _FD + r', )?' + _STRING
                     + r'(?:, (?:0|[A-Z_|]+))?\Z')


class TraceError(ValueError):
    pass


def env_digest(entries):
    """Order-independent digest of NAME=VALUE entries; None when not recorded."""
    if entries is None:
        return None
    return hashlib.sha256('\0'.join(sorted(entries)).encode('ascii')).hexdigest()


def _decode(encoded):
    try:
        return bytes.fromhex(encoded.replace('\\x', '')).decode('ascii')
    except (ValueError, UnicodeError) as exc:
        raise TraceError('trace_non_ascii_string') from exc


def _records(trace):
    """Reassemble unfinished/resumed records; yield (index, pid, kind, payload)."""
    pending = {}
    lines = trace.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    for index, line in enumerate(lines):
        match = _LINE.fullmatch(line)
        if not match:
            raise TraceError('unsupported_trace_line')
        pid, body = int(match[1]), match[2]
        exited = _EXITED.fullmatch(body)
        if exited:
            if pid in pending:
                raise TraceError('trace_record_interrupted')
            yield index, pid, 'exit', None if exited[1] is None else int(exited[1])
            continue
        if _SIGNAL.fullmatch(body):
            continue
        resumed = _RESUMED.fullmatch(body)
        if resumed:
            if pid not in pending or pending[pid][1] != resumed[1]:
                raise TraceError('trace_resume_without_start')
            start, name, prefix = pending.pop(pid)
            body = name + '(' + prefix + resumed[2]
        elif body.endswith(_UNFINISHED):
            started = _START.fullmatch(body[:-len(_UNFINISHED)])
            if not started or pid in pending:
                raise TraceError('unsupported_trace_line')
            pending[pid] = (index, started[1], started[2])
            continue
        else:
            start = index
        started = _START.fullmatch(body)
        returned = _RETURN.fullmatch(started[2]) if started else None
        if not returned:
            raise TraceError('unsupported_trace_line')
        value = None if returned[2] is None else int(returned[2])
        yield start, pid, 'syscall', (started[1], returned[1], value, returned[3])
    if pending:
        raise TraceError('trace_record_interrupted')


def _flags(text):
    flags = text.split('|')
    if any(not _FLAG.fullmatch(flag) for flag in flags):
        raise TraceError('unsupported_clone_flags')
    return set(flags)


def parse_trace(trace, root_pid, root_cwd):
    """Return successful execs with argv, exec_path, pid, cwd and exit code."""
    if not isinstance(trace, str) or not trace.isascii():
        raise TraceError('trace_not_ascii')
    if type(root_pid) is not int or not isinstance(root_cwd, str) or not root_cwd.startswith('/'):
        raise TraceError('trace_root_invalid')
    # shared: pid -> first trace index from which its fs (cwd) may be shared.
    events, created, shared = [], {}, {}
    for index, pid, kind, payload in _records(trace):
        if kind == 'exit':
            events.append((index, pid, 'exit', payload))
            continue
        name, arguments, value, error = payload
        if name == 'execve':
            match = _EXECVE.fullmatch(arguments)
            if not match:
                raise TraceError('unsupported_exec_trace_shape')
            argv = [_decode(item) for item in _ITEM.findall(match[2])]
            env = None if match[3] is None else [_decode(item) for item in _ITEM.findall(match[3])]
            if not argv or len(argv) > MAX_ARGV:
                raise TraceError('trace_argv_invalid')
            if error is None:
                events.append((index, pid, 'exec', (_decode(match[1]), argv, env_digest(env))))
        elif name == 'execveat':
            raise TraceError('unsupported_exec_trace_shape')
        elif name == 'chdir':
            match = _CHDIR.fullmatch(arguments)
            if not match:
                raise TraceError('unsupported_chdir_shape')
            if error is None:
                events.append((index, pid, 'chdir', _decode(match[1])))
        elif name == 'fchdir':
            if not _FCHDIR.fullmatch(arguments):
                raise TraceError('unsupported_chdir_shape')
            if error is None:
                events.append((index, pid, 'chdir', None))
        elif name in ('clone', 'fork', 'vfork'):
            if name == 'clone':
                match = _CLONE.fullmatch(arguments)
                if not match:
                    raise TraceError('unsupported_clone_shape')
                flags = _flags(match[1])
            elif arguments:
                raise TraceError('unsupported_clone_shape')
            else:
                flags = set()
            if error is None:
                if CLONE_UNTRACED in flags:
                    raise TraceError('untraced_clone_observed')
                if not value or value in created or value == root_pid:
                    raise TraceError('trace_child_identity_invalid')
                created[value] = (pid, index)
                if flags & {CLONE_FS, CLONE_THREAD}:
                    for member in (pid, value):
                        shared[member] = min(shared.get(member, index), index)
        elif name == 'clone3':
            if error is None:
                raise TraceError('unsupported_clone_shape')
        elif name in ('symlink', 'symlinkat'):
            if not _SYMLINK.fullmatch(arguments):
                raise TraceError('unsupported_symlink_shape')
            if error is None:
                events.append((index, pid, 'alias', None))
        elif name in ('rename', 'renameat', 'renameat2', 'link', 'linkat'):
            if not _RENAME.fullmatch(arguments):
                raise TraceError('unsupported_rename_shape')
            if error is None:
                events.append((index, pid, 'alias', None))
        else:
            raise TraceError('unexpected_traced_syscall')
    events.sort(key=lambda event: event[0])

    def cwd_at(pid, index, depth=0):
        # A CLONE_FS/CLONE_THREAD peer can change the cwd after the sharing clone.
        if shared.get(pid, index) < index or depth > 64:
            return None
        if pid == root_pid:
            current = root_cwd
        elif pid in created:
            parent, start = created[pid]
            current = cwd_at(parent, start, depth + 1)
        else:
            return None
        for position, owner, kind, payload in events:
            if position >= index:
                break
            if owner == pid and kind == 'chdir':
                current = (None if payload is None or current is None
                           else posixpath.normpath(posixpath.join(current, payload)))
        return current

    def image_at(pid, index, depth=0):
        if depth > 64:
            return None
        if pid == root_pid:
            current = LAUNCHER_IMAGE
        elif pid in created:
            parent, start = created[pid]
            current = image_at(parent, start, depth + 1)
        else:
            return None
        for position, owner, kind, payload in events:
            if position >= index:
                break
            if owner == pid and kind == 'exec':
                current = payload[0]
        return current

    path_alias_created = any(kind == 'alias' and image_at(pid, index) not in TOOL_IMAGES
                          for index, pid, kind, _ in events)
    calls, latest = [], {}
    for index, pid, kind, payload in events:
        if kind == 'exec':
            call = {'argv': payload[1], 'exec_path': payload[0], 'env_sha256': payload[2], 'pid': pid,
                    'cwd': cwd_at(pid, index), 'exit_code': None}
            calls.append(call)
            latest[pid] = call
        elif kind == 'exit' and pid in latest:
            latest[pid]['exit_code'] = payload
    exits = [payload for _, pid, kind, payload in events if kind == 'exit' and pid == root_pid]
    return {'calls': calls, 'path_alias_created': path_alias_created,
            'target_exit_code': exits[-1] if len(exits) == 1 else None}
