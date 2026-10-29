"""Boundary configuration, strict trace grammar and launcher seccomp contracts."""
import importlib.util
import unittest
from unittest.mock import patch

from paladin import sandbox_runtime as runtime
from tests.observer_fixtures import encoded, exec_line

PID = 10


def grammar():
    return runtime.trace_grammar()


def target_module():
    spec = importlib.util.spec_from_file_location('test_target', runtime.ASSETS / 'target.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_bpf(program, arch, number, flags=0):
    """Minimal classic-BPF interpreter for the launcher's seccomp program."""
    data = {0: number, 4: arch, 16: flags & 0xFFFFFFFF}
    accumulator, index = 0, 0
    while True:
        code, jt, jf, k = program[index]
        if code == 0x20:
            accumulator, index = data[k], index + 1
        elif code in (0x15, 0x35, 0x45):
            taken = {0x15: accumulator == k, 0x35: accumulator >= k, 0x45: bool(accumulator & k)}[code]
            index += 1 + (jt if taken else jf)
        elif code == 0x06:
            return k
        else:
            raise AssertionError('unknown opcode')


def parse(lines, cwd='/'):
    return grammar().parse_trace('\n'.join(lines) + '\n', PID, cwd)


class SandboxRuntimeTests(unittest.TestCase):
    def test_requires_image_id_before_any_execution(self):
        with patch.object(runtime.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'immutable_image_id'):
                runtime.run_observed(b'print(1)', 'python:latest',
                                     [{'kind': 'hg', 'value': 'stable', 'role': 'ordinary'}])
            run.assert_not_called()

    def test_container_has_no_host_mounts_and_bounded_privileges(self):
        arguments = runtime.container_arguments('sha256:' + 'a' * 64, 'test')
        for flag in ('--network=none', '--read-only', '--cap-drop=ALL', '--cap-add=SYS_PTRACE',
                     '--security-opt=no-new-privileges:true', '--pids-limit=64', '--memory=256m', '--cpus=1'):
            self.assertIn(flag, arguments)
        self.assertFalse(any(arg.startswith(('--mount', '--volume')) for arg in arguments))
        self.assertEqual([arg for arg in arguments if arg.startswith('--cap-add=')], ['--cap-add=SYS_PTRACE'])

    def test_execve_trace_records_kernel_arguments_cwd_and_child_exit(self):
        result = parse(['10 vfork() = 11', '11 chdir(' + encoded('/work/case') + ') = 0',
                        '11 chdir(' + encoded('hgsource') + ') = 0',
                        exec_line(11, '/usr/bin/hg', ['hg', 'checkout', '--', '--literal-branch']),
                        '11 +++ exited with 0 +++', '10 +++ exited with 0 +++'])
        call = result['calls'][0]
        self.assertEqual(call['argv'], ['hg', 'checkout', '--', '--literal-branch'])
        self.assertEqual((call['cwd'], call['exit_code'], result['target_exit_code']),
                         ('/work/case/hgsource', 0, 0))

    def test_real_strace_padding_and_unfinished_records_are_reassembled(self):
        result = parse(['10 vfork( <unfinished ...>',
                        '11 chdir(' + encoded('/tmp') + ')         = 0',
                        exec_line(11, '/bin/true', ['/bin/true', 'x']).replace(') = 0', ' <unfinished ...>'),
                        '10 <... vfork resumed>)              = 11',
                        '11 <... execve resumed>)             = 0',
                        '11 +++ exited with 0 +++',
                        '10 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=11} ---',
                        '10 clone3(NULL, 0)                   = -1 ENOSYS (Function not implemented)',
                        '10 +++ exited with 0 +++'])
        self.assertEqual([(c['argv'], c['cwd']) for c in result['calls']], [(['/bin/true', 'x'], '/tmp')])

    def test_truncated_elided_or_unknown_trace_shapes_fail_closed(self):
        hg = encoded('/usr/bin/hg')
        for line in ('12 execveat(3, "", [], 0x123, 0) = 0',
                     '12 execve(' + hg + ', [' + encoded('hg') + ', ...], 0x123 /* 1 var */) = 0',
                     '12 execve(' + hg + ', [' + encoded('hg') + '...], 0x123 /* 1 var */) = 0',
                     '12 execve(' + hg + '..., [' + encoded('hg') + '], 0x123 /* 1 var */) = 0',
                     '12 execve("/usr/bin/hg", ["hg"], 0x123) = 0',
                     '12 execve(' + hg + ', [' + encoded('hg') + '], 0x123 /* 1 var */) = ?',
                     '12 openat(AT_FDCWD, "", O_RDONLY) = 3',
                     '12 +++ superseded by execve in pid 13 +++',
                     'strace: Process 12 attached'):
            with self.assertRaises(ValueError, msg=line):
                parse([line])
        with self.assertRaisesRegex(ValueError, 'trace_record_interrupted'):
            parse(['10 vfork( <unfinished ...>'])

    def test_untraced_clone_success_is_rejected_and_failure_is_recorded_only(self):
        with self.assertRaisesRegex(ValueError, 'untraced_clone_observed'):
            parse(['10 clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = 11'])
        failed = parse(['10 clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = -1 EPERM (Operation not permitted)',
                        '10 +++ exited with 0 +++'])
        self.assertEqual((failed['calls'], failed['target_exit_code']), ([], 0))

    def test_shared_fs_or_fchdir_makes_exec_cwd_unknown(self):
        hg = exec_line(11, '/usr/bin/hg', ['hg', 'checkout', 'stable'])
        shared = parse(['10 clone(child_stack=0x7f, flags=CLONE_VM|CLONE_FS|SIGCHLD) = 11',
                        '11 chdir(' + encoded('/work/case/hgsource') + ') = 0', hg,
                        '11 +++ exited with 0 +++'])
        self.assertIsNone(shared['calls'][0]['cwd'])
        later_thread = parse(['10 vfork() = 11', '11 chdir(' + encoded('/work/case/hgsource') + ') = 0', hg,
                              '11 clone(child_stack=0x7f, flags=CLONE_VM|CLONE_FS|CLONE_THREAD) = 12',
                              '12 +++ exited with 0 +++', '11 +++ exited with 0 +++'])
        self.assertEqual(later_thread['calls'][0]['cwd'], '/work/case/hgsource')
        descriptor = parse(['10 vfork() = 11', '11 fchdir(3) = 0', hg, '11 +++ exited with 0 +++'])
        self.assertIsNone(descriptor['calls'][0]['cwd'])
        unknown = parse([exec_line(99, '/usr/bin/hg', ['hg', 'checkout', 'stable'])])
        self.assertIsNone(unknown['calls'][0]['cwd'])

    def test_only_target_image_symlinks_are_flagged(self):
        link = encoded('host:1') + ', ' + encoded('/work/case/hgsource/.hg/wlock')
        tool = parse(['10 vfork() = 11', exec_line(11, '/usr/bin/hg', ['hg', 'clone', 'x']),
                      '11 symlink(' + link + ') = 0', '11 +++ exited with 0 +++'])
        self.assertFalse(tool['path_alias_created'])
        target = parse(['10 symlinkat(' + encoded('/tmp') + ', AT_FDCWD, ' + encoded('/work/case') + ') = 0'])
        self.assertTrue(target['path_alias_created'])

    def test_target_rename_or_link_is_path_aliasing_but_tool_rename_is_not(self):
        pair = encoded('/work/a') + ', ' + encoded('/work/case/hgsource')
        for line in ('10 rename(' + pair + ') = 0',
                     '10 renameat2(AT_FDCWD, ' + encoded('/work/a') + ', AT_FDCWD, '
                     + encoded('/work/case') + ', RENAME_EXCHANGE) = 0',
                     '10 linkat(AT_FDCWD, ' + encoded('/work/a') + ', AT_FDCWD, ' + encoded('/work/b') + ', 0) = 0'):
            self.assertTrue(parse([line])['path_alias_created'], line)
        tool = parse(['10 vfork() = 11', exec_line(11, '/usr/bin/hg', ['hg', 'update']),
                      '11 rename(' + pair + ') = 0', '11 +++ exited with 0 +++'])
        self.assertFalse(tool['path_alias_created'])
        self.assertFalse(parse(['10 rename(' + pair + ') = -1 ENOENT (No such file or directory)'])['path_alias_created'])

    def test_launcher_seccomp_denies_untraced_clone_and_clone3(self):
        module = target_module()
        for machine, (arch, clone, clone3) in module.SECCOMP_ARCHES.items():
            program = module.seccomp_program(machine)
            self.assertEqual(run_bpf(program, arch, clone, 0x00800000 | 17), 0x00050001)
            self.assertEqual(run_bpf(program, arch, clone, 0x01200011), 0x7FFF0000)
            self.assertEqual(run_bpf(program, arch, clone3), 0x00050000 | 38)
            self.assertEqual(run_bpf(program, arch, 59), 0x7FFF0000)
            self.assertEqual(run_bpf(program, 0x40000003, clone), 0x80000000)
        x86 = module.seccomp_program('x86_64')
        self.assertEqual(run_bpf(x86, 0xC000003E, 0x40000038, 0x00800000), 0x80000000)


def observer_module():
    import sys
    sys.path.insert(0, str(runtime.ASSETS))
    try:
        spec = importlib.util.spec_from_file_location('test_observer', runtime.ASSETS / 'observer.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(runtime.ASSETS))
    return module


class ObserverReplayTests(unittest.TestCase):
    def test_root_replay_is_limited_to_fixed_ordinary_and_repaired_argv(self):
        observer = observer_module()
        case = {'kind': 'hg', 'value': 'stable', 'role': 'ordinary'}
        with patch.object(observer.subprocess, 'run') as run:
            for calls in ([],  # no checkout observed
                          [{'argv': ['hg', 'update', '--quiet', '-r=stable'], 'exec_path': '/usr/bin/hg',
                            'cwd': '/work/case/hgsource', 'exit_code': 0}],  # pip 23.3 form
                          [{'argv': ['hg', 'update', '--quiet', '--rev=stable'], 'exec_path': '/usr/bin/git',
                            'cwd': '/work/case/hgsource', 'exit_code': 0}],  # disguised binary
                          [{'argv': ['hg', 'update', '--quiet', '--rev=stable'], 'exec_path': '/usr/bin/hg',
                            'cwd': '/tmp', 'exit_code': 0}]):  # wrong directory
                self.assertEqual(observer.replay_branch('pip-mercurial', case, calls), (None, None))
            risk = dict(case, role='risk')
            calls = [{'argv': ['hg', 'update', '--quiet', '-r', 'stable'], 'exec_path': '/usr/bin/hg',
                      'cwd': '/work/case/hgsource', 'exit_code': 0}]
            self.assertEqual(observer.replay_branch('pip-mercurial', risk, calls), (None, None))
            run.assert_not_called()
        self.assertIn(['hg', 'checkout', '--', '--x'], observer.replayable_argv('cookiecutter', 'hg', '--x'))
        self.assertEqual(observer.replayable_argv('cookiecutter', 'git', 'v'), [['git', 'checkout', 'v']])


class InfrastructureRetryTests(unittest.TestCase):
    CASES = [{'kind': 'hg', 'value': 'stable', 'role': 'ordinary'}]

    def test_docker_timeout_retries_in_a_fresh_container_and_is_counted(self):
        from tests.observer_fixtures import observed_row
        good = {'observation': observed_row('cookiecutter', self.CASES[0], True), 'observer': {}}
        with patch.object(runtime, '_one_case',
                          side_effect=[ValueError('sandbox_execution_failed'), good]) as one:
            result = runtime.run_observed(b'x', 'sha256:' + 'a' * 64, self.CASES)
        self.assertEqual((one.call_count, result['infrastructure_retries']), (2, 1))

    def test_rejected_observations_are_never_retried(self):
        with patch.object(runtime, '_one_case',
                          side_effect=ValueError('sandbox_invalid_observer_credentials')) as one:
            with self.assertRaisesRegex(ValueError, 'sandbox_invalid_observer_credentials'):
                runtime.run_observed(b'x', 'sha256:' + 'a' * 64, self.CASES)
        self.assertEqual(one.call_count, 1)

    def test_retries_are_bounded(self):
        with patch.object(runtime, '_one_case', side_effect=ValueError('sandbox_execution_failed')) as one:
            with self.assertRaisesRegex(ValueError, 'sandbox_execution_failed'):
                runtime.run_observed(b'x', 'sha256:' + 'a' * 64, self.CASES)
        self.assertEqual(one.call_count, runtime.INFRASTRUCTURE_ATTEMPTS)


class HostPayloadValidationTests(unittest.TestCase):
    CASE = {'kind': 'hg', 'value': 'stable', 'role': 'ordinary'}

    def payload(self):
        from tests.observer_fixtures import observed_row
        return {'observation': observed_row('cookiecutter', self.CASE, True),
                'observer': {'id': runtime.OBSERVER_ID, 'target_uid': 65534, 'target_cap_eff': 0,
                             'trace_owner_uid': 0, 'target_no_new_privs': True,
                             'adapter': 'cookiecutter', 'target_seccomp_filters': 3,
                             'container_seccomp_filters': 2, 'trace_mode': '0o600',
                             'target_stdout_used': False,
                             'source_sha256': runtime._sha(b'source')}}

    def test_valid_payload_is_accepted(self):
        output = self.payload()
        self.assertIs(runtime.validate_output(output, b'source', self.CASE, 'cookiecutter'), output)

    def test_each_tampered_field_is_rejected_with_its_code(self):
        tampering = [
            ('sandbox_invalid_observer_credentials', lambda o: o['observer'].update(target_seccomp_filters=2)),
            ('sandbox_invalid_observer_credentials', lambda o: o['observer'].update(trace_mode='0o644')),
            ('sandbox_invalid_observer_credentials', lambda o: o['observer'].update(target_uid=0)),
            ('sandbox_invalid_observer_credentials', lambda o: o['observer'].update(adapter='pip-mercurial')),
            ('sandbox_invalid_observer_credentials', lambda o: o['observer'].update(source_sha256='0' * 64)),
            ('sandbox_invalid_case_identity', lambda o: o['observation'].update(value='other')),
            ('sandbox_trace_integrity_failed', lambda o: o['observation'].update(trace=o['observation']['trace'] + ' ')),
            ('sandbox_trace_parse_disagrees', lambda o: o['observation']['calls'][1].update(cwd='/tmp')),
            ('sandbox_trace_parse_disagrees', lambda o: o['observation'].update(path_alias_created=True)),
            ('sandbox_trace_parse_disagrees', lambda o: o['observation'].update(target_exit_code=1)),
        ]
        for code, tamper in tampering:
            output = self.payload()
            tamper(output)
            with self.assertRaisesRegex(ValueError, code):
                runtime.validate_output(output, b'source', self.CASE, 'cookiecutter')


if __name__ == '__main__':
    unittest.main()
