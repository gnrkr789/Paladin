"""The host accepts only external observations, never target-reported checks."""
import copy
import unittest

from paladin.case_verification import derive_checks, probe_cases
from tests.observer_fixtures import (adapter_calls, checkout_argv, observed_row, row_from_trace,
                                     trace_for)


def observations(repaired, adapter='cookiecutter'):
    return {'observations': [observed_row(adapter, case, repaired) for case in probe_cases(adapter)]}


def replace_row(output, index, calls, *, safe_ok=True, root_exit=0):
    case = {key: output['observations'][index][key] for key in ('kind', 'value', 'role')}
    output['observations'][index] = row_from_trace(case, trace_for(calls, root_exit), safe_ok=safe_ok)


class IsolatedVerificationTests(unittest.TestCase):
    def test_real_argument_observation_and_safe_checkout_are_required(self):
        before, after = observations(False), observations(True)
        self.assertTrue(all(derive_checks(before, after).values()))
        after['observations'][-1]['safe_ok'] = False
        self.assertFalse(derive_checks(before, after)['safe_after_passed'])

    def test_pip_adapter_requires_attached_long_revision(self):
        before, after = observations(False, 'pip-mercurial'), observations(True, 'pip-mercurial')
        self.assertTrue(all(derive_checks(before, after, 'pip-mercurial').values()))
        # pip 23.3 "-r=VALUE" form is not the protected argv and fails safe checks.
        broken = copy.deepcopy(after)
        for index, case in enumerate(probe_cases('pip-mercurial')):
            argv = ['hg', 'update', '--quiet', '-r=' + case['value']]
            replace_row(broken, index, adapter_calls('pip-mercurial', 'hg', argv, 255),
                        safe_ok=False, root_exit=1)
        checks = derive_checks(before, broken, 'pip-mercurial')
        self.assertFalse(checks['after_risk_blocked'])
        self.assertFalse(checks['safe_after_passed'])

    def test_forged_target_flags_without_os_calls_cannot_pass(self):
        output = observations(False)
        for index in range(len(output['observations'])):
            replace_row(output, index, [], safe_ok=True)
        self.assertFalse(any(derive_checks(output, output).values()))

    def test_git_executable_disguised_as_hg_is_not_an_hg_observation(self):
        before, after = observations(False), observations(True)
        index = next(i for i, case in enumerate(probe_cases()) if case['role'] == 'risk')
        value = probe_cases()[index]['value']
        calls = adapter_calls('cookiecutter', 'hg', ['hg', 'checkout', value], 0)
        calls[1] = (calls[1][0], '/usr/bin/git', calls[1][2], 0)
        replace_row(before, index, calls)
        self.assertFalse(derive_checks(before, after)['before_risk_observed'])
        ordinary = next(i for i, case in enumerate(probe_cases()) if case['role'] == 'literal')
        calls = adapter_calls('cookiecutter', 'hg', ['hg', 'checkout', '--', '--literal-branch'], 0)
        calls[0] = (calls[0][0], '/usr/bin/git', calls[0][2], 0)
        replace_row(after, ordinary, calls)
        self.assertFalse(derive_checks(observations(False), after)['safe_after_passed'])

    def test_only_exact_git_clone_helpers_are_allowed(self):
        index = next(i for i, case in enumerate(probe_cases()) if case['kind'] == 'git')
        command = "git-upload-pack '/fixtures/gitsource/.git'"
        helpers = [(['/bin/sh', '-c', command, command], '/bin/sh', '/work/case', 0),
                   (['git-upload-pack', '/fixtures/gitsource/.git'],
                    '/usr/lib/git-core/git-upload-pack', '/work/case', 0)]
        calls = adapter_calls('cookiecutter', 'git', ['git', 'checkout', 'stable'], 0)
        after = observations(True)
        replace_row(after, index, [calls[0], *helpers, calls[1]])
        self.assertTrue(derive_checks(observations(False), after)['safe_after_passed'])
        near_miss = [(['/bin/sh', '-c', command + ' ; id', command], '/bin/sh', '/work/case', 0)]
        replace_row(after, index, [calls[0], *near_miss, calls[1]])
        self.assertFalse(derive_checks(observations(False), after)['safe_after_passed'])

    def test_checkout_outside_cloned_fixture_directory_fails(self):
        after = observations(True)
        index = next(i for i, case in enumerate(probe_cases()) if case['role'] == 'ordinary')
        calls = adapter_calls('cookiecutter', 'hg', ['hg', 'checkout', 'stable'], 0)
        calls[1] = (calls[1][0], calls[1][1], '/tmp/elsewhere', 0)
        replace_row(after, index, calls)
        self.assertFalse(derive_checks(observations(False), after)['safe_after_passed'])

    def test_checkout_without_observed_fixture_clone_fails(self):
        after = observations(True)
        index = next(i for i, case in enumerate(probe_cases()) if case['role'] == 'ordinary')
        replace_row(after, index, adapter_calls('cookiecutter', 'hg', ['hg', 'checkout', 'stable'], 0)[1:])
        self.assertFalse(derive_checks(observations(False), after)['safe_after_passed'])

    def test_target_symlink_creation_fails_safe_check(self):
        after = observations(True)
        index = next(i for i, case in enumerate(probe_cases()) if case['role'] == 'ordinary')
        row = after['observations'][index]
        trace = row['trace'].replace('10 +++ exited', '10 symlink("\\x2f", "\\x2f\\x77") = 0\n10 +++ exited')
        after['observations'][index] = row_from_trace({k: row[k] for k in ('kind', 'value', 'role')},
                                                      trace, safe_ok=True)
        self.assertTrue(after['observations'][index]['path_alias_created'])
        self.assertFalse(derive_checks(observations(False), after)['safe_after_passed'])

    def test_target_files_cannot_replace_the_root_replay(self):
        # A hijacked hg (repo hook, injected environment) can exit 0 and write the
        # branch file, but without a matching root replay the safe check fails.
        after = observations(True)
        index = next(i for i, case in enumerate(probe_cases()) if case['role'] == 'ordinary')
        for replay in ({'replay_branch': None}, {'replay_branch': 'default'},
                       {'replayed_argv': ['hg', 'checkout', 'other']}):
            forged = copy.deepcopy(after)
            forged['observations'][index].update(replay, safe_ok=True)
            self.assertFalse(derive_checks(observations(False), forged)['safe_after_passed'], replay)

    def test_decisive_exec_with_injected_environment_is_not_bound(self):
        # PYTHONPATH or HGRCPATH injected into the target's own hg changes what that
        # process runs without changing argv, so the observation cannot count.
        from tests.observer_fixtures import LAUNCHER_ENV, exec_line, ROOT_PID
        index = next(i for i, case in enumerate(probe_cases()) if case['role'] == 'risk')
        value = probe_cases()[index]['value']
        before = observations(False)
        row = before['observations'][index]
        injected = exec_line(ROOT_PID + 2, '/usr/bin/hg', ['hg', 'checkout', value],
                             LAUNCHER_ENV + ['PYTHONPATH=/work/shadow'])
        trace = '\n'.join(injected if ' execve(' in line and '"\\x63\\x68\\x65' in line else line
                          for line in row['trace'].split('\n'))
        self.assertNotEqual(trace, row['trace'])
        before['observations'][index] = row_from_trace({k: row[k] for k in ('kind', 'value', 'role')},
                                                       trace, safe_ok=False)
        self.assertFalse(derive_checks(before, observations(True))['before_risk_observed'])

    def test_parsed_calls_that_disagree_with_trace_are_rejected(self):
        before, after = observations(False), observations(True)
        after['observations'][0]['calls'][1]['argv'] = checkout_argv('cookiecutter', 'hg', 'x', True)
        with self.assertRaisesRegex(ValueError, 'invalid_observer_calls'):
            derive_checks(before, after)
        after = observations(True)
        after['observations'][0]['trace'] += '\n'
        with self.assertRaisesRegex(ValueError, 'invalid_observer_trace'):
            derive_checks(before, after)


if __name__ == '__main__':
    unittest.main()
