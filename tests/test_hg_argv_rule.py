"""Generalized Mercurial argv rule: wrapper calls, update, built lists and Python 2."""
import ast
from pathlib import Path
import tempfile
import unittest

from paladin import hg_argv_rule
from paladin.candidate_scan import scan_project


def lines(source):
    return [line for line, _ in hg_argv_rule.ast_findings(ast.parse(source))]


class GeneralizedRuleTests(unittest.TestCase):
    def test_wrapper_calls_with_a_variable_revision_are_reported(self):
        source = ("def a(self, tag):\n    self.Run(['hg', 'checkout', tag])\n"
                  "def b(sha, path):\n    _run(['hg', 'update', '-r', sha], path)\n"
                  "def c(runner, rev):\n    runner.run(['hg', 'update', rev])\n")
        findings = hg_argv_rule.ast_findings(ast.parse(source))
        self.assertEqual(findings, [(2, 'CVE-2022-24065'), (4, 'CVE-2023-5752'), (6, 'CVE-2023-5752')])

    def test_lists_grown_in_the_same_function_are_followed(self):
        source = ("def f(source):\n    args = ['hg', 'checkout']\n    if source:\n"
                  "        args.append(source['tag'])\n    run(args)\n")
        self.assertEqual(lines(source), [4])
        terminated = source.replace("    args = ['hg', 'checkout']\n",
                                    "    args = ['hg', 'checkout']\n    args.append('--')\n")
        self.assertEqual(lines(terminated), [])
        other_scope = ("def f():\n    args = ['hg', 'checkout']\n    return args\n"
                       "def g(args, tag):\n    args.append(tag)\n")
        self.assertEqual(lines(other_scope), [])

    def test_protected_constant_and_fixed_prefix_values_are_not_reported(self):
        for source in ("run(['hg', 'checkout', '--', tag])\n",
                       "run(['hg', 'update', '--rev=' + rev])\n",
                       "run(['hg', 'update', f'--rev={rev}'])\n",
                       "run(['hg', 'checkout', 'tip~%d' % (count - 1)])\n",
                       "run(['hg', 'checkout', '-C', '.'])\n",
                       "run(['hg', 'pull', url])\n",
                       "run(['git', 'checkout', tag])\n"):
            self.assertEqual(lines(source), [], source)

    def test_global_options_before_the_subcommand_and_variadic_helpers(self):
        source = ("def f(target_dir, revision):\n    up_cmd = ['hg', '--cwd', target_dir, 'up']\n"
                  "    if revision:\n        up_cmd.extend(['-r', revision])\n    run(up_cmd)\n"
                  "def g(revision):\n    execute_command('hg', 'update', '-q', revision, cwd='x')\n"
                  "def h(dest):\n    execute_command('hg', 'clone', url, dest)\n")
        self.assertEqual(lines(source), [4, 7])

    def test_other_tools_bound_to_a_name_are_not_mercurial(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "wrap.py").write_text(
                "import shutil, subprocess\n"
                "def get_hg(revno):\n    hg = shutil.which('hg')\n"
                "    subprocess.check_call([hg, 'checkout', revno])\n"
                "def get_svn(revno):\n    svn = shutil.which('svn')\n"
                "    subprocess.check_call([svn, 'checkout', '-r', revno, url])\n", encoding="ascii")
            found = [(item["line"], item["rule_id"]) for item in scan_project(root)["candidates"]]
        self.assertEqual(found, [(4, "CVE-2022-24065:mercurial-checkout-v1")])

    def test_python2_source_uses_the_token_fallback(self):
        source = b"def f(self, tag):\n  print 'cloning'\n  self.Run([\"hg\", \"checkout\", tag], cwd=self.work)\n"
        with self.assertRaises(SyntaxError):
            ast.parse(source)
        self.assertEqual(hg_argv_rule.token_findings(source), [(3, 'CVE-2022-24065')])
        safe = source.replace(b'"checkout", tag', b'"checkout", "--", tag')
        self.assertEqual(hg_argv_rule.token_findings(safe), [])

    def test_scan_reports_review_candidates_that_are_not_verifiable(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "vcs.py").write_text("def f(rev):\n    _run(['hg', 'update', '-r', rev])\n", encoding="ascii")
            (root / "old.py").write_text("def g(tag):\n  print 'x'\n  Run(['hg', 'checkout', tag])\n",
                                         encoding="ascii")
            result = scan_project(root)
        found = {(item["path"], item["line"], item["detection"]) for item in result["candidates"]}
        self.assertEqual(found, {("vcs.py", 2, "ast"), ("old.py", 3, "token")})
        self.assertTrue(all(item["severity"] == "review" and item["verifiable"] is False
                            for item in result["candidates"]))
        self.assertEqual(result["status"], "partial")  # old.py could not be fully parsed


if __name__ == "__main__":
    unittest.main()
