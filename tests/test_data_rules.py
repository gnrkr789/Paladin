"""Declarative rule data: matching, import-alias resolution, prefilter and validation (S10, S11)."""
import unittest

from paladin import data_rules

YAML_LOAD = {
    "rule_id": "yaml-load-unsafe-loader-v1", "cve_ids": ["CVE-2020-1747"], "family": "unsafe_deserialization",
    "severity": "review", "title": "yaml.load without a safe loader",
    "fix": "Use yaml.safe_load or pass Loader=yaml.SafeLoader.",
    "call": ["yaml.load", "yaml.load_all"],
    "require": [{"keyword": "Loader", "absent_or_not_in": ["yaml.SafeLoader", "yaml.CSafeLoader"]}],
    "examples": {"vulnerable": ["import yaml\nyaml.load(data)\n"],
                 "fixed": ["import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n"],
                 "negative": ["import json\njson.load(data)\n"]},
}
SHELL = {
    "rule_id": "subprocess-shell-built-command-v1", "cve_ids": ["CVE-2021-0001"], "family": "command_injection",
    "severity": "review", "title": "Shell command built from data", "fix": "Pass an argument list without shell=True.",
    "call": ["subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"],
    "require": [{"keyword": "shell", "equals": True}, {"arg": 0, "keyword": "args", "is": "non_constant"}],
    "examples": {"vulnerable": ["import subprocess\nsubprocess.run('ls ' + path, shell=True)\n"],
                 "fixed": ["import subprocess\nsubprocess.run(['ls', path])\n"],
                 "negative": ["import subprocess\nsubprocess.run('ls -l', shell=True)\n"]},
}
SQL = {
    "rule_id": "dbapi-execute-built-sql-v1", "cve_ids": ["CVE-2021-0002"], "family": "sql_injection",
    "severity": "review", "title": "SQL text built with string formatting", "fix": "Pass values as query parameters.",
    "call": ["*.execute"], "require": [{"arg": 0, "is": "built_string"}],
    "examples": {"vulnerable": ["cursor.execute(f'SELECT * FROM t WHERE id = {uid}')\n"],
                 "fixed": ["cursor.execute('SELECT * FROM t WHERE id = %s', [uid])\n"],
                 "negative": ["cursor.execute(QUERY, [uid])\n"]},
}


def lines(rules, source):
    findings, _ = data_rules.scan(data_rules.compile_rules(rules), source)
    return [(finding["rule_id"], finding["line"]) for finding in findings]


class MatchingTests(unittest.TestCase):
    def test_import_aliases_and_from_imports_resolve_to_the_rule_call(self):
        for source in ("import yaml\nyaml.load(s)\n", "import yaml as y\ny.load(s)\n",
                       "from yaml import load\nload(s)\n", "from yaml import load as l\nl(s)\n"):
            with self.subTest(source=source):
                self.assertEqual(lines([YAML_LOAD], source), [("yaml-load-unsafe-loader-v1", 2)])

    def test_a_safe_loader_or_an_unrelated_module_is_not_reported(self):
        for source in ("import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\n",
                       "from yaml import load, CSafeLoader\nload(s, Loader=CSafeLoader)\n",
                       "import json\njson.load(s)\n", "def load(s):\n    pass\nload(s)\n"):
            with self.subTest(source=source):
                self.assertEqual(lines([YAML_LOAD], source), [])

    def test_absent_or_not_in_also_reads_a_positional_value(self):
        rule = dict(YAML_LOAD, require=[{"arg": 1, "keyword": "Loader",
                                         "absent_or_not_in": ["yaml.SafeLoader", "yaml.CSafeLoader"]}])

        self.assertEqual(lines([rule], "import yaml\nyaml.load(s, yaml.SafeLoader)\n"), [])
        self.assertEqual(lines([rule], "import yaml\nyaml.load(s, yaml.Loader)\n"), [("yaml-load-unsafe-loader-v1", 2)])
        self.assertEqual(data_rules.validate_rule(rule), [])

    def test_all_requirements_must_hold(self):
        self.assertEqual(lines([SHELL], "import subprocess\nsubprocess.run(cmd, shell=True)\n"),
                         [("subprocess-shell-built-command-v1", 2)])
        self.assertEqual(lines([SHELL], "import subprocess\nsubprocess.run(args=cmd, shell=True)\n"),
                         [("subprocess-shell-built-command-v1", 2)])
        self.assertEqual(lines([SHELL], "import subprocess\nsubprocess.run(cmd, shell=False)\n"), [])
        self.assertEqual(lines([SHELL], "import subprocess\nsubprocess.run('ls', shell=True)\n"), [])

    def test_wildcard_method_names_match_any_receiver_and_built_strings_are_detected(self):
        for source in ("cur.execute('SELECT %s' % name)\n", "cur.execute('SELECT ' + name)\n",
                       "cur.execute('SELECT ' + name + ' FROM t')\n", "cur.execute('SELECT ' + 'a, ' + name)\n",
                       "cur.execute(name + ' FROM t')\n",
                       "cur.execute('SELECT {}'.format(name))\n", "cur.execute(f'SELECT {name}')\n"):
            with self.subTest(source=source):
                self.assertEqual(lines([SQL], source), [("dbapi-execute-built-sql-v1", 1)])
        for source in ("cur.execute('SELECT 1')\n", "cur.execute(sql, params)\n", "cur.execute(f'SELECT 1')\n",
                       "cur.execute('SELECT ' + 'a FROM t')\n", "cur.execute(a + b)\n"):
            with self.subTest(source=source):
                self.assertEqual(lines([SQL], source), [])

    def test_only_rules_whose_module_is_imported_are_run(self):
        compiled = data_rules.compile_rules([YAML_LOAD, SHELL, SQL])

        self.assertEqual({rule["rule_id"] for rule in data_rules.applicable(compiled, {"json"})},
                         {"dbapi-execute-built-sql-v1"})
        self.assertEqual({rule["rule_id"] for rule in data_rules.applicable(compiled, {"yaml", "os"})},
                         {"yaml-load-unsafe-loader-v1", "dbapi-execute-built-sql-v1"})

    def test_unparsable_source_is_reported_as_a_note_not_an_error(self):
        findings, notes = data_rules.scan(data_rules.compile_rules([YAML_LOAD]), "def broken(:\n")

        self.assertEqual(findings, [])
        self.assertTrue(notes)


class ValidationTests(unittest.TestCase):
    def test_rules_whose_examples_behave_are_accepted(self):
        for rule in (YAML_LOAD, SHELL, SQL):
            with self.subTest(rule=rule["rule_id"]):
                self.assertEqual(data_rules.validate_rule(rule), [])

    def test_a_rule_that_misses_its_vulnerable_example_is_rejected(self):
        rule = dict(YAML_LOAD, examples=dict(YAML_LOAD["examples"], vulnerable=["import yaml\nyaml.safe_load(s)\n"]))

        self.assertTrue(any("vulnerable" in error for error in data_rules.validate_rule(rule)))

    def test_a_rule_that_flags_its_fixed_or_negative_example_is_rejected(self):
        rule = dict(YAML_LOAD, require=[])

        errors = data_rules.validate_rule(rule)

        self.assertTrue(any("fixed" in error for error in errors), errors)

    def test_bad_shapes_are_rejected(self):
        for change in ({"severity": "block"}, {"call": []}, {"call": ["*"]}, {"require": [{"keyword": "x"}]},
                       {"require": [{"arg": 0, "is": "eval_this"}]}, {"extra": 1}, {"title": "café"}):
            with self.subTest(change=change):
                self.assertTrue(data_rules.validate_rule(dict(YAML_LOAD, **change)))


if __name__ == "__main__":
    unittest.main()
