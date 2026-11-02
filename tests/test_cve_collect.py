"""CVE expansion collector: PYSEC + GHSA advisories joined to CVE records (S1, S2, S8)."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from paladin import cve_collect

PINS = {"pysec": "a" * 40, "ghsa": "b" * 40, "cvelist": "c" * 40}
FIX = {"type": "FIX", "url": "https://github.com/django/django/commit/04ac1624bdc2fa737188401757cf95ced122d26d"}


class Sources:
    """Builds tiny checkouts shaped like the three upstream repositories."""

    def __init__(self, root):
        self.pysec, self.ghsa, self.cves = root / "pysec", root / "ghsa", root / "cvelist"

    def write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def pysec_entry(self, package, ident, aliases=(), references=(FIX,), extra=""):
        lines = ["id: " + ident, "summary: Example", "details: Example details.",
                 "aliases:" + ("" if aliases else " []")]
        lines += ["- " + alias for alias in aliases]
        lines += ["affected:", "- package:", "    name: " + package, "    ecosystem: PyPI",
                  "references:" + ("" if references else " []")]
        for ref in references:
            lines += ["- type: " + ref["type"], "  url: " + ref["url"]]
        return self.write(self.pysec / "vulns" / package / (ident + ".yaml"), "\n".join(lines) + "\n" + extra)

    def ghsa_entry(self, package, ident, aliases=(), cwes=(), references=(FIX,), ecosystem="PyPI", withdrawn=None):
        record = {"id": ident, "aliases": list(aliases), "summary": "Example", "details": "Example details.",
                  "affected": [{"package": {"ecosystem": ecosystem, "name": package}}],
                  "references": list(references), "database_specific": {"cwe_ids": list(cwes)}}
        if withdrawn:
            record["withdrawn"] = withdrawn
        return self.write(self.ghsa / "advisories" / "github-reviewed" / "2021" / "05" / ident / (ident + ".json"),
                          json.dumps(record))

    def cve_record(self, cve_id, state="PUBLISHED", cwes=()):
        year, number = cve_id.split("-")[1:]
        record = {"cveMetadata": {"cveId": cve_id, "state": state},
                  "containers": {"cna": {"problemTypes": [
                      {"descriptions": [{"type": "CWE", "cweId": cwe} for cwe in cwes]}]}}}
        return self.write(self.cves / "cves" / year / (str(int(number) // 1000) + "xxx") / (cve_id + ".json"),
                          json.dumps(record))

    def collect(self, packages=("django", "jinja2")):
        return cve_collect.collect(self.pysec, self.ghsa, self.cves, packages, PINS)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.src = Sources(Path(self._tmp.name))

    def reason(self, result, ident):
        return {item["advisory"]: item["reason"] for item in result["skipped_items"]}[ident]

    def test_published_cve_with_fix_reference_and_mapped_cwe_is_listed_with_source_hashes(self):
        pysec = self.src.pysec_entry("django", "PYSEC-2021-1", aliases=["CVE-2021-31542", "GHSA-rxjp-mfm9-w4wr"])
        ghsa = self.src.ghsa_entry("Django", "GHSA-rxjp-mfm9-w4wr", aliases=["CVE-2021-31542"], cwes=["CWE-22"])
        cve = self.src.cve_record("CVE-2021-31542")

        result = self.src.collect()

        self.assertEqual(result["sources"], PINS)
        [case] = result["cases"]
        self.assertEqual(case["cve_id"], "CVE-2021-31542")
        self.assertEqual(case["packages"], ["django"])
        self.assertEqual(case["family"], "path_traversal")
        self.assertEqual(case["cwe_ids"], ["CWE-22"])
        self.assertEqual(case["fix_references"], [FIX["url"]])
        self.assertEqual(case["advisories"], [
            {"id": "GHSA-rxjp-mfm9-w4wr", "source": "ghsa", "sha256": sha(ghsa),
             "path": "advisories/github-reviewed/2021/05/GHSA-rxjp-mfm9-w4wr/GHSA-rxjp-mfm9-w4wr.json"},
            {"id": "PYSEC-2021-1", "source": "pysec", "sha256": sha(pysec), "path": "vulns/django/PYSEC-2021-1.yaml"}])
        self.assertEqual(case["cve_record"], {"path": "cves/2021/31xxx/CVE-2021-31542.json", "sha256": sha(cve),
                                              "state": "PUBLISHED"})
        self.assertEqual(result["family_counts"], {"path_traversal": 1})

    def test_advisories_that_cannot_become_cards_are_counted_with_a_reason(self):
        self.src.pysec_entry("django", "PYSEC-2021-2")
        self.src.pysec_entry("numpy", "PYSEC-2021-3", aliases=["CVE-2021-1003"])
        self.src.cve_record("CVE-2021-1003", cwes=["CWE-22"])
        self.src.pysec_entry("django", "PYSEC-2021-4", aliases=["CVE-2021-1004"])
        self.src.cve_record("CVE-2021-1004", state="REJECTED", cwes=["CWE-22"])
        self.src.pysec_entry("django", "PYSEC-2021-5", aliases=["CVE-2021-1005"])
        self.src.pysec_entry("django", "PYSEC-2021-6", aliases=["CVE-2021-1006"], references=())
        self.src.cve_record("CVE-2021-1006", cwes=["CWE-22"])
        self.src.ghsa_entry("django", "GHSA-wwww-wwww-wwww", aliases=["CVE-2021-1007"], cwes=["CWE-22"],
                            withdrawn="2022-01-01T00:00:00Z")
        self.src.cve_record("CVE-2021-1007")
        self.src.ghsa_entry("express", "GHSA-nnnn-nnnn-nnnn", aliases=["CVE-2021-1008"], ecosystem="npm")

        result = self.src.collect()

        self.assertEqual(result["cases"], [])
        self.assertEqual(self.reason(result, "PYSEC-2021-2"), "no_cve_id")
        self.assertEqual(self.reason(result, "PYSEC-2021-3"), "package_not_selected")
        self.assertEqual(self.reason(result, "PYSEC-2021-4"), "cve_not_published")
        self.assertEqual(self.reason(result, "PYSEC-2021-5"), "cve_record_missing")
        self.assertEqual(self.reason(result, "PYSEC-2021-6"), "no_fix_reference")
        self.assertEqual(self.reason(result, "GHSA-wwww-wwww-wwww"), "withdrawn")
        self.assertNotIn("GHSA-nnnn-nnnn-nnnn", {item["advisory"] for item in result["skipped_items"]})
        self.assertEqual(result["skipped"], {"cve_not_published": 1, "cve_record_missing": 1, "no_cve_id": 1,
                                             "no_fix_reference": 1, "package_not_selected": 1, "withdrawn": 1})

    def test_commit_urls_count_as_fix_references_whatever_their_reference_type(self):
        urls = ["http://github.com/openstack/keystone/commit/255b1d43500f5d98ec73a0056525b492b14fec05",
                "https://gitlab.com/group/project/-/commit/0123456789abcdef0123456789abcdef01234567",
                "https://github.com/pallets/jinja/pull/1343"]
        self.src.ghsa_entry("django", "GHSA-aaaa-aaaa-aaaa", aliases=["CVE-2021-1001"], cwes=["CWE-22"],
                            references=[{"type": "WEB", "url": url} for url in urls]
                            + [{"type": "WEB", "url": "https://github.com/someone/CVE-2021-1001-poc"}])
        self.src.cve_record("CVE-2021-1001")

        [case] = self.src.collect()["cases"]

        self.assertEqual(case["fix_references"], sorted(urls))

    def test_cwe_from_the_cve_record_is_used_when_the_advisory_has_none(self):
        self.src.pysec_entry("jinja2", "PYSEC-2024-1", aliases=["CVE-2024-22195"])
        self.src.cve_record("CVE-2024-22195", cwes=["CWE-79"])

        [case] = self.src.collect()["cases"]

        self.assertEqual((case["family"], case["cwe_ids"]), ("xss", ["CWE-79"]))

    def test_unmapped_or_conflicting_cwes_are_recorded_instead_of_guessed(self):
        self.src.pysec_entry("django", "PYSEC-2022-1", aliases=["CVE-2022-1001"])
        self.src.cve_record("CVE-2022-1001", cwes=["CWE-200"])
        self.src.pysec_entry("django", "PYSEC-2022-2", aliases=["CVE-2022-1002"])
        self.src.cve_record("CVE-2022-1002", cwes=["CWE-89", "CWE-79"])
        self.src.pysec_entry("django", "PYSEC-2022-3", aliases=["CVE-2022-1003"])
        self.src.cve_record("CVE-2022-1003", cwes=["CWE-22", "CWE-20"])

        result = self.src.collect()

        self.assertEqual(self.reason(result, "PYSEC-2022-1"), "unsupported_family")
        self.assertEqual(self.reason(result, "PYSEC-2022-2"), "ambiguous_family")
        self.assertEqual([case["family"] for case in result["cases"]], ["path_traversal"])

    def test_cwe_map_covers_current_and_new_families(self):
        expected = {"CWE-22": "path_traversal", "CWE-89": "sql_injection", "CWE-918": "ssrf",
                    "CWE-78": "command_injection", "CWE-88": "command_injection",
                    "CWE-502": "unsafe_deserialization", "CWE-79": "xss", "CWE-601": "open_redirect",
                    "CWE-611": "xxe", "CWE-1333": "redos"}
        for cwe, family in expected.items():
            self.assertEqual(cve_collect.family_for([cwe]), (family, None), cwe)
        self.assertEqual(cve_collect.family_for([]), (None, "unsupported_family"))

    def test_package_names_are_normalized(self):
        self.src.ghsa_entry("Jinja2", "GHSA-h5c8-rqwp-cp95", aliases=["CVE-2024-22195"], cwes=["CWE-79"])
        self.src.cve_record("CVE-2024-22195")

        [case] = self.src.collect(packages=("JINJA2",))["cases"]

        self.assertEqual(case["packages"], ["jinja2"])

    def test_malformed_files_are_skipped_without_stopping_the_run(self):
        self.src.write(self.src.pysec / "vulns" / "django" / "PYSEC-2023-9.yaml", "id: [unclosed\n")
        self.src.write(self.src.ghsa / "advisories" / "github-reviewed" / "2023" / "01" / "GHSA-x" / "GHSA-x.json",
                       "{not json")
        self.src.pysec_entry("django", "PYSEC-2021-1", aliases=["CVE-2021-31542"])
        self.src.cve_record("CVE-2021-31542", cwes=["CWE-22"])

        result = self.src.collect()

        self.assertEqual(len(result["cases"]), 1)
        self.assertEqual(result["skipped"]["parse_error"], 2)

    def test_reruns_on_the_same_inputs_are_identical(self):
        self.src.pysec_entry("django", "PYSEC-2021-1", aliases=["CVE-2021-31542"])
        self.src.cve_record("CVE-2021-31542", cwes=["CWE-22"])
        self.src.pysec_entry("jinja2", "PYSEC-2024-1", aliases=["CVE-2024-22195"])
        self.src.cve_record("CVE-2024-22195", cwes=["CWE-79"])
        self.src.pysec_entry("django", "PYSEC-2021-2")

        first, second = self.src.collect(), self.src.collect()

        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        self.assertEqual([case["cve_id"] for case in first["cases"]], ["CVE-2021-31542", "CVE-2024-22195"])

    def test_advisories_with_malformed_ids_are_parse_errors(self):
        self.src.write(self.src.ghsa / "advisories" / "github-reviewed" / "2021" / "05" / "GHSA-x" / "GHSA-x.json",
                       json.dumps({"id": "GHSA-x/../../../etc/x", "aliases": ["CVE-2021-31542"],
                                   "affected": [{"package": {"ecosystem": "PyPI", "name": "django"}}],
                                   "references": [FIX]}))
        self.src.write(self.src.pysec / "vulns" / "django" / "PYSEC-2021-1.yaml",
                       "id: PYSEC-../x\naliases: [CVE-2021-31542]\n")
        self.src.cve_record("CVE-2021-31542", cwes=["CWE-22"])

        result = self.src.collect()

        self.assertEqual(result["cases"], [])
        self.assertEqual(result["skipped"], {"parse_error": 2})

    def test_invalid_cve_ids_never_become_file_paths(self):
        self.src.pysec_entry("django", "PYSEC-2021-7", aliases=["CVE-2021-../../x"])

        result = self.src.collect()

        self.assertEqual(self.reason(result, "PYSEC-2021-7"), "no_cve_id")


if __name__ == "__main__":
    unittest.main()
