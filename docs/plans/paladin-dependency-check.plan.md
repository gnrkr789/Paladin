# Plan: Dependency version check against the collected advisories

Status: done
Done: D1, D2, D3, D4, D5, D6, D7, D8

## Summary

416 of 520 cards got no code rule because the weakness is inside a library: user
code has no call shape to match, and the fix is an upgrade. Those CVEs are found
by comparing the project's pinned dependency versions with the affected ranges
of the advisories Paladin already collected (PYSEC and GHSA, OSV format, at
pinned commits). The check is static data and runs without a model or network,
so the change hook can run it when an agent edits a dependency file.

## Behavior

| ID | Given | When | Then |
|---|---|---|---|
| D1 | the pinned PYSEC and GHSA files of the collected cases | the advisory index is built | each CVE in the pack gets its PyPI package names and ECOSYSTEM ranges (introduced, fixed, last_affected), or its explicit version list when no range exists |
| D2 | requirements*.txt with name==version | it is checked | an affected version is reported with the CVE, the card title and the first fixed version |
| D3 | uv.lock, poetry.lock or Pipfile.lock | it is checked | every locked package version is compared the same way |
| D4 | a requirement without an exact pin (>=, ranges, bare names) | it is checked | it is listed as not pinned, never as safe or affected |
| D5 | a version that is not PEP 440 | it is checked | it is noted and skipped |
| D6 | package names in other spellings (Flask_Login, flask-login) | they are compared | names are normalized as in PEP 503 |
| D7 | `paladin deps check` and the MCP tool check_dependencies | they run | they report the same findings for the workspace's dependency files |
| D8 | an agent edits a dependency file | the change hook runs | affected versions are a non-blocking review note with card ids; no model, network or index is used |

## Decisions

- User, 2026-11-03: build the dependency check first, then redraft code rules
  from the patch-checked cards.
- Findings are review level: the version is affected, but whether the project
  uses the vulnerable feature is unknown.

## Results (2026-11-03)

- Index: 549 entries for 520 of the 524 pack CVEs (4 advisories name no PyPI range
  or version); 162 KB, packaged as dependency-advisories.json.
- A requirements file with Django 3.2.0, Jinja2 2.10, requests 2.19.0, Pillow 8.0.0
  and urllib3 1.24.1: 22 findings (Django 14, Pillow 4, Jinja2 2, urllib3 2) in
  0.55 s; requests 2.19.0 has no finding because its CVEs are not in the pack.
- The CLI exits 1 on findings, like pip-audit, so it can gate CI.
