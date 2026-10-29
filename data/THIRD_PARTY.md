# Third-party data in this repository

Paladin's own code, knowledge cards, guidance packs, indexes, schemas and
evaluation records are licensed under Apache-2.0 (see `LICENSE` and `NOTICE`).
The files below are verbatim copies of third-party material, kept unchanged as
provenance (their bytes are pinned by sha256 in the evidence indexes). Each
remains under its own license; the full license texts are in `licenses/`.

- CVE records: Copyright (c) The MITRE Corporation. CVE(R) is a registered
  trademark of The MITRE Corporation. Reproduced under the CVE Terms of Use,
  whose text is included verbatim in `licenses/CVE-Terms-of-Use.txt`.
- Patch files are `git format-patch` output from the named upstream projects
  and include their original author lines.
- The PoC list entries come from nomi-sec/PoC-in-GitHub (CC0-1.0). The listed
  repositories themselves were never downloaded or redistributed.
- Files under `docs/evidence/` may quote excerpts of the sources below in test
  and evaluation records; the same licenses apply to those excerpts.
- Web page snapshots without a clear redistribution license are not included;
  `data/external-references.json` lists their URLs and the hashes of the bytes
  collected at the time.
- External projects used for validation (`.validation-cache/`) are not part of
  this repository. Evaluation records under `docs/evidence/private-alpha/` quote
  short excerpts of pip (MIT, `licenses/pip-MIT.txt`) and Cookiecutter
  (BSD-3-Clause) sources and their Docker traces.

| File | Upstream | License | License text |
|---|---|---|---|
| `data/m0/sources/CVE-2021-23727.changelog.rst` | celery/celery | BSD-3-Clause | [celery-BSD-3-Clause.txt](../licenses/celery-BSD-3-Clause.txt) |
| `data/m0/sources/CVE-2021-23727.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m0/sources/CVE-2021-23727.patch.patch` | celery/celery | BSD-3-Clause | [celery-BSD-3-Clause.txt](../licenses/celery-BSD-3-Clause.txt) |
| `data/m0/sources/CVE-2021-23727.release_diff.patch` | celery/celery | BSD-3-Clause | [celery-BSD-3-Clause.txt](../licenses/celery-BSD-3-Clause.txt) |
| `data/m0/sources/CVE-2021-31542.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m0/sources/CVE-2021-31542.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m0/sources/CVE-2021-35042.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m0/sources/CVE-2021-35042.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m0/sources/CVE-2021-35042.poc_index.json` | nomi-sec/poc-in-github | CC0-1.0 | [PoC-in-GitHub-CC0-1.0.txt](../licenses/PoC-in-GitHub-CC0-1.0.txt) |
| `data/m0/sources/CVE-2022-24065.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m0/sources/CVE-2022-24065.patch.patch` | cookiecutter/cookiecutter | BSD-3-Clause | [cookiecutter-BSD-3-Clause.txt](../licenses/cookiecutter-BSD-3-Clause.txt) |
| `data/m0/sources/CVE-2022-34265.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m0/sources/CVE-2022-34265.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m0/sources/CVE-2022-34265.poc_index.json` | nomi-sec/poc-in-github | CC0-1.0 | [PoC-in-GitHub-CC0-1.0.txt](../licenses/PoC-in-GitHub-CC0-1.0.txt) |
| `data/m0/sources/CVE-2023-24329.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m0/sources/CVE-2023-24329.patch.patch` | python/cpython | PSF-2.0 | [cpython-PSF-2.0.txt](../licenses/cpython-PSF-2.0.txt) |
| `data/m0/sources/CVE-2023-24329.poc_index.json` | nomi-sec/poc-in-github | CC0-1.0 | [PoC-in-GitHub-CC0-1.0.txt](../licenses/PoC-in-GitHub-CC0-1.0.txt) |
| `data/m0/sources/CVE-2024-11168.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m0/sources/CVE-2024-11168.patch.patch` | python/cpython | PSF-2.0 | [cpython-PSF-2.0.txt](../licenses/cpython-PSF-2.0.txt) |
| `data/m0/sources/CVE-2024-2912.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m0/sources/CVE-2024-2912.patch.patch` | bentoml/bentoml | Apache-2.0 | [bentoml-Apache-2.0.txt](../licenses/bentoml-Apache-2.0.txt) |
| `data/m0/sources/CVE-2024-49766.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m0/sources/CVE-2024-49766.patch.patch` | pallets/werkzeug | BSD-3-Clause | [werkzeug-BSD-3-Clause.txt](../licenses/werkzeug-BSD-3-Clause.txt) |
| `data/m0/sources/CVE-2024-5998.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m0/sources/CVE-2024-5998.patch.patch` | langchain-ai/langchain | MIT | [langchain-MIT.txt](../licenses/langchain-MIT.txt) |
| `data/m2/sources/CVE-2009-2659.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2009-2659.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2011-0698.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2011-0698.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2013-4315.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2013-4315.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2019-14234.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2019-14234.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2020-7471.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2020-7471.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2020-9402.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2020-9402.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2021-28658.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2021-28658.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2021-3281.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2021-3281.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2021-33203.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2021-33203.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2021-33571.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2021-33571.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2021-45452.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2021-45452.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2022-28346.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2022-28346.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2022-28347.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2022-28347.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2024-39330.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2024-39330.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2024-42005.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2024-42005.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2024-53908.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2024-53908.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2025-13372.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2025-13372.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2025-50181.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2025-50181.patch.patch` | urllib3/urllib3 | MIT | [urllib3-MIT.txt](../licenses/urllib3-MIT.txt) |
| `data/m2/sources/CVE-2025-57833.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2025-57833.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2025-59681.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2025-59681.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2025-59682.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2025-59682.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `data/m2/sources/CVE-2025-64459.cve.json` | cveproject/cvelistv5 | CVE Terms of Use (MITRE) | [CVE-Terms-of-Use.txt](../licenses/CVE-Terms-of-Use.txt) |
| `data/m2/sources/CVE-2025-64459.patch.patch` | django/django | BSD-3-Clause | [django-BSD-3-Clause.txt](../licenses/django-BSD-3-Clause.txt) |
| `docs/evidence/patch-context-repair/reference.patch` | bentoml/bentoml | Apache-2.0 | [bentoml-Apache-2.0.txt](../licenses/bentoml-Apache-2.0.txt) |
