# Plan: Block by CVE severity

Status: done
Done: B1, B2, B3, B4, B5, B6, B7

## Summary

Data rules drafted from CVE cards only advised. The user's criterion (2026-11-04):
a rule whose CVE is MEDIUM, HIGH or CRITICAL blocks the agent's turn; LOW is
opt-in. Severity comes from the pinned GitHub advisories (database_specific.severity,
MODERATE read as MEDIUM), else the CVE record's CVSS base severity. Of the 125
shipped rules, 116 would block (CRITICAL 21, HIGH 49, MEDIUM 46), 7 are LOW and 2
have no severity yet.

## Behavior

| ID | Given | When | Then |
|---|---|---|---|
| B1 | the pinned GHSA and CVE records of the pack CVEs | the severity index is built | each CVE gets LOW, MEDIUM, HIGH or CRITICAL with its source, or none |
| B2 | a rule with several CVEs | rules are built | its CVE severity is the highest of them; MEDIUM and above make it a block rule, LOW and none keep it review |
| B3 | a block rule matches a line the edit wrote | the hook runs | the turn is blocked with the CVE, severity, line and fix |
| B4 | a block rule matches a line the edit did not write | the hook runs | it is a review note, so old code in a file does not block every later edit |
| B5 | a LOW rule matches | the hook runs without --block-low | review note; with `hook install --block-low` it blocks like MEDIUM |
| B6 | a rule has no known severity | it matches | review note, and the build reports how many such rules ship |
| B7 | the two exact CVE rules | they match | unchanged: they block wherever they match |

## Decisions

- User, 2026-11-04: HIGH and MEDIUM always block; LOW is optional. CRITICAL blocks
  as the level above HIGH.
- Assumed here, to confirm: no severity means review (B6), and a card-rule block
  applies to the lines the edit wrote (B4).

## Risks

- The first site-packages scan shows block rules firing in real code: the pickle
  rule (CRITICAL) in 37 of 4,055 files, SQL built strings (HIGH) in 6. Agents will
  be stopped on such lines until they change them.

## Results (2026-11-04)

- Severity index (src/paladin/resources/cve-severity.json): 523 of 524 pack CVEs;
  LOW 24, MEDIUM 234, HIGH 194, CRITICAL 71. CVE-2021-28658 has neither a GHSA level
  nor CVSS in its record. The CVSS fallback gave a level to the 2 rules that had none.
- Shipped rules: 118 block (CRITICAL 21, HIGH 49, MEDIUM 48) and 7 LOW advise.
- A card-rule block now shows the CVE, its severity, fix and card ids; before, a block
  from a card rule would have shown an empty Why and Fix.
- Sample file with pickle.loads and yaml.load on data: blocked with both CRITICAL
  CVEs in 0.47 s.
- Code review fixes: exact CVE blocks now take the findings budget before card-rule
  blocks, so 50 or more card matches on old lines can no longer push an exact block
  out; card blocks on lines the edit did not write are reported as review notes (they
  had been dropped); shipped rule data must pair block with MEDIUM and above.

## Real sessions and precision sample (2026-11-04)

- Claude Code run 4: blocked on CVE-2022-24065 and the pickle rule (CRITICAL) in one
  message; the agent fixed both and the final check is clean.
- Codex run 8: blocked on the pickle rule; the agent added HMAC authentication before
  pickle.loads, which is the fix the card names, but the rule cannot see it, so the
  line is still flagged (a review note on later edits). Neither agent got stuck.
- Precision sample (scripts/audit_block_matches.py, docs/evidence/block-precision/):
  the 118 block rules match 267 times in 63 of 4,055 site-packages files (pickle 116,
  SQL built strings 93, archive extractall 29). A Fable judge on 41 seeded matches
  (up to 4 per rule): 4 real risk (10%), 33 safe in context, 4 cannot tell. The 4 real
  ones are Pillow Image.open on network or user bytes and torch.load on caller files;
  every sampled pickle, SQL and extractall match was safe in context. Library code is
  a pessimistic proxy for application code, but these rules cannot tell trusted from
  untrusted data.

## Decision: severity plus precision (user, 2026-11-04)

- A rule whose judged matches in real code showed no real risk is held at review,
  whatever its CVE severity (severity.precision_holds; field precision_hold in the
  shipped rules). Held now: 11 rules (archive extractall, commonprefix containment,
  file scheme blocklist, Jinja2 autoescape, lxml entity resolution, two Mako lookups,
  MCP client URL, os.system strings, pickle loads, SQL built strings).
- Shipped: 107 block (CRITICAL 20, HIGH 42, MEDIUM 45), 7 LOW and 11 held advise.
  Rules that never matched the corpus have no precision evidence and keep their
  severity. A held rule can block again after its conditions are tightened and a new
  judged sample shows real risks.
