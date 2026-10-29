# Freeze evaluation inputs and separate partial evidence from outcome

During M5, the normal Codex host pilot reached exit 0 while its effective
read-only policy rejected both the edit and test. A newly authorized,
invocation-local automatic approval review pilot made a real edit and passed
the independent check. A host exit code is not an integration gate.

The first scored C task called Paladin and visibly used a pinned CVE before
editing, but get_pattern_evidence returned partial because requested excerpts
hit the byte limit. Its metadata remained available. The frozen scorer
classified it incomplete because it accepted only complete evidence status.
Do not silently change that primary classification after seeing scored data.
Preserve the raw trace and report a separately labeled post hoc sensitivity
analysis that accepts only excerpt-byte-limit omissions with visible pre-edit
use. Keep both denominators and do not retune or rerun the disclosed task set
as if it were unseen.

Permission changes must be authorized for the current milestone. The M4
single-retry authorization did not carry into M5; the user separately approved
M5-only invocation-local automatic approval review.
