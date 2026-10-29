# Plan: Source-complete patch context

Status: review
Done: P1, P2, P3

## Behavior

- P1: An explicitly requested repair context returns the verified upstream
  patch, its complete changed-file list and a content identity, including
  integration hunks outside the summary card anchor.
- P2: Oversized or malformed patch context is explicitly incomplete; target
  applicability and successful repair are never inferred from source context.
- P3: Existing default guidance and historical pack bytes remain stable.

## Diagnosis

The original baseline already named the CVE and desired fix. Four boundary
cases per family gave both arms little room to differ. BentoML direct-method
scoring bypassed a legitimate middleware repair. Thus absence of measured
benefit is not proof that guidance has no benefit. The concrete content gap is
that summary anchors omit integration changes and complete upstream tests.

## Validation

Use preserved upstream snapshots, explicit source hashes, malformed/oversized
context tests, and the full project suite. A changed guidance response is not
proof of improved agent patch accuracy; a prospective evaluation remains
necessary for that claim.

## Results and review

- All five pilot contexts return complete verified patches. BentoML exposes
  six changed files instead of app.py alone; the real worker returned complete
  context with six paths.
- The reference upstream patch applied to a new vulnerable BentoML copy and
  passed four direct risk/safe boundary cases. This is not an agent comparison.
- Full project suite: 111 tests, OK. Source audit: PASS, 30 patterns and 61
  references.
- fixed -> incomplete hunk content could be labeled complete -> hunk count
  validation and extra-line regression tests.
- fixed -> response budget could discard base guidance -> optional context
  degrades to partial first; oversized response regression test.
- deferred -> reference transplant does not pin a complete base installation
  tree -> four cases are bounded diagnostic evidence only.
- deferred -> increased agent accuracy has not been measured prospectively ->
  no effectiveness claim or candidate promotion.
