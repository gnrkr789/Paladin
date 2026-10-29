# Project language and scope

Use English for all project-authored code, comments, identifiers, documentation,
knowledge cards, fixtures, messages and supported text inputs. Korean support,
translation and multilingual fallback are out of scope. Keep chat responses in
the user's preferred language; this does not change the project language.

The current technical-text contract is `english-ascii-v1`: printable ASCII plus
tabs and line breaks. Reject unsupported characters before model/database access.
This is a deterministic character contract, not a natural-language classifier.
Use escaped Unicode literals only to exercise rejected-input behavior in tests.

Preserve original third-party evidence, raw affected-version claims and historical
records verbatim. They are provenance, not supported product input. Do not modify
source bytes or historical results to make a language scan pass. Keep obsolete
evaluation fixtures archived separately from the active English evaluation.

Changing the text policy must invalidate encoder/index identity. Keep diagnostic
vectors separate from semantic retrieval. Similarity is not a security verdict;
source observations are not human approval or executed vulnerability tests.

Do not implement the next milestone merely because a handoff describes it.
