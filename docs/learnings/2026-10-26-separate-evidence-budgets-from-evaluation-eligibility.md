# Separate evidence budgets from evaluation eligibility

The M3 MCP byte budgets serve bounded resource use and explicit truncation:
4,096 bytes by default per requested excerpt, at most 16 KiB per excerpt and
in total, and a 64 KiB serialized tool-result cap. Whole-line truncation is
reported as `partial` with `excerpt_byte_limit`; metadata and available text
may still be useful, but the response is not complete evidence.

The frozen M5 scorer required a `complete` evidence response and a literal
pattern ID in a pre-edit agent message. In the 40 C traces, 30 evidence
responses were `partial`; 27 traces lacked the literal ID even though each
had a pre-edit message discussing Paladin evidence. Only five attempts met
the primary completion rule. Treat this as an evaluation eligibility issue,
not proof that Paladin worked or failed. Preserve the frozen score and raw
traces. Any revised evidence budget or consumption measure belongs to a new,
separately specified protocol with independent review of applicability and
outcomes.
