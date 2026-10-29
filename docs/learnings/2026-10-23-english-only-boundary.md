# English-only contracts and immutable evidence

Date: 2026-10-23
Context: Paladin M2 initially supported mixed-language retrieval. The user required
English-only internals and inputs after the local pack/model integration.

Decision: Keep authored code, docs, messages, cards and active evaluation English.
Apply a shared deterministic ASCII technical-text policy before DB/model access
and at embedding/pack validation boundaries. Reject unsupported input explicitly;
do not silently translate. A character policy cannot classify all ASCII languages.

Evidence: Initial regression RED had four failures. The implemented policy passes
the 57-test suite; actual CLI rejection exits1/invalid_request, English search
returns the expected CVE, and semantic doctor is ready. The new English evaluation
retrieves relevant cards for20/20 queries; this is not prevention-effectiveness
evidence or a directly comparable improvement over the former mixed-language run.

Lesson: Language capability of a model and the supported product input contract
are separate. Keep validated weights when an interface restriction suffices.
Include the policy in encoder/index identity so old manifests cannot bypass a
changed contract. Preserve raw evidence and historical evaluation bytes; archive
obsolete fixtures rather than rewriting them and invalidating provenance.

Related operational lessons: Docker health can precede collection query readiness;
bounded retry evidence must preserve transient failure. SQLite transaction context
managers do not close connections; explicit closing avoids Windows file locks.

Next use: Apply the same English-only boundary to future MCP tool inputs and
responses. Keep source_observed, human reviewed, rule tested and reproduced states
separate. Do not promote similarity into a blocking verdict.
