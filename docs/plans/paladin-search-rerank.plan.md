# Plan: Second encoder and reranker for prevention search

Status: dropped
Done: R1, R2, R3, R4, R5, R6 (built, measured, then removed)

## Summary

MCP search (run only when an agent or user asks; never in the change hook) was to
gain two optional local models: BAAI/bge-small-en-v1.5 as a second dense signal and
cross-encoder/ms-marco-MiniLM-L6-v2 as a reranker. Spike on the development sets
(spent known-item v2 and v3): hybrid e5+BM25 0.754/0.641 and 0.781/0.603 hit@5/MRR;
e5+bge+BM25+MiniLM 0.797/0.698 and 0.844/0.688. Replacing the order with a
reranker alone lowered hit@5, so every model was one more RRF signal.

The gain did not hold on two fresh held-out sets, so the code was removed and
search stays the committed e5+BM25 hybrid (hybrid_bm25_rrf_v1).

## Behavior (as built)

| ID | Given | When | Then |
|---|---|---|---|
| R1 | search models not prepared | a search runs | the e5+BM25 hybrid answers, marked hybrid_bm25_rrf_v1 |
| R2 | `paladin model prepare-search` | it runs | both pinned models are downloaded and verified by size and sha256 |
| R3 | prepared models and a matching bge passage snapshot | a search runs | e5 and bge candidates (100 each) are fused with BM25, the top 40 are scored by the reranker, all four signals are fused, marked hybrid_rerank_v1 |
| R4 | a bge snapshot for another pack or model | a search runs | the reranked path is skipped, R1 applies |
| R5 | the change hook | any edit | it loads none of these models (existing guard test) |
| R6 | a fresh held-out known-item set (targets disjoint from v2 and v3) | measured once | hit@5 and MRR are recorded with the ranking |

## Decisions

- User, 2026-11-02: add the encoder and reranker; heavy evaluation runs only
  before a release or on request. Models are opt-in downloads.
- User, 2026-11-03: after v4, try a heavier reranker (BAAI/bge-reranker-base,
  revision 2cfc18c9415c912f9d8155881c133215df768a70) on a new held-out set.
- User, 2026-11-03: drop the reranked path; keep the hybrid, this record and the
  held-out query sets.

## Results

Held-out sets are each measured once and then count as development sets.

| Set | e5+BM25 hybrid | four signals + MiniLM | four signals + bge-reranker-base |
|---|---|---|---|
| v2 (dev) | 0.754 / 0.641 | 0.797 / 0.698 | 0.812 / 0.711 |
| v3 (dev) | 0.781 / 0.603 | 0.844 / 0.688 | 0.844 / 0.697 |
| v4 (held-out, 59 queries, seed 20261103) | 0.831 / 0.697 | 0.814 / 0.690 | 0.881 / 0.751 (after v4 was spent) |
| v5 (held-out, 55 queries, seed 20261104) | 0.873 / 0.736 | 0.873 / 0.737 | 0.855 / 0.748 |

Values are hit@5 / MRR. Dense e5 alone on v4: 0.780 / 0.632.

- v4 evidence: docs/evidence/m2/retrieval-evaluation-v4-heldout.json (reranked
  MiniLM run via Milvus, search p95 4.8 s).
- v5 targets exclude v2-v4 targets and the sql and xxe families; measured by an
  offline script against the same pack and Milvus pool.
- Cost: MiniLM path about 4 s per query and a 224 MB download; bge-reranker-base
  about 16 s per query for 40 candidates and a 1.1 GB model.
- One v5 query is 0.018 hit@5, so the v5 differences are within noise. The
  development gains came from sets used to choose the method.
- The code and the downloaded models were deleted; this record and the query
  sets are what remains.
