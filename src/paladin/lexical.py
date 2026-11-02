"""BM25 over pack passages and reciprocal rank fusion with dense results.

Dense search finds the candidates; BM25 reorders them so that specific terms in a
question (an API name, a parameter) count. Pure Python, no model, no network.
"""
from collections import Counter
import math
import re

STOP = frozenset("a an the of to in for and or is are be can how do i my what should with from that this when it on "
                 "by as into not without so".split())
K1, B, RRF_K = 1.2, 0.75, 60


def _terms(text):
    return [term for term in re.findall(r"[a-z0-9_]+", text.lower()) if term not in STOP]


class Bm25:
    def __init__(self, documents):
        self.docs = {key: Counter(_terms(text)) for key, text in documents.items()}
        self.lengths = {key: sum(counts.values()) for key, counts in self.docs.items()}
        self.average = sum(self.lengths.values()) / max(len(self.docs), 1)
        frequency = Counter(term for counts in self.docs.values() for term in counts)
        total = len(self.docs)
        self.idf = {term: math.log(1 + (total - n + 0.5) / (n + 0.5)) for term, n in frequency.items()}

    def scores(self, query):
        terms = _terms(query)
        result = {}
        for key, counts in self.docs.items():
            norm = K1 * (1 - B + B * self.lengths[key] / self.average)
            result[key] = sum(self.idf[t] * counts[t] * (K1 + 1) / (counts[t] + norm) for t in terms if t in counts)
        return result


def fuse(dense_ids, lexical_scores, limit):
    """Reorder dense candidates by summed reciprocal ranks; ties keep dense order.

    Lexical ranks are taken over every scored document, so a candidate's lexical
    weight does not depend on how many dense candidates were fetched.
    """
    matched = sorted((key for key, score in lexical_scores.items() if score > 0),
                     key=lambda key: (-lexical_scores[key], key))
    lexical_rank = {key: index for index, key in enumerate(matched, start=1)}
    fused = {key: 1 / (RRF_K + index) + (1 / (RRF_K + lexical_rank[key]) if key in lexical_rank else 0)
             for index, key in enumerate(dense_ids, start=1)}
    return sorted(dense_ids, key=lambda key: -fused[key])[:limit]
