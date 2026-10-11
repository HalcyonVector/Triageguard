"""Cipher identification from constants and API strings, with confidence %."""

import mmap
import os
from collections import defaultdict

from .signatures import SIGNATURES

MAX_HITS = 20  # offsets kept per signature, enough to cite as evidence


def _find_all(buf, pattern, limit=MAX_HITS):
    hits, start = [], 0
    while len(hits) < limit:
        i = buf.find(pattern, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    return hits


def scan_buffer(buf):
    """Return {sig_name: (Sig, [offsets])} for every signature found in buf."""
    found = {}
    for sig in SIGNATURES:
        offsets = _find_all(buf, sig.pattern)
        if sig.wide:
            offsets += _find_all(buf, sig.pattern.decode().encode("utf-16le"))
        if offsets:
            found[sig.name] = (sig, sorted(offsets))
    return found


def scan_file(path):
    if os.path.getsize(path) == 0:
        return {}
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        return scan_buffer(mm)


def combine(masses):
    """Dempster's rule of combination for simple support functions that all back the
    same hypothesis ("algorithm A is present"). Each matched signature commits mass w
    to A and 1 - w to "don't know"; with no competing hypothesis there is no conflict
    and the combined belief is Bel(A) = 1 - prod(1 - w) (Shafer 1976, ch. 4). This is
    the same expression as Pearl's noisy-OR (1988). It assumes the signatures are
    independent pieces of evidence, so repeat hits of one signature count once."""
    miss = 1.0
    for w in masses:
        miss *= 1 - w
    return 1 - miss


def score(found):
    """Turn raw signature hits into per-algorithm confidence (belief, in %).

    Returns a list of dicts sorted by confidence, highest first.
    """
    by_algo = defaultdict(list)
    for sig, offsets in found.values():
        by_algo[sig.algo].append((sig, offsets))

    results = []
    for algo, hits in by_algo.items():
        has_constant = any(s.kind == "constant" for s, _ in hits)
        results.append({
            "algorithm": algo,
            "confidence": round(combine(s.weight for s, _ in hits) * 100, 1),
            # constants mean the cipher is implemented here; API strings only
            # mean it is referenced (could be an import that is never called)
            "basis": "implementation constants" if has_constant else "API/string references only",
            "evidence": [
                {"signature": s.name, "kind": s.kind, "count": len(o), "offsets": [hex(x) for x in o[:5]]}
                for s, o in hits
            ],
        })

    # AES-GCM is a subset of AES, and belief is monotone over subsets (Bel(A) >= Bel(B)
    # when B is contained in A), so mass committed to AES-GCM also supports AES: combine
    # the two with the same rule. This replaces an earlier fixed 0.8 factor.
    algos = {r["algorithm"]: r for r in results}
    if gcm := algos.get("AES-GCM"):
        aes = algos.get("AES")
        if aes is None:
            results.append({"algorithm": "AES", "confidence": gcm["confidence"],
                            "basis": "inferred from AES-GCM evidence", "evidence": []})
        else:
            aes["confidence"] = round(combine([aes["confidence"] / 100, gcm["confidence"] / 100]) * 100, 1)
            aes["evidence"].append({"signature": "AES-GCM evidence (subset of AES)", "kind": "inferred", "count": 1, "offsets": []})

    results.sort(key=lambda r: r["confidence"], reverse=True)
    return results


def identify_file(path):
    return score(scan_file(path))


def identify_bytes(data):
    return score(scan_buffer(data))
