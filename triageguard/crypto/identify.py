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


def score(found):
    """Turn raw signature hits into per-algorithm confidence.

    Returns a list of dicts sorted by confidence, highest first.
    """
    by_algo = defaultdict(list)
    for sig, offsets in found.values():
        by_algo[sig.algo].append((sig, offsets))

    results = []
    for algo, hits in by_algo.items():
        miss = 1.0
        for sig, _ in hits:
            miss *= 1 - sig.weight
        has_constant = any(s.kind == "constant" for s, _ in hits)
        results.append({
            "algorithm": algo,
            "confidence": round((1 - miss) * 100, 1),
            # constants mean the cipher is implemented here; API strings only
            # mean it is referenced (could be an import that is never called)
            "basis": "implementation constants" if has_constant else "API/string references only",
            "evidence": [
                {"signature": s.name, "kind": s.kind, "count": len(o), "offsets": [hex(x) for x in o[:5]]}
                for s, o in hits
            ],
        })

    # AES-GCM implies AES; if GCM is seen but AES itself was weak, lift AES a bit
    algos = {r["algorithm"]: r for r in results}
    if "AES-GCM" in algos and "AES" not in algos:
        results.append({
            "algorithm": "AES",
            "confidence": round(algos["AES-GCM"]["confidence"] * 0.8, 1),
            "basis": "inferred from AES-GCM evidence",
            "evidence": [],
        })

    results.sort(key=lambda r: r["confidence"], reverse=True)
    return results


def identify_file(path):
    return score(scan_file(path))


def identify_bytes(data):
    return score(scan_buffer(data))
