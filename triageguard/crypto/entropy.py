"""Shannon entropy over fixed windows, to spot encrypted or packed regions."""

import math
from collections import Counter

HIGH = 7.2  # bits/byte; random or encrypted data sits close to 8.0


def shannon(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def high_entropy_regions(path, window=4096, threshold=HIGH, max_regions=200):
    """Scan a file in windows and merge adjacent high-entropy windows."""
    regions, cur = [], None
    with open(path, "rb") as f:
        offset = 0
        while True:
            chunk = f.read(window)
            if not chunk:
                break
            e = shannon(chunk)
            if e >= threshold:
                if cur and cur["end"] == offset:
                    cur["end"] = offset + len(chunk)
                    cur["max_entropy"] = max(cur["max_entropy"], e)
                else:
                    cur = {"start": offset, "end": offset + len(chunk), "max_entropy": e}
                    regions.append(cur)
                    if len(regions) >= max_regions:
                        break
            offset += len(chunk)
    for r in regions:
        r["size"] = r["end"] - r["start"]
        r["max_entropy"] = round(r["max_entropy"], 3)
        r["start"], r["end"] = hex(r["start"]), hex(r["end"])
    return regions
