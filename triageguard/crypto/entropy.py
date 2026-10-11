"""Shannon entropy over fixed windows, to spot encrypted or packed regions.

H = -sum p_b log2 p_b over byte values (Shannon 1948), 0 to 8 bits per byte.
Threshold: Lyda and Hamrock (IEEE S&P 2007) measured average entropy of 6.80 for
packed and 7.18 for encrypted executables, so 7.2 sits at the encrypted level and
above packed code. For reference, a 4 KB window of truly random bytes measures about
7.955, not 8, because the plug-in estimate is biased low by about (256-1)/(2N ln 2)
(Miller 1955). Entropy alone cannot tell encrypted from compressed data: deflate or
LZMA output passes a byte-uniformity chi-square test in 4 KB windows as often as
random data does (we checked), which is why Casino et al. (2025) train a classifier
for that. So these regions are "encrypted or compressed", never "encrypted".
"""

import math
from collections import Counter

HIGH = 7.2  # bits/byte, encrypted-executable level from Lyda and Hamrock 2007


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
