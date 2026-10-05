"""Crypto analysis: entropy, cipher identification, RSA weak-key tests."""

import mmap

from . import entropy, identify, rsa_weak


def analyse(path):
    """Run every crypto check on one file (dump, binary or memory region)."""
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        algos = identify.score(identify.scan_buffer(mm))
        keys = rsa_weak.assess(rsa_weak.extract_keys(mm, source=str(path)))
    return {
        "algorithms": algos,
        "rsa_keys": rsa_weak.to_serialisable(keys),
        "high_entropy_regions": entropy.high_entropy_regions(path),
    }
