"""Crypto analysis: entropy, cipher identification, RSA weak-key tests."""

import mmap

from . import entropy, identify, rsa_weak


def analyse(path):
    """Run every crypto check on one file (dump, binary or memory region)."""
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        algos = identify.score(identify.scan_buffer(mm))
        keys = rsa_weak.extract_keys(mm, source=str(path))
    # Tor microdescriptors carry one RSA-1024 onion key per relay: thousands of them say
    # "a Tor client ran here", and testing each pairwise would take hours
    tor = [k for k in keys if k["format"] == rsa_weak.TOR]
    keys = rsa_weak.assess([k for k in keys if k["format"] != rsa_weak.TOR])
    return {
        "algorithms": algos,
        "rsa_keys": rsa_weak.to_serialisable(keys),
        "tor_keys": {"count": len(tor), "first_offset": tor[0]["offset"] if tor else None},
        "high_entropy_regions": entropy.high_entropy_regions(path),
    }
