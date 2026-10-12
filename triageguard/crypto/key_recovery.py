"""Recover an RSA private key from leftover primes in process memory.

Windows CryptoAPI on XP to 7 does not wipe the primes p and q from memory when a key
pair is generated and the context is released (CryptReleaseContext). WannaCry
generates a per-victim RSA-2048 pair with CryptGenKey, so its process memory can
still hold p long after encryption; wannakey (A. Guinet, 2017) and WanaKiwi (B. Delpy, 2017) used this to
decrypt victims' files without paying. The same check works for any RSA key: if a
number of half the modulus size that divides n is lying in memory, the key is broken.

The scan reads every 4-byte aligned window of len(n)/2 bytes, in little-endian (how
CryptoAPI stores big numbers) and big-endian order, keeps only odd candidates with the
top bit set (every RSA prime has both), and tests the product of all moduli mod p.
"""

ALIGN = 4
PAGE = 4096


def _scan(data, size, align):
    """Yield (offset, window) for aligned windows worth testing. Pages of zeros, the bulk
    of most process memory, are skipped at C speed."""
    end = len(data) - size + 1
    for page in range(0, max(end, 0), PAGE):
        if data[page:page + PAGE + size].count(0) > PAGE + size - 16:
            continue
        for i in range(page, min(page + PAGE, end), align):
            lo, hi = data[i], data[i + size - 1]
            # every RSA prime is odd with its top bit set: check both byte orders cheaply
            if (lo & 1 and hi & 0x80) or (hi & 1 and lo & 0x80):
                yield i, data[i:i + size]


def find_factors(moduli, data, align=ALIGN):
    """Scan data once for primes of any of the moduli (all of one size).
    Returns {n: (p, offset, byte order)}. All moduli are tested with one remainder
    against their product, so many keys cost about the same as one."""
    size = (max(n.bit_length() for n in moduli) + 15) // 16  # bytes in one prime of a balanced key
    if size < 32:
        return {}
    product = 1
    for n in moduli:
        product *= n
    found = {}
    for i, window in _scan(data, size, align):
        for o in ("little", "big"):
            p = int.from_bytes(window, o)
            if not p & 1 or p.bit_length() != 8 * size or product % p:
                continue
            for n in moduli:
                if n not in found and n % p == 0 and p < n:
                    found[n] = (p, i, o)
        if len(found) == len(moduli):
            break
    return found


def recover(keys, data, align=ALIGN, min_bits=1024):
    """Try every key of at least min_bits against data. Returns one result per key whose
    private key could be rebuilt; d is checked by a round trip, never stored."""
    by_size = {}
    for k in keys:
        if k["n"].bit_length() >= min_bits:
            by_size.setdefault((k["n"].bit_length() + 15) // 16, {}).setdefault(k["n"], k)
    found = []
    for group in by_size.values():
        for n, (p, offset, order) in find_factors(list(group), data, align).items():
            k, e, q = group[n], group[n]["e"], n // p
            d = pow(e, -1, (p - 1) * (q - 1))
            if pow(pow(2, e, n), d, n) != 2:
                continue
            found.append({"bits": n.bit_length(), "e": e, "fingerprint": k.get("fingerprint"), "key_offset": k.get("offset"),
                          "prime_offset": hex(offset), "byte_order": order, "format": k.get("format")})
    return found
