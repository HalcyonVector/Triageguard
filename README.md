# TriageGuard

AI-assisted memory forensics and cryptographic malware triage pipeline.
ICT 3141 Information Security Lab, CCE A. Sagnik Basu (240953528), Arjun Mittal (240953440).

Takes a memory dump (plus an optional pcap), extracts processes, connections, injected code and USB history
with Volatility3, identifies ciphers and weak RSA keys, finds credentials, stores everything in SQLite and
turns the findings (never the raw dump) into an evidence-cited report.

## Quick start

```bash
pip install -r requirements.txt
python samples/make_synthetic.py                      # builds samples/synthetic.raw
python -m triageguard crypto samples/synthetic.raw     # crypto module only
python -m triageguard analyze samples/synthetic.raw --no-llm
pytest -q
```

For the LLM report, set `GROQ_API_KEY` (free tier) and drop `--no-llm`. Model defaults to
`llama-3.3-70b-versatile`, override with `TRIAGEGUARD_MODEL`.

Volatility3 downloads Windows symbols from the Microsoft symbol server on first use. If that is blocked,
download ISF symbol tables (e.g. JPCERTCC/Windows-Symbol-Tables) and set `TRIAGEGUARD_VOL_SYMBOLS=/path/to/symbols`.

To test on real process memory without a Windows image, `samples/dump_process.py <pid> out.raw` dumps a
running Linux process (e.g. one holding synthetic keys), which the crypto and credential stages scan as is.

Real dumps: any public Windows image works, e.g. the Volatility Foundation samples, MemLabs, or CTF
memory challenges. `python -m triageguard analyze dump.raw --pcap traffic.pcap --binary dropped.exe`

## Pipeline

| Stage | Module | What it does |
|---|---|---|
| 1. Memory | `memory.py` | Volatility3 `pslist`, `cmdline`, `netscan`, `malfind --dump`, USBSTOR registry key |
| 2. Static | `static.py` | strings, PE headers, section entropy, crypto imports, YARA (`rules/`) |
| 3. Crypto | `crypto/` | entropy regions, cipher ID with confidence %, RSA key extraction + weak key tests |
| 4. Credentials | `credentials.py` | JWT decode + checks, OAuth/API tokens, `otpauth://` OTP secrets (stored redacted) |
| 5. Network | `network.py` | pyshark: conversations, DNS, TLS SNI, negotiated version and cipher suite (flags no forward secrecy, CBC, deprecated versions) |
| 6. Report | `report.py` | Groq LLM report citing finding ids `[F3]`, or rule-based fallback |

Everything lands in SQLite (`store.py`), one row per finding with a citation id.

### Cipher identification

Signatures live in `crypto/signatures.py`. Confidence per algorithm is `1 - prod(1 - w)` over the matched
signatures, and each result says whether it rests on implementation constants (the cipher is actually
implemented here) or only on API/string references.

| Algorithm | Evidence |
|---|---|
| AES | S-box, inverse S-box, T-tables (both endians), Rcon, CALG/CNG names |
| DES / 3DES | IP, PC-1, S1 tables, OpenSSL SPtrans, `CALG_3DES`, `DES-EDE3` |
| ChaCha20 / Salsa20 | `expand 32-byte k` and `expand 16-byte k` constants |
| AES-GCM | GHASH reduction tables (rem_4bit, rem_8bit), `ChainingModeGCM` |
| Curve25519 / Ed25519 | p = 2^255-19, Ed25519 d constant |
| ECC P-256, secp256k1 | curve b, order n, base point, CNG names |
| RSA | rsaEncryption OID, CAPI/CNG key blob headers, PEM |

Checked against real libraries: OpenSSL `libcrypto.so.3`, `libsodium` and `libgcrypt` are all identified
correctly, and 1 MB of random data gives zero hits.

### RSA weak key tests

Keys are pulled from CAPI blobs, CNG blobs, DER SubjectPublicKeyInfo and PEM, then tested for: modulus
size (<=512 critical, <1024 high, <2048 medium), small exponent, shared modulus with different exponents,
shared prime via pairwise GCD, close primes via Fermat, and small factors. Each key gets a 0 to 100 strength score.

## Constraints

Public datasets and synthetic keys/tokens only. No live malware execution, no cracking of third-party data,
no real user credentials. The synthetic sample is generated locally from random values.

## Roadmap

- [x] Pipeline skeleton, SQLite store, CLI
- [x] Crypto module: entropy, cipher ID (widened scope), RSA weak keys
- [x] Credential module, rule-based report, Groq report
- [x] Tested on real process memory + locally captured TLS pcap
- [ ] Run on a public Windows dump and tune severities
- [ ] LLM red-teaming: misleading content embedded in the dump (fake strings, prompt injection in findings)
- [ ] Defences: input sanitisation, mandatory citation check, rule-based cross-check; before/after metrics
- [ ] Post-quantum (ML-KEM, ML-DSA): discussion only unless time allows
