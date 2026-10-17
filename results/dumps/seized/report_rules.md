# TriageGuard report (rule-based)

**Risk score:** 82/100 (high, CVSS v3.1 bands)
- Compromise: 80/100 (high), evidence of attacker activity
- Crypto exposure: 20/100 (low), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 88/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| compromise | memory/suspicious_process | 3 | [F7] | 0.80 |
| exposure | rsa/rsa_key | 3 | [F15] | 0.20 |

## Cipher identification
- [F9] **info** AES identified (94.2%, implementation constants) in dump.mem
- [F10] **info** RSA identified (91.0%, implementation constants) in dump.mem
- [F11] **info** ChaCha20/Salsa20 identified (89.2%, implementation constants) in dump.mem
- [F12] **info** AES-GCM identified (76.0%, implementation constants) in dump.mem
- [F13] **info** 3DES identified (50.0%, API/string references only) in dump.mem
- [F14] **info** Curve25519 identified (40.0%, API/string references only) in dump.mem

## RSA keys
- [F15] **low** RSA-2048 key e=43147 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F16] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F17] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F18] **info** 118 RSA keys with no weaknesses and 1 corrupt key-like structures in dump.mem

## Encrypted / packed regions
- [F19] **info** 200 high-entropy regions (2269184 bytes) in dump.mem

## Processes and memory
- [F1] **info** processes: 220 rows
- [F2] **info** cmdlines: 220 rows
- [F3] **info** network: skipped (ValueError: Symbol type not in symbol_table_name1 SymbolTable: inet6_ifaddr)
- [F4] **info** injected: 1 rows
- [F5] **info** bash: 0 rows
- [F6] **low** PID 3636 anacron: 1 RWX/injected region(s): 1 x region starts with zero bytes, no code at the region base
- [F7] **high** PID 2876 bash: shell started by ncat (PID 2854): a reverse or bind shell
- [F8] **high** PID 2886 python: upgrades a reverse shell to a full terminal ('pty.spawn'): python -c import pty; pty.spawn("/bin/bash")
