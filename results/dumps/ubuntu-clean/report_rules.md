# TriageGuard report (rule-based)

**Risk score:** 28/100 (low, CVSS v3.1 bands)
- Compromise: 20/100 (low), evidence of attacker activity
- Crypto exposure: 20/100 (low), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 88/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| compromise | memory/suspicious_process | 1 | [F6] | 0.20 |
| exposure | rsa/rsa_key | 1 | [F16] | 0.20 |

## Cipher identification
- [F7] **info** AES identified (100.0%, implementation constants) in ubuntu-lab-Snapshot2.vmem
- [F8] **info** Curve25519 identified (99.9%, implementation constants) in ubuntu-lab-Snapshot2.vmem
- [F9] **info** ECC P-256 identified (99.1%, implementation constants) in ubuntu-lab-Snapshot2.vmem
- [F10] **info** AES-GCM identified (97.6%, implementation constants) in ubuntu-lab-Snapshot2.vmem
- [F11] **info** ChaCha20/Salsa20 identified (95.5%, implementation constants) in ubuntu-lab-Snapshot2.vmem
- [F12] **info** ECC secp256k1 identified (92.8%, implementation constants) in ubuntu-lab-Snapshot2.vmem
- [F13] **info** RSA identified (91.0%, implementation constants) in ubuntu-lab-Snapshot2.vmem
- [F14] **info** DES identified (80.0%, implementation constants) in ubuntu-lab-Snapshot2.vmem
- [F15] **info** 3DES identified (50.0%, API/string references only) in ubuntu-lab-Snapshot2.vmem

## RSA keys
- [F16] **low** RSA-2048 key e=43147 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F17] **info** 95 RSA keys with no weaknesses and 0 corrupt key-like structures in ubuntu-lab-Snapshot2.vmem

## Encrypted / packed regions
- [F18] **info** 200 high-entropy regions (18993152 bytes) in ubuntu-lab-Snapshot2.vmem

## Processes and memory
- [F1] **info** processes: 244 rows
- [F2] **info** cmdlines: 244 rows
- [F3] **info** network: 308 rows
- [F4] **info** injected: 1 rows
- [F5] **info** bash: 11 rows
- [F6] **low** PID 843 unattended-upgr: 1 RWX/injected region(s): 1 x libffi closure trampolines (Python ctypes/cffi callbacks), RWX by design
