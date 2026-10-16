# TriageGuard report (rule-based)

**Risk score:** 86/100 (high, CVSS v3.1 bands)
- Compromise: 80/100 (high), evidence of attacker activity
- Crypto exposure: 55/100 (medium), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 88/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| compromise | memory/suspicious_process | 6 | [F6] | 0.80 |
| exposure | rsa/rsa_key | 2 | [F27] | 0.55 |

## Cipher identification
- [F12] **info** AES identified (100.0%, implementation constants) in ubuntu-lab-Snapshot1.vmem
- [F13] **info** ECC P-256 identified (99.1%, implementation constants) in ubuntu-lab-Snapshot1.vmem
- [F14] **info** AES-GCM identified (97.6%, implementation constants) in ubuntu-lab-Snapshot1.vmem
- [F15] **info** ChaCha20/Salsa20 identified (95.5%, implementation constants) in ubuntu-lab-Snapshot1.vmem
- [F16] **info** ECC secp256k1 identified (92.8%, implementation constants) in ubuntu-lab-Snapshot1.vmem
- [F17] **info** DES identified (80.0%, implementation constants) in ubuntu-lab-Snapshot1.vmem
- [F18] **info** Curve25519 identified (78.4%, API/string references only) in ubuntu-lab-Snapshot1.vmem
- [F19] **info** RSA identified (70.0%, implementation constants) in ubuntu-lab-Snapshot1.vmem
- [F20] **info** 3DES identified (50.0%, API/string references only) in ubuntu-lab-Snapshot1.vmem

## RSA keys
- [F21] **low** RSA-2048 key e=43147 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F22] **info** 98 RSA keys with no weaknesses and 0 corrupt key-like structures in ubuntu-lab-Snapshot1.vmem
- [F24] **info** No RSA prime found in updater (PID 1275) for its 0 RSA key(s)
- [F25] **info** No RSA prime found in syncd (PID 1276) for its 0 RSA key(s)
- [F26] **info** RSA-2048 private key of keysvc (PID 1277) recovered from a prime left in its memory at 0xabbbe0: data encrypted under this key can be decrypted
- [F27] **high** RSA-2048 key e=3 (DER SPKI) in legacy_rsa (PID 1278), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F28] **info** RSA-2048 private key of legacy_rsa (PID 1278) recovered from a prime left in its memory at 0xabc010: data encrypted under this key can be decrypted

## AES keys recovered
- [F29] **info** AES-256 key of updater (PID 1275) recovered from its expanded key schedule at 0x9ea098, key id aad044fcc2de: data encrypted under this key can be decrypted
- [F30] **info** AES-256 key of keysvc (PID 1277) recovered from its expanded key schedule at 0x8287b0 (2 copies), key id 05a7c63877ac: data encrypted under this key can be decrypted
- [F31] **info** AES-256 key of keysvc (PID 1277) recovered from its expanded key schedule at 0xabac30 (2 copies), key id 8ef4845f2e8c: data encrypted under this key can be decrypted
- [F32] **info** AES-256 key of legacy_rsa (PID 1278) recovered from its expanded key schedule at 0x8d1550 (2 copies), key id 604cc1badd23: data encrypted under this key can be decrypted
- [F33] **info** AES-256 key of legacy_rsa (PID 1278) recovered from its expanded key schedule at 0xabba30 (2 copies), key id 86e81212f32a: data encrypted under this key can be decrypted
- [F34] **info** AES-256 key schedule identical in 2 processes (keysvc (1277), legacy_rsa (1278)), key id 630dcd2966c4: mapped from a shared library, so likely a built-in constant rather than a key the malware made

## Encrypted / packed regions
- [F23] **info** 200 high-entropy regions (18141184 bytes) in ubuntu-lab-Snapshot1.vmem

## Processes and memory
- [F1] **info** processes: 252 rows
- [F2] **info** cmdlines: 252 rows
- [F3] **info** network: 299 rows
- [F4] **info** injected: 1 rows
- [F5] **info** bash: 15 rows
- [F6] **high** PID 931 unattended-upgr: 1 RWX/injected region(s): 1 x executable private memory with code unique to this process
- [F7] **medium** PID 1275 updater: command line mentions 'encrypt': /tmp/tglab/updater -c 
import os, sys
case, key = sys.argv[1], bytes.fromhex(sys.argv[2])
keep, n = [os.urandom(8 << 20)], 0
if case != "control":
    from cryptography.hazmat.primitives import serial
- [F8] **medium** PID 1276 syncd: command line mentions 'encrypt': /tmp/tglab/syncd -c 
import os, sys
case, key = sys.argv[1], bytes.fromhex(sys.argv[2])
keep, n = [os.urandom(8 << 20)], 0
if case != "control":
    from cryptography.hazmat.primitives import serializ
- [F9] **medium** PID 1277 keysvc: command line mentions 'encrypt': /tmp/tglab/keysvc -c 
import os, sys
case, key = sys.argv[1], bytes.fromhex(sys.argv[2])
keep, n = [os.urandom(8 << 20)], 0
if case != "control":
    from cryptography.hazmat.primitives import seriali
- [F10] **medium** PID 1278 legacy_rsa: command line mentions 'encrypt': /tmp/tglab/legacy_rsa -c 
import os, sys
case, key = sys.argv[1], bytes.fromhex(sys.argv[2])
keep, n = [os.urandom(8 << 20)], 0
if case != "control":
    from cryptography.hazmat.primitives import ser
- [F11] **medium** PID 1279 python3: command line mentions 'encrypt': /usr/bin/python3 -c 
import os, sys
case, key = sys.argv[1], bytes.fromhex(sys.argv[2])
keep, n = [os.urandom(8 << 20)], 0
if case != "control":
    from cryptography.hazmat.primitives import serializ

## MITRE ATT&CK view

| Tactic | Technique | Findings |
|---|---|---|
| Defense Evasion | T1055 Process Injection | [F6] |
| Impact | T1486 Data Encrypted for Impact | [F7], [F8], [F9], [F10], [F11] |
