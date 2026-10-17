# TriageGuard report (rule-based)

**Risk score:** 97/100 (critical, CVSS v3.1 bands)
- Compromise: 95/100 (critical), evidence of attacker activity
- Crypto exposure: 98/100 (critical), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 0/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| compromise | memory/suspicious_process | 3 | [F7] | 0.95 |
| exposure | rsa/rsa_key | 16 | [F25] | 0.95 |
| exposure | credentials/JWT | 3 | [F40] | 0.55 |

## Cipher identification
- [F12] **info** AES identified (99.9%, implementation constants) in MemoryDump.mem
- [F13] **info** ECC P-256 identified (99.0%, implementation constants) in MemoryDump.mem
- [F14] **info** AES-GCM identified (95.5%, API/string references only) in MemoryDump.mem
- [F15] **info** ECC secp256k1 identified (92.8%, implementation constants) in MemoryDump.mem
- [F16] **info** RSA identified (92.8%, implementation constants) in MemoryDump.mem
- [F17] **info** generic identified (83.2%, API/string references only) in MemoryDump.mem
- [F18] **info** 3DES identified (72.0%, API/string references only) in MemoryDump.mem
- [F19] **info** ChaCha20/Salsa20 identified (70.0%, implementation constants) in MemoryDump.mem
- [F20] **info** DES identified (60.0%, implementation constants) in MemoryDump.mem
- [F21] **info** Curve25519 identified (40.0%, API/string references only) in MemoryDump.mem

## RSA keys
- [F22] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F23] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F24] **info** RSA-512 key e=65537 (CAPI blob), strength 0/100 (0-bit security, broken): modulus size
- [F25] **critical** RSA-512 key e=65537 (CAPI blob), strength 0/100 (0-bit security, broken): modulus size
- [F26] **low** RSA-2048 key e=3 (CNG blob), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F27] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F28] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F29] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F30] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F31] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F32] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F33] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F34] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F35] **low** RSA-1536 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F36] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F37] **info** RSA-512 key e=65537 (DER SPKI), strength 0/100 (0-bit security, broken): modulus size
- [F38] **info** 130 RSA keys with no weaknesses and 9 corrupt key-like structures in MemoryDump.mem

## Encrypted / packed regions
- [F39] **info** 200 high-entropy regions (864256 bytes) in MemoryDump.mem

## Credentials
- [F40] **medium** JWT eyJ0eX...8PgA: token expired
- [F41] **medium** JWT eyJ0eX...1m-w: token expired
- [F42] **medium** JWT eyJ0eX...zUuQ: token expired

## Processes and memory
- [F1] **info** processes: 100 rows
- [F2] **info** cmdlines: 100 rows
- [F3] **info** network: 113 rows
- [F4] **info** injected: 3 rows
- [F5] **info** usb: 25 rows
- [F6] **low** PID 5704 RuntimeBroker.: 1 RWX/injected region(s): 1 x region starts with zero bytes, no code at the region base
- [F7] **critical** PID 5896 oneetx.exe: 1 RWX/injected region(s): 1 x contains a PE header (MZ), likely injected DLL/EXE
- [F8] **low** PID 7540 smartscreen.ex: 1 RWX/injected region(s): 1 x executable private memory with code unique to this process

## Static analysis
- [F9] **info** pid.5704.vad.0x21ddbca0000-0x21ddbcaffff.dmp: entropy 1.982, crypto imports [], yara []
- [F10] **info** pid.5896.vad.0x400000-0x437fff.dmp: entropy 0.397, crypto imports [], yara []
- [F11] **info** pid.7540.vad.0x2505c140000-0x2505c15ffff.dmp: entropy 0.257, crypto imports [], yara []

## MITRE ATT&CK view

| Tactic | Technique | Findings |
|---|---|---|
| Defense Evasion | T1055 Process Injection | [F7] |
| Credential Access | T1528 Steal Application Access Token | [F40], [F41], [F42] |
| Credential Access | T1552 Unsecured Credentials | [F40], [F41], [F42] |
