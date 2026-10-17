# TriageGuard report (rule-based)

**Risk score:** 90/100 (critical, CVSS v3.1 bands)
- Compromise: 80/100 (high), evidence of attacker activity
- Crypto exposure: 95/100 (critical), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 0/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| exposure | rsa/rsa_key | 32 | [F37] | 0.95 |
| compromise | memory/suspicious_process | 6 | [F6] | 0.80 |

## Cipher identification
- [F23] **info** AES identified (100.0%, implementation constants) in memory.dmp
- [F24] **info** Curve25519 identified (99.7%, implementation constants) in memory.dmp
- [F25] **info** RSA identified (99.6%, implementation constants) in memory.dmp
- [F26] **info** AES-GCM identified (99.3%, implementation constants) in memory.dmp
- [F27] **info** ECC P-256 identified (99.0%, implementation constants) in memory.dmp
- [F28] **info** ECC secp256k1 identified (92.8%, implementation constants) in memory.dmp
- [F29] **info** generic identified (83.2%, API/string references only) in memory.dmp
- [F30] **info** ChaCha20/Salsa20 identified (82.0%, implementation constants) in memory.dmp
- [F31] **info** DES identified (60.0%, implementation constants) in memory.dmp
- [F32] **info** 3DES identified (60.0%, API/string references only) in memory.dmp

## RSA keys
- [F33] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F34] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F35] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F36] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F37] **critical** RSA-512 key e=65537 (CAPI blob), strength 0/100 (0-bit security, broken): modulus size
- [F38] **low** RSA-2048 key e=3 (CNG blob), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F39] **low** RSA-1536 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F40] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F41] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F42] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F43] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F44] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F45] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F46] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F47] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F48] **critical** RSA-512 key e=65537 (DER SPKI), strength 0/100 (0-bit security, broken): modulus size
- [F49] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F50] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F51] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F52] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F53] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F54] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F55] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F56] **low** RSA-2048 key e=43147 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F57] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F58] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F59] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F60] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F61] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F62] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F63] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F64] **info** 477 RSA keys with no weaknesses and 6 corrupt key-like structures in memory.dmp
- [F66] **info** RSA-2048 key e=65537 (CNG blob) in ChromeSetup.ex (PID 4628), strength None/100 (None-bit security, None): invalid modulus
- [F67] **info** RSA prime search skipped in ChromeSetup.ex (PID 4628): 529 MB process, 56 RSA key(s) assessed but not tested for leftover primes

## Symmetric keys recovered
- [F68] **info** AES-128 key of ChromeSetup.ex (PID 4628) recovered from its expanded key schedule at 0x164ca960, key id 996c4ee5be0f: data encrypted under this key can be decrypted
- [F69] **info** AES-128 key of ChromeSetup.ex (PID 4628) recovered from its expanded key schedule at 0x1d437aa0 (2 copies), key id 69daecf5c89f: data encrypted under this key can be decrypted
- [F70] **info** AES-256 key of ChromeSetup.ex (PID 4628) recovered from its expanded key schedule at 0x1672bbb0, key id 858f7c634419: data encrypted under this key can be decrypted

## Encrypted / packed regions
- [F65] **info** 200 high-entropy regions (1081344 bytes) in memory.dmp

## Processes and memory
- [F1] **info** processes: 127 rows
- [F2] **info** cmdlines: 127 rows
- [F3] **info** network: 86 rows
- [F4] **info** injected: 11 rows
- [F5] **info** usb: 28 rows
- [F6] **high** PID 2128 SearchApp.exe: 2 RWX/injected region(s): 1 x identical code in 3 processes, likely a system-wide hook; 1 x executable private memory with code unique to this process
- [F7] **high** PID 7068 RuntimeBroker.: 1 RWX/injected region(s): 1 x executable private memory with code unique to this process
- [F8] **high** PID 7484 smartscreen.ex: 5 RWX/injected region(s): 3 x identical code in 3 processes, likely a system-wide hook; 2 x executable private memory with code unique to this process
- [F9] **low** PID 7780 OneDrive.exe: 1 RWX/injected region(s): 1 x region starts with zero bytes, no code at the region base
- [F10] **high** PID 5912 WWAHost.exe: 2 RWX/injected region(s): 1 x identical code in 3 processes, likely a system-wide hook; 1 x executable private memory with code unique to this process
- [F11] **low** PID 4628 ChromeSetup.ex: runs from a user-writable folder: "C:\Users\alex\Downloads\ChromeSetup.exe" 

## Static analysis
- [F12] **info** pid.2128.vad.0x25942230000-0x2594224ffff.dmp: entropy 0.836, crypto imports [], yara []
- [F13] **info** pid.2128.vad.0x259535c0000-0x25953623fff.dmp: entropy 0.086, crypto imports [], yara []
- [F14] **info** pid.5912.vad.0x18909a60000-0x18909a7ffff.dmp: entropy 0.466, crypto imports [], yara []
- [F15] **info** pid.5912.vad.0x1890a380000-0x1890a3e3fff.dmp: entropy 0.081, crypto imports [], yara []
- [F16] **info** pid.7068.vad.0x1db7d360000-0x1db7d360fff.dmp: entropy 0.117, crypto imports [], yara []
- [F17] **info** pid.7484.vad.0x1f413fe0000-0x1f413ffffff.dmp: entropy 0.257, crypto imports [], yara []
- [F18] **info** pid.7484.vad.0x1f414320000-0x1f414383fff.dmp: entropy 0.081, crypto imports [], yara []
- [F19] **info** pid.7484.vad.0x1f4247d0000-0x1f4247effff.dmp: entropy 0.257, crypto imports [], yara []
- [F20] **info** pid.7484.vad.0x1f424860000-0x1f4248c3fff.dmp: entropy 0.081, crypto imports [], yara []
- [F21] **info** pid.7484.vad.0x1f4351d0000-0x1f4351effff.dmp: entropy 0.257, crypto imports [], yara []
- [F22] **info** pid.7780.vad.0x76b0000-0x76bffff.dmp: entropy 0.341, crypto imports [], yara []

## MITRE ATT&CK view

| Tactic | Technique | Findings |
|---|---|---|
| Defense Evasion | T1055 Process Injection | [F6], [F7], [F8], [F10] |
