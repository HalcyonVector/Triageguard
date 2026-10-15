# TriageGuard report (rule-based)

**Risk score:** 86/100 (high, CVSS v3.1 bands)
- Compromise: 80/100 (high), evidence of attacker activity
- Crypto exposure: 55/100 (medium), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 0/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| compromise | memory/suspicious_process | 4 | [F6] | 0.80 |
| exposure | rsa/rsa_key | 82 | [F110] | 0.55 |

## Cipher identification
- [F23] **info** AES identified (98.8%, implementation constants) in charlie-2009-12-11.mddramimage
- [F24] **info** RSA identified (92.8%, implementation constants) in charlie-2009-12-11.mddramimage
- [F25] **info** generic identified (65.7%, API/string references only) in charlie-2009-12-11.mddramimage
- [F26] **info** DES identified (60.0%, implementation constants) in charlie-2009-12-11.mddramimage
- [F27] **info** 3DES identified (60.0%, API/string references only) in charlie-2009-12-11.mddramimage
- [F28] **info** ECC P-256 identified (40.0%, API/string references only) in charlie-2009-12-11.mddramimage
- [F29] **info** ECC secp256k1 identified (40.0%, API/string references only) in charlie-2009-12-11.mddramimage

## RSA keys
- [F30] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F31] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F32] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F33] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F34] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F35] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F36] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F37] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F38] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F39] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F40] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F41] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F42] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F43] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F44] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F45] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F46] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F47] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F48] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F49] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F50] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F51] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F52] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F53] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F54] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F55] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F56] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F57] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F58] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F59] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F60] **low** RSA-1536 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F61] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F62] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F63] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F64] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F65] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F66] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F67] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F68] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F69] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F70] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F71] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F72] **low** RSA-1000 key e=65537 (DER SPKI), strength 62/100 (79.1-bit security, disallowed (legacy use only)): modulus size
- [F73] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F74] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F75] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F76] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F77] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F78] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F79] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F80] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F81] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F82] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F83] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F84] **low** RSA-2046 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F85] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F86] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F87] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F88] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F89] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F90] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F91] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F92] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F93] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F94] **low** RSA-2046 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F95] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F96] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F97] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F98] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F99] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F100] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F101] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F102] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F103] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F104] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F105] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F106] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F107] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F108] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F109] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F110] **critical** RSA-512 key e=65537 (DER SPKI), strength 0/100 (0-bit security, broken): modulus size
- [F111] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F112] **info** 112 RSA keys with no weaknesses and 2 corrupt key-like structures in charlie-2009-12-11.mddramimage

## Encrypted / packed regions
- [F113] **info** 200 high-entropy regions (11202560 bytes) in charlie-2009-12-11.mddramimage
- [F114] **info** 1 high-entropy regions (8192 bytes) in pid.948.vad.0x12c40000-0x12c43fff.dmp
- [F115] **info** 1 high-entropy regions (4096 bytes) in pid.948.vad.0x18240000-0x18243fff.dmp
- [F116] **info** 1 high-entropy regions (4096 bytes) in pid.948.vad.0x741a0000-0x741a3fff.dmp

## Processes and memory
- [F1] **info** processes: 26 rows
- [F2] **info** cmdlines: 26 rows
- [F3] **info** network: skipped (NotImplementedError: This version of Windows is not supported: 5.1 15.2600!)
- [F4] **info** injected: 13 rows
- [F5] **info** usb: 16 rows
- [F6] **high** PID 924 csrss.exe: 1 RWX/injected region(s): 1 x executable private memory with code unique to this process
- [F7] **high** PID 948 winlogon.exe: 10 RWX/injected region(s): 2 x executable private memory with code unique to this process; 8 x region starts with zero bytes, no code at the region base
- [F8] **low** PID 1004 lsass.exe: 1 RWX/injected region(s): 1 x region starts with zero bytes, no code at the region base
- [F9] **high** PID 3088 soffice.bin: 1 RWX/injected region(s): 1 x executable private memory with code unique to this process

## Static analysis
- [F10] **info** pid.1004.vad.0x280000-0x347fff.dmp: entropy 0.051, crypto imports [], yara []
- [F11] **info** pid.3088.vad.0x29a0000-0x29a0fff.dmp: entropy 0.954, crypto imports [], yara []
- [F12] **info** pid.924.vad.0x7f6f0000-0x7f7effff.dmp: entropy 0.138, crypto imports [], yara []
- [F13] **info** pid.948.vad.0x12c40000-0x12c43fff.dmp: entropy 7.059, crypto imports [], yara []
- [F14] **info** pid.948.vad.0x18240000-0x18243fff.dmp: entropy 7.175, crypto imports [], yara []
- [F15] **info** pid.948.vad.0x22e70000-0x22e73fff.dmp: entropy 1.766, crypto imports [], yara []
- [F16] **info** pid.948.vad.0x4f250000-0x4f253fff.dmp: entropy 5.352, crypto imports [], yara []
- [F17] **info** pid.948.vad.0x52820000-0x52823fff.dmp: entropy 4.885, crypto imports [], yara []
- [F18] **info** pid.948.vad.0x5c0000-0x5dffff.dmp: entropy 0.433, crypto imports [], yara []
- [F19] **info** pid.948.vad.0x6d690000-0x6d693fff.dmp: entropy 3.333, crypto imports [], yara []
- [F20] **info** pid.948.vad.0x741a0000-0x741a3fff.dmp: entropy 6.889, crypto imports [], yara []
- [F21] **info** pid.948.vad.0x7add0000-0x7add3fff.dmp: entropy 2.317, crypto imports [], yara []
- [F22] **info** pid.948.vad.0x7f6f0000-0x7f7effff.dmp: entropy 0.049, crypto imports [], yara []

## MITRE ATT&CK view

| Tactic | Technique | Findings |
|---|---|---|
| Defense Evasion | T1055 Process Injection | [F6], [F7], [F9] |
