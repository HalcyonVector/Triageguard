# TriageGuard report (rule-based)

**Risk score:** 96/100 (critical, CVSS v3.1 bands)
- Compromise: 95/100 (critical), evidence of attacker activity
- Crypto exposure: 20/100 (low), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 0/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| compromise | memory/suspicious_process | 5 | [F8] | 0.95 |
| exposure | rsa/rsa_key | 81 | [F34] | 0.20 |

## Cipher identification
- [F26] **info** AES identified (99.9%, implementation constants) in citadeldc01.mem
- [F27] **info** ECC P-256 identified (99.7%, implementation constants) in citadeldc01.mem
- [F28] **info** RSA identified (97.8%, implementation constants) in citadeldc01.mem
- [F29] **info** AES-GCM identified (95.5%, API/string references only) in citadeldc01.mem
- [F30] **info** ECC secp256k1 identified (92.8%, implementation constants) in citadeldc01.mem
- [F31] **info** generic identified (83.2%, API/string references only) in citadeldc01.mem
- [F32] **info** DES identified (80.0%, implementation constants) in citadeldc01.mem
- [F33] **info** 3DES identified (72.0%, API/string references only) in citadeldc01.mem
- [F117] **info** generic identified (51.0%, API/string references only) in pid.3724.vad.0x4afbf20000-0x4afbf51fff.dmp
- [F118] **info** AES identified (30.0%, API/string references only) in pid.3724.vad.0x4afbf20000-0x4afbf51fff.dmp
- [F119] **info** RSA identified (20.0%, API/string references only) in pid.3724.vad.0x4afbf20000-0x4afbf51fff.dmp
- [F120] **info** generic identified (51.0%, API/string references only) in pid.3724.vad.0x4afc070000-0x4afc0a8fff.dmp
- [F121] **info** AES identified (30.0%, API/string references only) in pid.3724.vad.0x4afc070000-0x4afc0a8fff.dmp
- [F122] **info** RSA identified (20.0%, API/string references only) in pid.3724.vad.0x4afc070000-0x4afc0a8fff.dmp
- [F123] **info** generic identified (30.0%, API/string references only) in pid.3724.vad.0x4afc1f0000-0x4afc25afff.dmp

## RSA keys
- [F34] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F35] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F36] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F37] **low** RSA-2048 key e=3 (CNG blob), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F38] **low** RSA-2048 key e=65537 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus
- [F39] **low** RSA-2048 key e=65537 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus
- [F40] **low** RSA-2048 key e=65537 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus
- [F41] **low** RSA-1536 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F42] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F43] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F44] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F45] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F46] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F47] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F48] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F49] **low** RSA-2048 key e=6702873 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus
- [F50] **low** RSA-2048 key e=83529 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus
- [F51] **low** RSA-2048 key e=7266387 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus
- [F52] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F53] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F54] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F55] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F56] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F57] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F58] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F59] **info** RSA-512 key e=65537 (DER SPKI), strength 0/100 (0-bit security, broken): modulus size
- [F60] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F61] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F62] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F63] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F64] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F65] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F66] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F67] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F68] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F69] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F70] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F71] **low** RSA-2047 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F72] **low** RSA-2048 key e=50557 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F73] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F74] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F75] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F76] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F77] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F78] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F79] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F80] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F81] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F82] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F83] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F84] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F85] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F86] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F87] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F88] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F89] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F90] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F91] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F92] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F93] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F94] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F95] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F96] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F97] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F98] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F99] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F100] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F101] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F102] **low** RSA-2048 key e=43147 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F103] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F104] **low** RSA-4096 key e=40409 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F105] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F106] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F107] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F108] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F109] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F110] **low** RSA-4096 key e=62353 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F111] **low** RSA-2047 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F112] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F113] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F114] **low** RSA-1000 key e=65537 (DER SPKI), strength 62/100 (79.1-bit security, disallowed (legacy use only)): modulus size
- [F115] **info** 332 RSA keys with no weaknesses and 9 corrupt key-like structures in citadeldc01.mem

## Encrypted / packed regions
- [F116] **info** 200 high-entropy regions (1753088 bytes) in citadeldc01.mem

## Processes and memory
- [F1] **info** processes: 40 rows
- [F2] **info** cmdlines: 40 rows
- [F3] **info** network: 19685 rows
- [F4] **info** injected: 15 rows
- [F5] **info** usb: 19 rows
- [F6] **low** PID 1292 Microsoft.Acti: 5 RWX/injected region(s): 5 x executable private memory with code unique to this process
- [F7] **low** PID 1236 svchost.exe: 1 RWX/injected region(s): 1 x region starts with zero bytes, no code at the region base
- [F8] **critical** PID 3724 spoolsv.exe: 4 RWX/injected region(s): 1 x executable private memory with code unique to this process; 3 x contains a PE header (MZ), likely injected DLL/EXE
- [F9] **low** PID 3472 explorer.exe: 2 RWX/injected region(s): 2 x region starts with zero bytes, no code at the region base
- [F10] **low** PID 400 ServerManager.: 3 RWX/injected region(s): 3 x executable private memory with code unique to this process

## Static analysis
- [F11] **info** pid.1236.vad.0x1b10ee0000-0x1b10ee0fff.dmp: entropy 1.184, crypto imports [], yara []
- [F12] **info** pid.1292.vad.0x10500100000-0x1050010cfff.dmp: entropy 0.096, crypto imports [], yara []
- [F13] **info** pid.1292.vad.0x10500120000-0x1050012ffff.dmp: entropy 0.278, crypto imports [], yara []
- [F14] **info** pid.1292.vad.0x105001f0000-0x105001fffff.dmp: entropy 0.053, crypto imports [], yara []
- [F15] **info** pid.1292.vad.0x7ff5ff8d0000-0x7ff5ff8dffff.dmp: entropy 0.036, crypto imports [], yara []
- [F16] **info** pid.1292.vad.0x7ff5ff8e0000-0x7ff5ff97ffff.dmp: entropy 0.003, crypto imports [], yara []
- [F17] **info** pid.3472.vad.0x5770000-0x5770fff.dmp: entropy 0.589, crypto imports [], yara []
- [F18] **info** pid.3472.vad.0xd840000-0xd840fff.dmp: entropy 1.413, crypto imports [], yara []
- [F19] **info** pid.3724.vad.0x4afbf20000-0x4afbf51fff.dmp: entropy 5.993, crypto imports [], yara []
- [F20] **info** pid.3724.vad.0x4afc070000-0x4afc0a8fff.dmp: entropy 5.523, crypto imports [], yara []
- [F21] **info** pid.3724.vad.0x4afc1f0000-0x4afc25afff.dmp: entropy 5.689, crypto imports [], yara []
- [F22] **info** pid.3724.vad.0x4afc260000-0x4afc283fff.dmp: entropy 5.424, crypto imports [], yara []
- [F23] **info** pid.400.vad.0x5dc9cb0000-0x5dc9cbcfff.dmp: entropy 0.107, crypto imports [], yara []
- [F24] **info** pid.400.vad.0x5dc9ce0000-0x5dc9ceffff.dmp: entropy 1.138, crypto imports [], yara []
- [F25] **info** pid.400.vad.0x5dc9e70000-0x5dc9e7ffff.dmp: entropy 0.662, crypto imports [], yara []

## Network
- [F124] **info** 50 conversations, TLS SNI ['64.media.tumblr.com', '66.media.tumblr.com', '78.media.tumblr.com', 'a.thumbs.redditmedia.com', 'a125375509.cdn.optimizely.com'], weak TLS []

## MITRE ATT&CK view

| Tactic | Technique | Findings |
|---|---|---|
| Defense Evasion | T1055 Process Injection | [F8] |
