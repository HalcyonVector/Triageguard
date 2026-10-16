# TriageGuard report (rule-based)

**Risk score:** 89/100 (high, CVSS v3.1 bands)
- Compromise: 80/100 (high), evidence of attacker activity
- Crypto exposure: 93/100 (critical), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 62/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| compromise | memory/suspicious_process | 5 | [F7] | 0.80 |
| exposure | credentials/JWT | 1 | [F76] | 0.55 |
| exposure | credentials/AWS access key id | 1 | [F77] | 0.55 |
| exposure | credentials/Bearer token | 1 | [F78] | 0.55 |
| exposure | rsa/rsa_key | 36 | [F38] | 0.20 |

## Cipher identification
- [F28] **info** AES identified (100.0%, implementation constants) in 20210430-Win10Home-20H2-64bit-memdump.mem
- [F29] **info** ECC P-256 identified (99.7%, implementation constants) in 20210430-Win10Home-20H2-64bit-memdump.mem
- [F30] **info** RSA identified (99.6%, implementation constants) in 20210430-Win10Home-20H2-64bit-memdump.mem
- [F31] **info** AES-GCM identified (98.2%, implementation constants) in 20210430-Win10Home-20H2-64bit-memdump.mem
- [F32] **info** ChaCha20/Salsa20 identified (93.5%, implementation constants) in 20210430-Win10Home-20H2-64bit-memdump.mem
- [F33] **info** ECC secp256k1 identified (92.8%, implementation constants) in 20210430-Win10Home-20H2-64bit-memdump.mem
- [F34] **info** Curve25519 identified (91.4%, implementation constants) in 20210430-Win10Home-20H2-64bit-memdump.mem
- [F35] **info** DES identified (86.0%, implementation constants) in 20210430-Win10Home-20H2-64bit-memdump.mem
- [F36] **info** generic identified (83.2%, API/string references only) in 20210430-Win10Home-20H2-64bit-memdump.mem
- [F37] **info** 3DES identified (60.0%, API/string references only) in 20210430-Win10Home-20H2-64bit-memdump.mem

## RSA keys
- [F38] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F39] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F40] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F41] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F42] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F43] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F44] **low** RSA-1023 key e=65537 (CAPI blob), strength 62/100 (80.0-bit security, disallowed (legacy use only)): modulus size
- [F45] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F46] **low** RSA-2048 key e=3 (CNG blob), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F47] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F48] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F49] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F50] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F51] **low** RSA-1536 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F52] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F53] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F54] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F55] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F56] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F57] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F58] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F59] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F60] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F61] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F62] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F63] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F64] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F65] **low** RSA-4096 key e=62353 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F66] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F67] **low** RSA-2048 key e=43147 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F68] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F69] **low** RSA-2048 key e=50557 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F70] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F71] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F72] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F73] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F74] **info** 506 RSA keys with no weaknesses and 18 corrupt key-like structures in 20210430-Win10Home-20H2-64bit-memdump.mem

## Encrypted / packed regions
- [F75] **info** 200 high-entropy regions (1744896 bytes) in 20210430-Win10Home-20H2-64bit-memdump.mem

## Credentials
- [F76] **medium** JWT eyJhbG...8Sus: symmetric HS256: security rests on secret strength; offline guessing possible; token expired
- [F77] **medium** AWS access key id AKIAIW...H53A
- [F78] **medium** Bearer token 585d36...ca1d

## Processes and memory
- [F1] **info** processes: 134 rows
- [F2] **info** cmdlines: 134 rows
- [F3] **info** network: 103 rows
- [F4] **info** injected: 17 rows
- [F5] **info** usb: 32 rows
- [F6] **low** PID 1156 MsMpEng.exe: 7 RWX/injected region(s): 7 x known JIT process, RWX private memory is expected
- [F7] **high** PID 5104 SearchApp.exe: 2 RWX/injected region(s): 2 x executable private memory with code unique to this process
- [F8] **high** PID 6716 smartscreen.ex: 2 RWX/injected region(s): 2 x executable private memory with code unique to this process
- [F9] **low** PID 6988 OneDrive.exe: 1 RWX/injected region(s): 1 x region starts with zero bytes, no code at the region base
- [F10] **high** PID 5096 powershell.exe: 5 RWX/injected region(s): 5 x executable private memory with code unique to this process

## Static analysis
- [F11] **info** pid.1156.vad.0x244e0960000-0x244e0a5ffff.dmp: entropy 4.938, crypto imports [], yara []
- [F12] **info** pid.1156.vad.0x244e0a70000-0x244e0c6ffff.dmp: entropy 5.036, crypto imports [], yara []
- [F13] **info** pid.1156.vad.0x244e2eb0000-0x244e2fbcfff.dmp: entropy 4.559, crypto imports [], yara []
- [F14] **info** pid.1156.vad.0x244e3b00000-0x244e3c0cfff.dmp: entropy 4.342, crypto imports [], yara []
- [F15] **info** pid.1156.vad.0x244e3f60000-0x244e406cfff.dmp: entropy 3.058, crypto imports [], yara []
- [F16] **info** pid.1156.vad.0x244ea260000-0x244ea36cfff.dmp: entropy 2.827, crypto imports [], yara []
- [F17] **info** pid.1156.vad.0x244ee170000-0x244ee27cfff.dmp: entropy 0.01, crypto imports [], yara []
- [F18] **info** pid.5096.vad.0x211f14d0000-0x211f14e9fff.dmp: entropy 0.058, crypto imports [], yara []
- [F19] **info** pid.5096.vad.0x211f1640000-0x211f164ffff.dmp: entropy 0.059, crypto imports [], yara []
- [F20] **info** pid.5096.vad.0x211f17c0000-0x211f17cffff.dmp: entropy 1.426, crypto imports [], yara []
- [F21] **info** pid.5096.vad.0x7df4c4d90000-0x7df4c4d9ffff.dmp: entropy 0.037, crypto imports [], yara []
- [F22] **info** pid.5096.vad.0x7df4c4da0000-0x7df4c4e3ffff.dmp: entropy 0.003, crypto imports [], yara []
- [F23] **info** pid.5104.vad.0x1e223a20000-0x1e223a3ffff.dmp: entropy 1.322, crypto imports [], yara []
- [F24] **info** pid.5104.vad.0x1e224f60000-0x1e224fc3fff.dmp: entropy 0.288, crypto imports [], yara []
- [F25] **info** pid.6716.vad.0x1dff1080000-0x1dff109ffff.dmp: entropy 0.257, crypto imports [], yara []
- [F26] **info** pid.6716.vad.0x1dff1480000-0x1dff14e3fff.dmp: entropy 0.081, crypto imports [], yara []
- [F27] **info** pid.6988.vad.0x7a60000-0x7a6ffff.dmp: entropy 0.341, crypto imports [], yara []

## MITRE ATT&CK view

| Tactic | Technique | Findings |
|---|---|---|
| Defense Evasion | T1055 Process Injection | [F7], [F8], [F10] |
| Execution | T1059.001 Command and Scripting Interpreter: PowerShell | [F10] |
| Credential Access | T1528 Steal Application Access Token | [F76], [F78] |
| Credential Access | T1552 Unsecured Credentials | [F76], [F77], [F78] |
