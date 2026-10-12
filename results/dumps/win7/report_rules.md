# TriageGuard report (rule-based)

**Risk score:** 60/100 (medium, CVSS v3.1 bands)
- Compromise: 55/100 (medium), evidence of attacker activity
- Crypto exposure: 20/100 (low), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 62/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| compromise | memory/suspicious_process | 6 | [F6] | 0.55 |
| exposure | rsa/rsa_key | 29 | [F28] | 0.20 |

## Cipher identification
- [F19] **info** AES identified (99.9%, implementation constants) in Challenge.vmem
- [F20] **info** ECC P-256 identified (99.7%, implementation constants) in Challenge.vmem
- [F21] **info** RSA identified (97.8%, implementation constants) in Challenge.vmem
- [F22] **info** AES-GCM identified (95.5%, API/string references only) in Challenge.vmem
- [F23] **info** ECC secp256k1 identified (92.8%, implementation constants) in Challenge.vmem
- [F24] **info** generic identified (83.2%, API/string references only) in Challenge.vmem
- [F25] **info** DES identified (60.0%, implementation constants) in Challenge.vmem
- [F26] **info** 3DES identified (60.0%, API/string references only) in Challenge.vmem
- [F27] **info** ChaCha20/Salsa20 identified (40.0%, implementation constants) in Challenge.vmem

## RSA keys
- [F28] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F29] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F30] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F31] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F32] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F33] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F34] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F35] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F36] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F37] **low** RSA-2048 key e=3 (CNG blob), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F38] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F39] **low** RSA-1536 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F40] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F41] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F42] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F43] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F44] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F45] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F46] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F47] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F48] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F49] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F50] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F51] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F52] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F53] **low** RSA-1536 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F54] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F55] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F56] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F57] **info** 80 RSA keys with no weaknesses and 2 corrupt key-like structures in Challenge.vmem

## Encrypted / packed regions
- [F58] **info** 200 high-entropy regions (839680 bytes) in Challenge.vmem

## Processes and memory
- [F1] **info** processes: 42 rows
- [F2] **info** cmdlines: 42 rows
- [F3] **info** network: 65 rows
- [F4] **info** injected: 7 rows
- [F5] **info** usb: 13 rows
- [F6] **medium** PID 776 svchost.exe: 1 RWX/injected region(s): 1 x identical code in 5 processes, likely a system-wide hook
- [F7] **medium** PID 1052 svchost.exe: 1 RWX/injected region(s): 1 x identical code in 5 processes, likely a system-wide hook
- [F8] **medium** PID 1312 explorer.exe: 2 RWX/injected region(s): 1 x identical code in 5 processes, likely a system-wide hook; 1 x region starts with zero bytes, no code at the region base
- [F9] **medium** PID 2316 wmpnetwk.exe: 1 RWX/injected region(s): 1 x identical code in 5 processes, likely a system-wide hook
- [F10] **medium** PID 2956 notepad.exe: 2 RWX/injected region(s): 1 x region starts with zero bytes, no code at the region base; 1 x identical code in 5 processes, likely a system-wide hook
- [F11] **medium** PID 3940 cmd.exe: shell started by vmtoolsd.exe (PID 1756), not by a user session or another shell

## Static analysis
- [F12] **info** pid.1052.vad.0x610000-0x611fff.dmp: entropy 5.009, crypto imports [], yara []
- [F13] **info** pid.1312.vad.0x1e80000-0x1e81fff.dmp: entropy 5.014, crypto imports [], yara []
- [F14] **info** pid.1312.vad.0x3130000-0x3130fff.dmp: entropy 2.575, crypto imports [], yara []
- [F15] **info** pid.2316.vad.0x970000-0x971fff.dmp: entropy 5.009, crypto imports [], yara []
- [F16] **info** pid.2956.vad.0x2a00000-0x2a00fff.dmp: entropy 2.019, crypto imports [], yara []
- [F17] **info** pid.2956.vad.0x2bd0000-0x2bd1fff.dmp: entropy 5.022, crypto imports [], yara []
- [F18] **info** pid.776.vad.0xde0000-0xde1fff.dmp: entropy 5.009, crypto imports [], yara []

## MITRE ATT&CK view

| Tactic | Technique | Findings |
|---|---|---|
| Execution | T1059.003 Command and Scripting Interpreter: Windows Command Shell | [F11] |
