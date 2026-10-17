# TriageGuard report (rule-based)

**Risk score:** 74/100 (high, CVSS v3.1 bands)
- Compromise: 55/100 (medium), evidence of attacker activity
- Crypto exposure: 84/100 (high), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 0/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| compromise | memory/suspicious_process | 4 | [F8] | 0.55 |
| exposure | credentials/JWT | 4 | [F76] | 0.55 |
| exposure | network/pcap_summary | 1 | [F80] | 0.55 |
| exposure | rsa/rsa_key | 38 | [F36] | 0.20 |

## Cipher identification
- [F26] **info** AES identified (100.0%, implementation constants) in memory.dmp
- [F27] **info** AES-GCM identified (99.3%, implementation constants) in memory.dmp
- [F28] **info** RSA identified (99.1%, implementation constants) in memory.dmp
- [F29] **info** ECC P-256 identified (99.0%, implementation constants) in memory.dmp
- [F30] **info** ECC secp256k1 identified (92.8%, implementation constants) in memory.dmp
- [F31] **info** Curve25519 identified (91.4%, implementation constants) in memory.dmp
- [F32] **info** ChaCha20/Salsa20 identified (89.2%, implementation constants) in memory.dmp
- [F33] **info** generic identified (83.2%, API/string references only) in memory.dmp
- [F34] **info** DES identified (72.0%, implementation constants) in memory.dmp
- [F35] **info** 3DES identified (72.0%, API/string references only) in memory.dmp

## RSA keys
- [F36] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F37] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F38] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F39] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F40] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F41] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F42] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F43] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F44] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F45] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F46] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F47] **low** RSA-2048 key e=65537 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus
- [F48] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F49] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F50] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F51] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F52] **low** RSA-4096 key e=40409 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F53] **low** RSA-2048 key e=50557 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F54] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F55] **low** RSA-2048 key e=65671 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus
- [F56] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F57] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F58] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F59] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F60] **low** RSA-2048 key e=43147 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F61] **low** RSA-4096 key e=62353 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F62] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F63] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F64] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F65] **info** RSA-512 key e=65537 (DER SPKI), strength 0/100 (0-bit security, broken): modulus size
- [F66] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F67] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F68] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F69] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F70] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F71] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F72] **low** RSA-1536 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F73] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F74] **info** 593 RSA keys with no weaknesses and 5 corrupt key-like structures in memory.dmp

## Encrypted / packed regions
- [F75] **info** 200 high-entropy regions (847872 bytes) in memory.dmp

## Credentials
- [F76] **medium** JWT eyJhbG...2Yeg: token expired
- [F77] **medium** JWT eyJhbG...EMRX: token expired
- [F78] **medium** JWT eyJhbG...n2Lx: token expired
- [F79] **medium** JWT eyJhbG...HQ0L: token expired

## Processes and memory
- [F1] **info** processes: 160 rows
- [F2] **info** cmdlines: 160 rows
- [F3] **info** network: 52 rows
- [F4] **info** injected: 16 rows
- [F5] **info** usb: 50 rows
- [F6] **low** PID 3088 MsMpEng.exe: 15 RWX/injected region(s): 15 x known JIT process, RWX private memory is expected
- [F7] **low** PID 1300 OneDrive.exe: 1 RWX/injected region(s): 1 x region starts with zero bytes, no code at the region base
- [F8] **medium** PID 8860 Notepad.exe: command line mentions 'encrypt': "C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2412.16.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe" "C:\Users\Robert Paulson\Desktop\encryption_log.txt"
- [F9] **low** PID 2164 DumpIt.exe: runs from a user-writable folder: "C:\Users\Robert Paulson\Desktop\DumpIt.exe" 

## Static analysis
- [F10] **info** pid.1300.vad.0x2786eb20000-0x2786eb2ffff.dmp: entropy 0.403, crypto imports [], yara []
- [F11] **info** pid.3088.vad.0x231985c0000-0x231986ccfff.dmp: entropy 1.715, crypto imports [], yara []
- [F12] **info** pid.3088.vad.0x231986d0000-0x231987dcfff.dmp: entropy 0.333, crypto imports [], yara []
- [F13] **info** pid.3088.vad.0x231987e0000-0x231988ecfff.dmp: entropy 4.043, crypto imports [], yara []
- [F14] **info** pid.3088.vad.0x23198db0000-0x23198ebcfff.dmp: entropy 4.264, crypto imports [], yara []
- [F15] **info** pid.3088.vad.0x2319dea0000-0x2319dea0fff.dmp: entropy 0.13, crypto imports [], yara []
- [F16] **info** pid.3088.vad.0x231a80d0000-0x231a80d0fff.dmp: entropy 0.13, crypto imports [], yara []
- [F17] **info** pid.3088.vad.0x231a80f0000-0x231a80f0fff.dmp: entropy 0.13, crypto imports [], yara []
- [F18] **info** pid.3088.vad.0x231a8120000-0x231a8121fff.dmp: entropy 0.071, crypto imports [], yara []
- [F19] **info** pid.3088.vad.0x231a81b0000-0x231a81b2fff.dmp: entropy 0.049, crypto imports [], yara []
- [F20] **info** pid.3088.vad.0x231a81d0000-0x231a81d0fff.dmp: entropy 0.13, crypto imports [], yara []
- [F21] **info** pid.3088.vad.0x231a82a0000-0x231a82a1fff.dmp: entropy 0.071, crypto imports [], yara []
- [F22] **info** pid.3088.vad.0x231a8340000-0x231a8340fff.dmp: entropy 0.13, crypto imports [], yara []
- [F23] **info** pid.3088.vad.0x231a8380000-0x231a838afff.dmp: entropy 0.015, crypto imports [], yara []
- [F24] **info** pid.3088.vad.0x231a8900000-0x231a89fffff.dmp: entropy 4.92, crypto imports [], yara []
- [F25] **info** pid.3088.vad.0x231a8a00000-0x231a8bfffff.dmp: entropy 2.523, crypto imports [], yara []

## Network
- [F80] **medium** 1 conversations, TLS SNI [], weak TLS ['TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)', 'SSL 3.0']

## MITRE ATT&CK view

| Tactic | Technique | Findings |
|---|---|---|
| Impact | T1486 Data Encrypted for Impact | [F8] |
| Credential Access | T1528 Steal Application Access Token | [F76], [F77], [F78], [F79] |
| Credential Access | T1552 Unsecured Credentials | [F76], [F77], [F78], [F79] |
| Command and Control | T1573 Encrypted Channel | [F80] |
