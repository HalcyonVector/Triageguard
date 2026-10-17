# TriageGuard report (rule-based)

**Risk score:** 86/100 (high, CVSS v3.1 bands)
- Compromise: 80/100 (high), evidence of attacker activity
- Crypto exposure: 64/100 (medium), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 0/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| compromise | memory/suspicious_process | 6 | [F11] | 0.80 |
| exposure | credentials/JWT | 1 | [F72] | 0.55 |
| exposure | rsa/rsa_key | 36 | [F34] | 0.20 |

## Cipher identification
- [F24] **info** AES identified (100.0%, implementation constants) in 192-Reveal.dmp
- [F25] **info** ECC P-256 identified (99.0%, implementation constants) in 192-Reveal.dmp
- [F26] **info** RSA identified (98.7%, implementation constants) in 192-Reveal.dmp
- [F27] **info** AES-GCM identified (98.2%, implementation constants) in 192-Reveal.dmp
- [F28] **info** ECC secp256k1 identified (92.8%, implementation constants) in 192-Reveal.dmp
- [F29] **info** generic identified (83.2%, API/string references only) in 192-Reveal.dmp
- [F30] **info** ChaCha20/Salsa20 identified (82.0%, implementation constants) in 192-Reveal.dmp
- [F31] **info** Curve25519 identified (78.4%, API/string references only) in 192-Reveal.dmp
- [F32] **info** DES identified (72.0%, implementation constants) in 192-Reveal.dmp
- [F33] **info** 3DES identified (72.0%, API/string references only) in 192-Reveal.dmp

## RSA keys
- [F34] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F35] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F36] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F37] **info** RSA-512 key e=65537 (CAPI blob), strength 0/100 (0-bit security, broken): modulus size
- [F38] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F39] **low** RSA-2048 key e=3 (CNG blob), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F40] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F41] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F42] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F43] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F44] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F45] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F46] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F47] **low** RSA-1536 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F48] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F49] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F50] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F51] **low** RSA-2048 key e=43147 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F52] **low** RSA-4096 key e=62353 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F53] **low** RSA-1024 key e=3 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size; small exponent
- [F54] **info** RSA-512 key e=65537 (DER SPKI), strength 0/100 (0-bit security, broken): modulus size
- [F55] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F56] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F57] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F58] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F59] **low** RSA-2048 key e=65537 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus
- [F60] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F61] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F62] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F63] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F64] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F65] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F66] **low** RSA-2048 key e=131071 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus
- [F67] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F68] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F69] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F70] **info** 484 RSA keys with no weaknesses and 7 corrupt key-like structures in 192-Reveal.dmp

## Encrypted / packed regions
- [F71] **info** 200 high-entropy regions (868352 bytes) in 192-Reveal.dmp

## Credentials
- [F72] **medium** JWT eyJ0eX...8Es4: symmetric HS256: security rests on secret strength; offline guessing possible; no expiry (exp) claim

## Processes and memory
- [F1] **info** processes: 109 rows
- [F2] **info** cmdlines: 109 rows
- [F3] **info** network: 79 rows
- [F4] **info** injected: 12 rows
- [F5] **info** usb: 31 rows
- [F6] **low** PID 7848 RuntimeBroker.: 1 RWX/injected region(s): 1 x region starts with zero bytes, no code at the region base
- [F7] **low** PID 4492 thunderbird.ex: 2 RWX/injected region(s): 2 x known JIT process, RWX private memory is expected
- [F8] **low** PID 3644 thunderbird.ex: 2 RWX/injected region(s): 2 x known JIT process, RWX private memory is expected
- [F9] **low** PID 3004 thunderbird.ex: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F10] **low** PID 2820 smartscreen.ex: 1 RWX/injected region(s): 1 x executable private memory with code unique to this process
- [F11] **high** PID 3692 powershell.exe: 5 RWX/injected region(s): 5 x executable private memory with code unique to this process

## Static analysis
- [F12] **info** pid.2820.vad.0x153f35a0000-0x153f35bffff.dmp: entropy 0.257, crypto imports [], yara []
- [F13] **info** pid.3004.vad.0x1a785f40000-0x1a785f4ffff.dmp: entropy 3.228, crypto imports [], yara []
- [F14] **info** pid.3644.vad.0x2b991750000-0x2b99175ffff.dmp: entropy 3.598, crypto imports [], yara []
- [F15] **info** pid.3644.vad.0x2b9917e0000-0x2b9917effff.dmp: entropy 3.102, crypto imports [], yara []
- [F16] **info** pid.3692.vad.0x1cb6aa50000-0x1cb6aa5ffff.dmp: entropy 0.059, crypto imports [], yara []
- [F17] **info** pid.3692.vad.0x1cb6c3e0000-0x1cb6c3e6fff.dmp: entropy 0.186, crypto imports [], yara []
- [F18] **info** pid.3692.vad.0x1cb6cac0000-0x1cb6cacffff.dmp: entropy 1.466, crypto imports [], yara []
- [F19] **info** pid.3692.vad.0x7df44e2c0000-0x7df44e2cffff.dmp: entropy 0.036, crypto imports [], yara []
- [F20] **info** pid.3692.vad.0x7df44e2d0000-0x7df44e36ffff.dmp: entropy 0.003, crypto imports [], yara []
- [F21] **info** pid.4492.vad.0x1bfe20e0000-0x1bfe20effff.dmp: entropy 3.599, crypto imports [], yara []
- [F22] **info** pid.4492.vad.0x1bfe2300000-0x1bfe230ffff.dmp: entropy 3.103, crypto imports [], yara []
- [F23] **info** pid.7848.vad.0x230013f0000-0x230013fffff.dmp: entropy 1.983, crypto imports [], yara []

## MITRE ATT&CK view

| Tactic | Technique | Findings |
|---|---|---|
| Defense Evasion | T1055 Process Injection | [F11] |
| Execution | T1059.001 Command and Scripting Interpreter: PowerShell | [F11] |
| Credential Access | T1528 Steal Application Access Token | [F72] |
| Credential Access | T1552 Unsecured Credentials | [F72] |
