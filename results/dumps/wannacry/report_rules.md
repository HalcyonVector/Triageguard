# TriageGuard report (rule-based)

**Risk score:** 95/100 (critical, CVSS v3.1 bands)
- Compromise: 91/100 (critical), evidence of attacker activity
- Crypto exposure: 95/100 (critical), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 0/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| exposure | rsa/rsa_key | 59 | [F71] | 0.95 |
| compromise | memory/suspicious_process | 7 | [F7] | 0.80 |
| compromise | memory/tor_client | 1 | [F89] | 0.55 |

## Cipher identification
- [F19] **info** AES identified (100.0%, implementation constants) in wannacry.elf
- [F20] **info** ECC P-256 identified (99.7%, implementation constants) in wannacry.elf
- [F21] **info** RSA identified (99.4%, implementation constants) in wannacry.elf
- [F22] **info** AES-GCM identified (98.8%, implementation constants) in wannacry.elf
- [F23] **info** ECC secp256k1 identified (92.8%, implementation constants) in wannacry.elf
- [F24] **info** generic identified (83.2%, API/string references only) in wannacry.elf
- [F25] **info** Curve25519 identified (64.0%, API/string references only) in wannacry.elf
- [F26] **info** DES identified (60.0%, implementation constants) in wannacry.elf
- [F27] **info** 3DES identified (60.0%, API/string references only) in wannacry.elf
- [F28] **info** ChaCha20/Salsa20 identified (40.0%, implementation constants) in wannacry.elf

## RSA keys
- [F29] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F30] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F31] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F32] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F33] **low** RSA-1024 key e=65537 (CAPI blob), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F34] **low** RSA-2048 key e=3 (CNG blob), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F35] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F36] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F37] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F38] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F39] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F40] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F41] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F42] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F43] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F44] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F45] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F46] **low** RSA-1536 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F47] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F48] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F49] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F50] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F51] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F52] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F53] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F54] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F55] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F56] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F57] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F58] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F59] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F60] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F61] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F62] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F63] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F64] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F65] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F66] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F67] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F68] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F69] **low** RSA-1024 key e=65537 (DER SPKI), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F70] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F71] **critical** RSA-512 key e=65537 (PEM private), strength 0/100 (0-bit security, broken): modulus size
- [F72] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F73] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F74] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F75] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F76] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F77] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F78] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F79] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F80] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F81] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F82] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F83] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F84] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F85] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F86] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F87] **low** RSA-1024 key e=65537 (PEM public), strength 62/100 (80-bit security, disallowed (legacy use only)): modulus size
- [F88] **info** 169 RSA keys with no weaknesses and 25 corrupt key-like structures in wannacry.elf
- [F91] **info** RSA-2048 private key of @WanaDecryptor (PID 816) recovered from a CryptoAPI private key blob still in its memory at 0xb68a8: data encrypted under this key can be decrypted
- [F92] **info** RSA-2048 private key of @WanaDecryptor (PID 1252) recovered from a CryptoAPI private key blob still in its memory at 0xd48a8: data encrypted under this key can be decrypted
- [F93] **info** RSA-2048 private key of ed01ebfbc9eb5b (PID 3812) recovered from a prime left in its memory at 0xc0890: data encrypted under this key can be decrypted
- [F94] **info** RSA-2048 private key of ed01ebfbc9eb5b (PID 3812) recovered from a prime left in its memory at 0x13955e4: data encrypted under this key can be decrypted

## Encrypted / packed regions
- [F90] **info** 200 high-entropy regions (880640 bytes) in wannacry.elf

## Processes and memory
- [F1] **info** processes: 57 rows
- [F2] **info** cmdlines: 57 rows
- [F3] **info** network: 102 rows
- [F4] **info** injected: 6 rows
- [F5] **info** usb: 14 rows
- [F6] **low** PID 832 explorer.exe: 1 RWX/injected region(s): 1 x region starts with zero bytes, no code at the region base
- [F7] **high** PID 1760 EMET_Agent.exe: 1 RWX/injected region(s): 1 x executable private memory with code unique to this process
- [F8] **high** PID 2392 svchost.exe: 3 RWX/injected region(s): 2 x region starts with zero bytes, no code at the region base; 1 x executable private memory with code unique to this process
- [F9] **high** PID 2288 SearchFilterHo: 1 RWX/injected region(s): 1 x executable private memory with code unique to this process
- [F10] **low** PID 3812 ed01ebfbc9eb5b: runs from a user-writable folder: "C:\Users\IEUser\Desktop\ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.bin\ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.bin (1).exe" 
- [F11] **medium** PID 816 @WanaDecryptor: command line mentions 'Decrypt': @WanaDecryptor@.exe co
- [F12] **medium** PID 1252 @WanaDecryptor: command line mentions 'Decrypt': @WanaDecryptor@.exe
- [F89] **medium** Tor directory data in wannacry.elf: 6055 relay onion keys, so a Tor client ran on this host (command and control over Tor)

## Static analysis
- [F13] **info** pid.1760.vad.0x3ef0000-0x3f2ffff.dmp: entropy 0.101, crypto imports [], yara []
- [F14] **info** pid.2288.vad.0x5b0000-0x5effff.dmp: entropy 0.012, crypto imports [], yara []
- [F15] **info** pid.2392.vad.0x1260000-0x133ffff.dmp: entropy 0.115, crypto imports [], yara []
- [F16] **info** pid.2392.vad.0x1ac0000-0x1b3ffff.dmp: entropy 3.438, crypto imports [], yara []
- [F17] **info** pid.2392.vad.0x1b40000-0x1c3ffff.dmp: entropy 3.05, crypto imports [], yara []
- [F18] **info** pid.832.vad.0x2de0000-0x2de0fff.dmp: entropy 2.423, crypto imports [], yara []

## MITRE ATT&CK view

| Tactic | Technique | Findings |
|---|---|---|
| Defense Evasion | T1055 Process Injection | [F7], [F8], [F9] |
| Command and Control | T1090.003 Proxy: Multi-hop Proxy | [F89] |
