# TriageGuard report (rule-based)

**Risk score:** 85/100
**Weakest RSA key strength:** 0/100

## Cipher identification
- [F16] **info** ECC P-256 identified (99.3%, implementation constants) in DESKTOP-SDN1RPT.mem
- [F17] **info** AES identified (98.8%, implementation constants) in DESKTOP-SDN1RPT.mem
- [F18] **info** AES-GCM identified (95.5%, API/string references only) in DESKTOP-SDN1RPT.mem
- [F19] **info** RSA identified (94.0%, implementation constants) in DESKTOP-SDN1RPT.mem
- [F20] **info** ECC secp256k1 identified (92.8%, implementation constants) in DESKTOP-SDN1RPT.mem
- [F21] **info** generic identified (83.2%, API/string references only) in DESKTOP-SDN1RPT.mem
- [F22] **info** 3DES identified (75.0%, API/string references only) in DESKTOP-SDN1RPT.mem
- [F23] **info** DES identified (60.0%, implementation constants) in DESKTOP-SDN1RPT.mem
- [F24] **info** Curve25519 identified (40.0%, API/string references only) in DESKTOP-SDN1RPT.mem
- [F44] **info** AES identified (30.0%, API/string references only) in pid.3316.vad.0x10c6bfc0000-0x10c6bff8fff.dmp

## RSA keys
- [F25] **low** RSA-1024 key e=65537 (CAPI blob), strength 35/100: modulus size
- [F26] **low** RSA-1024 key e=65537 (CAPI blob), strength 35/100: modulus size
- [F27] **low** RSA-1024 key e=65537 (CAPI blob), strength 35/100: modulus size
- [F28] **low** RSA-2048 key e=3 (CNG blob), strength 40/100: small exponent
- [F29] **low** RSA-1024 key e=65537 (DER SPKI), strength 35/100: modulus size
- [F30] **low** RSA-1024 key e=65537 (DER SPKI), strength 35/100: modulus size
- [F31] **low** RSA-1024 key e=65537 (DER SPKI), strength 35/100: modulus size
- [F32] **low** RSA-1024 key e=65537 (DER SPKI), strength 35/100: modulus size
- [F33] **low** RSA-1536 key e=65537 (DER SPKI), strength 35/100: modulus size
- [F34] **low** RSA-1024 key e=65537 (DER SPKI), strength 35/100: modulus size
- [F35] **low** RSA-1024 key e=65537 (DER SPKI), strength 35/100: modulus size
- [F36] **low** RSA-1024 key e=65537 (DER SPKI), strength 35/100: modulus size
- [F37] **critical** RSA-512 key e=65537 (DER SPKI), strength 0/100: modulus size
- [F38] **low** RSA-1024 key e=65537 (DER SPKI), strength 35/100: modulus size
- [F39] **low** RSA-1024 key e=65537 (DER SPKI), strength 35/100: modulus size
- [F40] **low** RSA-2048 key e=3 (DER SPKI), strength 40/100: small exponent
- [F41] **info** 151 RSA keys with no weaknesses and 6 corrupt key-like structures in DESKTOP-SDN1RPT.mem

## Encrypted / packed regions
- [F42] **info** 200 high-entropy regions (864256 bytes) in DESKTOP-SDN1RPT.mem
- [F43] **info** 1 high-entropy regions (4096 bytes) in pid.2404.vad.0x25453170000-0x2545326ffff.dmp
- [F45] **info** 2 high-entropy regions (8192 bytes) in pid.3316.vad.0x10c6bfc0000-0x10c6bff8fff.dmp
- [F46] **info** 1 high-entropy regions (4096 bytes) in pid.3316.vad.0x7df4f5a80000-0x7df4f5a8ffff.dmp
- [F47] **info** 6 high-entropy regions (24576 bytes) in pid.3316.vad.0x7df4f5a90000-0x7df4f5b2ffff.dmp

## Processes and memory
- [F1] **info** processes: 95 rows
- [F2] **info** cmdlines: 95 rows
- [F3] **info** network: 115 rows
- [F4] **info** injected: 7 rows
- [F5] **info** usb: 32 rows
- [F6] **critical** PID 2188 spoolsv.exe: 1 RWX/injected region(s): 1 x contains a PE header (MZ), likely injected DLL/EXE
- [F7] **low** PID 2404 MsMpEng.exe: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F8] **critical** PID 3316 powershell.exe: 5 RWX/injected region(s): 2 x executable private memory with code unique to this process; 2 x region starts with zero bytes, no code at the region base; 1 x contains a PE header (MZ), likely injected DLL/EXE

## Static analysis
- [F9] **info** pid.2188.vad.0x1840000-0x1863fff.dmp: entropy 5.368, crypto imports [], yara []
- [F10] **info** pid.2404.vad.0x25453170000-0x2545326ffff.dmp: entropy 3.435, crypto imports [], yara []
- [F11] **info** pid.3316.vad.0x10c6bfc0000-0x10c6bff8fff.dmp: entropy 2.734, crypto imports [], yara []
- [F12] **info** pid.3316.vad.0x10c6c000000-0x10c6c06afff.dmp: entropy 0.185, crypto imports [], yara []
- [F13] **info** pid.3316.vad.0x10c6c070000-0x10c6c093fff.dmp: entropy 5.428, crypto imports [], yara []
- [F14] **info** pid.3316.vad.0x7df4f5a80000-0x7df4f5a8ffff.dmp: entropy 5.45, crypto imports [], yara []
- [F15] **info** pid.3316.vad.0x7df4f5a90000-0x7df4f5b2ffff.dmp: entropy 5.272, crypto imports [], yara []

## Network
- [F48] **info** 50 conversations, TLS SNI ['64.media.tumblr.com', '66.media.tumblr.com', '78.media.tumblr.com', 'a.thumbs.redditmedia.com', 'a125375509.cdn.optimizely.com'], weak TLS []
