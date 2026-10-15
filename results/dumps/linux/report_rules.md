# TriageGuard report (rule-based)

**Risk score:** 89/100 (high, CVSS v3.1 bands)
- Compromise: 80/100 (high), evidence of attacker activity
- Crypto exposure: 93/100 (critical), weak keys, tokens and TLS; counts half in the overall score
**Weakest RSA key strength:** 88/100

Risk is the Dempster-Shafer combination of independent evidence sources, each counted once at its strongest finding (severity as CVSS v3.1 band midpoint). A weak key seen only as a public key counts at most as medium.

| Score | Evidence source | Findings | Strongest | Mass |
|---|---|---|---|---|
| compromise | memory/suspicious_process | 59 | [F58] | 0.80 |
| exposure | credentials/JWT | 3 | [F94] | 0.55 |
| exposure | credentials/AWS access key id | 1 | [F97] | 0.55 |
| exposure | credentials/Bearer token | 1 | [F98] | 0.55 |
| exposure | rsa/rsa_key | 16 | [F74] | 0.20 |

## Cipher identification
- [F65] **info** AES identified (100.0%, implementation constants) in memory.vmem
- [F66] **info** ECC P-256 identified (99.1%, implementation constants) in memory.vmem
- [F67] **info** AES-GCM identified (97.6%, implementation constants) in memory.vmem
- [F68] **info** ChaCha20/Salsa20 identified (93.5%, implementation constants) in memory.vmem
- [F69] **info** ECC secp256k1 identified (92.8%, implementation constants) in memory.vmem
- [F70] **info** Curve25519 identified (91.4%, implementation constants) in memory.vmem
- [F71] **info** RSA identified (91.0%, implementation constants) in memory.vmem
- [F72] **info** DES identified (90.0%, implementation constants) in memory.vmem
- [F73] **info** 3DES identified (50.0%, API/string references only) in memory.vmem

## RSA keys
- [F74] **low** RSA-2048 key e=65537 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus
- [F75] **low** RSA-2048 key e=83975 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus
- [F76] **low** RSA-2048 key e=124389 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus
- [F77] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F78] **low** RSA-2048 key e=65537 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus
- [F79] **low** RSA-2048 key e=79877 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus
- [F80] **low** RSA-2048 key e=131071 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus
- [F81] **low** RSA-2048 key e=43147 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F82] **low** RSA-2048 key e=68655 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus
- [F83] **low** RSA-4096 key e=3 (DER SPKI), strength 100/100 (128-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F84] **low** RSA-2048 key e=3 (DER SPKI), strength 88/100 (112-bit security, non-compliant exponent (FIPS 186-5)): small exponent
- [F85] **low** RSA-2048 key e=113409 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus
- [F86] **low** RSA-2048 key e=96263 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus
- [F87] **low** RSA-2048 key e=81923 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus
- [F88] **low** RSA-2048 key e=77933 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus
- [F89] **low** RSA-2048 key e=84109 (DER SPKI), strength 88/100 (112-bit security, acceptable): shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus; shared modulus
- [F90] **info** 275 RSA keys with no weaknesses and 10 corrupt key-like structures in memory.vmem
- [F92] **info** No RSA prime found in nettstat (PID 6422) for its 0 RSA key(s)
- [F93] **info** No RSA prime found in youtube_downloa (PID 4910) for its 0 RSA key(s)

## Encrypted / packed regions
- [F91] **info** 200 high-entropy regions (15028224 bytes) in memory.vmem

## Credentials
- [F94] **medium** JWT eyJhbG...psbQ: token expired
- [F95] **medium** JWT eyJhbG...n2Xk: symmetric HS256: security rests on secret strength; offline guessing possible; token expired
- [F96] **medium** JWT eyJhbG...NGxg: token expired
- [F97] **medium** AWS access key id AKIAIS...ITAL
- [F98] **medium** Bearer token SG.e9c...PD8m

## Processes and memory
- [F1] **info** processes: 344 rows
- [F2] **info** cmdlines: 344 rows
- [F3] **info** network: skipped (linux.sockstat timed out after 10 minutes)
- [F4] **info** injected: 162 rows
- [F5] **info** bash: 28 rows
- [F6] **low** PID 880 networkd-dispat: 1 RWX/injected region(s): 1 x region starts with zero bytes, no code at the region base
- [F7] **medium** PID 1032 unattended-upgr: 1 RWX/injected region(s): 1 x identical code in 4 processes, likely a system-wide hook
- [F8] **low** PID 1702 gnome-shell: 34 RWX/injected region(s): 34 x known JIT process, RWX private memory is expected
- [F9] **low** PID 1814 gjs: 4 RWX/injected region(s): 4 x known JIT process, RWX private memory is expected
- [F10] **low** PID 2212 gjs: 5 RWX/injected region(s): 5 x known JIT process, RWX private memory is expected
- [F11] **low** PID 2254 gjs: 9 RWX/injected region(s): 9 x known JIT process, RWX private memory is expected
- [F12] **low** PID 3000 firefox: 10 RWX/injected region(s): 10 x known JIT process, RWX private memory is expected
- [F13] **low** PID 3161 Privileged Cont: 5 RWX/injected region(s): 5 x known JIT process, RWX private memory is expected
- [F14] **low** PID 3330 WebExtensions: 6 RWX/injected region(s): 6 x known JIT process, RWX private memory is expected
- [F15] **low** PID 3640 Isolated Web Co: 4 RWX/injected region(s): 4 x known JIT process, RWX private memory is expected
- [F16] **low** PID 3742 Isolated Web Co: 3 RWX/injected region(s): 3 x known JIT process, RWX private memory is expected
- [F17] **low** PID 3981 Isolated Web Co: 5 RWX/injected region(s): 5 x known JIT process, RWX private memory is expected
- [F18] **low** PID 4215 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F19] **low** PID 4218 Isolated Web Co: 6 RWX/injected region(s): 6 x known JIT process, RWX private memory is expected
- [F20] **low** PID 4348 gnome-terminal-: 4 RWX/injected region(s): 4 x known JIT process, RWX private memory is expected
- [F21] **low** PID 4599 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F22] **low** PID 4771 Isolated Web Co: 7 RWX/injected region(s): 7 x known JIT process, RWX private memory is expected
- [F23] **low** PID 4806 Isolated Web Co: 3 RWX/injected region(s): 3 x known JIT process, RWX private memory is expected
- [F24] **low** PID 5075 Isolated Web Co: 2 RWX/injected region(s): 2 x known JIT process, RWX private memory is expected
- [F25] **low** PID 5102 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F26] **low** PID 5128 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F27] **low** PID 5132 Isolated Web Co: 3 RWX/injected region(s): 3 x known JIT process, RWX private memory is expected
- [F28] **low** PID 5166 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F29] **low** PID 5191 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F30] **low** PID 5221 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F31] **low** PID 5278 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F32] **low** PID 5319 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F33] **low** PID 5321 Isolated Web Co: 2 RWX/injected region(s): 2 x known JIT process, RWX private memory is expected
- [F34] **low** PID 5359 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F35] **low** PID 5378 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F36] **low** PID 5381 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F37] **low** PID 5402 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F38] **low** PID 5432 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F39] **low** PID 5452 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F40] **low** PID 5472 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F41] **low** PID 5477 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F42] **low** PID 5491 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F43] **low** PID 5520 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F44] **low** PID 5559 Isolated Web Co: 2 RWX/injected region(s): 2 x known JIT process, RWX private memory is expected
- [F45] **low** PID 5570 Isolated Web Co: 2 RWX/injected region(s): 2 x known JIT process, RWX private memory is expected
- [F46] **low** PID 5604 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F47] **low** PID 6519 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F48] **low** PID 6572 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F49] **low** PID 6661 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F50] **low** PID 6683 Isolated Web Co: 3 RWX/injected region(s): 3 x known JIT process, RWX private memory is expected
- [F51] **low** PID 6962 Isolated Web Co: 2 RWX/injected region(s): 2 x known JIT process, RWX private memory is expected
- [F52] **low** PID 7075 Isolated Web Co: 9 RWX/injected region(s): 9 x known JIT process, RWX private memory is expected
- [F53] **low** PID 7135 Isolated Web Co: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F54] **low** PID 7421 Isolated Servic: 2 RWX/injected region(s): 2 x known JIT process, RWX private memory is expected
- [F55] **low** PID 7428 Web Content: 2 RWX/injected region(s): 2 x known JIT process, RWX private memory is expected
- [F56] **low** PID 7572 Web Content: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F57] **low** PID 7737 Web Content: 1 RWX/injected region(s): 1 x known JIT process, RWX private memory is expected
- [F58] **high** PID 6422 nettstat: name 'nettstat' imitates the system program 'netstat' (one letter different)
- [F59] **medium** PID 6422 nettstat: started by cron (nettstat <- sh <- cron <- cron): a scheduled job, a common way to keep malware running
- [F60] **medium** PID 4453 bash: bash history: 'chmod 755 youtube_downloader.elf' in chmod 755 youtube_downloader.elf 
- [F61] **medium** PID 4453 bash: bash history: 'sudo ./youtube_downloader.elf' in sudo ./youtube_downloader.elf 
- [F62] **medium** PID 4908 sudo: runs a program from the current folder as root through sudo, not an installed one: sudo ./youtube_downloader.elf
- [F63] **medium** PID 4909 sudo: runs a program from the current folder as root through sudo, not an installed one: sudo ./youtube_downloader.elf
- [F64] **medium** PID 4910 youtube_downloa: runs a program from the current folder, not an installed one: ./youtube_downloader.elf

## MITRE ATT&CK view

| Tactic | Technique | Findings |
|---|---|---|
| Defense Evasion | T1036.005 Masquerading: Match Legitimate Name or Location | [F58] |
| Persistence | T1053.003 Scheduled Task/Job: Cron | [F59] |
| Execution | T1059.004 Command and Scripting Interpreter: Unix Shell | [F60], [F61] |
| Execution | T1204.002 User Execution: Malicious File | [F61], [F62], [F63], [F64] |
| Privilege Escalation | T1548.003 Abuse Elevation Control Mechanism: Sudo | [F61], [F62], [F63] |
| Credential Access | T1528 Steal Application Access Token | [F94], [F95], [F96], [F98] |
| Credential Access | T1552 Unsecured Credentials | [F94], [F95], [F96], [F97], [F98] |
