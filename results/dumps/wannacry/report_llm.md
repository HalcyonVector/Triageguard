## Summary  
The analyzed memory image of the Wannacry sample shows multiple high‑severity artifacts: a **critical RSA‑512 private key** with zero security strength [F71]; two **high‑severity processes** (svchost.exe and SearchFilterHo) that contain RWX‑injected memory regions matching ATT&CK T1055 (Process Injection) [F8] [F9]; and evidence of a **Tor client** (≈6 k onion keys) indicating possible C2 over Tor [F89]. Numerous low‑severity RSA keys (1024‑bit, 1536‑bit, 2048‑bit) with weak parameters are also present [F29]‑[F58]. No credential artifacts were extracted.

## Cryptography  

### Algorithms identified  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA‑512 | 99.9% | implementation constants | [F71] |
| RSA‑1024 | 99.5% | implementation constants | [F29] |
| RSA‑1536 | 99.5% | implementation constants | [F46] |
| RSA‑2048 | 99.5% | implementation constants | [F34] |

### RSA key details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | modulus factorable (broken) | [F71] |
| 1024 bits | 65537 | 62 | < 1024 bits (legacy, disallowed) | [F29] |
| 1536 bits | 65537 | 62 | < 2048 bits (legacy, disallowed) | [F46] |
| 2048 bits | 3 | 88 | non‑compliant exponent (FIPS 186‑5) | [F34] |

## Credentials  
No password hashes, tokens, or other credential artifacts were recovered from the image. [F11] [F12]

## Processes and Network  

| PID | Process | Observation | ATT&CK Technique | Finding |
|-----|---------|-------------|------------------|---------|
| 2392 | svchost.exe | 3 RWX/injected regions (2 zero‑filled, 1 with unique code) | T1055 – Process Injection | [F8] |
| 2288 | SearchFilterHo | 1 RWX/injected region with unique code | T1055 – Process Injection | [F9] |
| 816 | @WanaDecryptor | Command line contains “Decrypt” | – | [F11] |
| 1252 | @WanaDecryptor | Command line contains “Decrypt” | – | [F12] |
| – | Tor client (embedded in wannacry.elf) | 6 055 onion relay keys found – indicates Tor C2 usage | T1090.003 – Proxy: Tor | [F89] |
| 832 | explorer.exe | 1 RWX region (zero‑filled) – low severity | – | [F6] |
| 1760 | EMET_Agent.exe | 1 RWX region with unique code – low severity | – | [F7] |
| 3812 | ed01ebfbc9eb5b | Executable run from a user‑writable desktop folder | – | [F10] |

## Risk Score  

* **Overall Risk – 95** – This matches the rule‑based score; the combination of critical cryptographic weakness, high‑severity process injection, and Tor C2 evidence justifies the high rating [F71] [F8] [F9] [F89] [F29]‑[F58].  
* **Compromise – 91** – High‑severity injected processes (svchost.exe, SearchFilterHo) and the Tor client provide strong evidence of active attacker control [F8] [F9] [F89].  
* **Crypto Exposure – 95** – The broken RSA‑512 key (strength 0) and the large number of weak RSA keys (strength ≤ 88) severely degrade cryptographic security [F71] [F29]‑[F58].

## Recommendations  

* **Terminate and investigate the injected processes** (svchost.exe PID 2392, SearchFilterHo PID 2288) and remove their RWX memory regions to stop ongoing code injection [F8] [F9].  
* **Block outbound Tor traffic** and delete the embedded Tor client to eliminate the covert C2 channel [F89].  
* **Revoke and replace the RSA‑512 private key** with a modern RSA‑2048 (or stronger) key using a standard exponent (65537) [F71].  
* **Rotate all RSA‑1024 and RSA‑1536 keys** to RSA‑2048 or larger keys; ensure the exponent is 65537 to comply with FIPS 186‑5 [F29]‑[F58] [F34].  
* **Enforce a cryptographic policy** that disallows keys smaller than 2048 bits and rejects non‑standard exponents [F34].  
* **Conduct a full system integrity scan** to locate any additional injected code or persistence mechanisms not captured in the current dump [F8] [F9].  
* **Apply least‑privilege execution controls** to prevent executables from being run from user‑writable directories (e.g., the desktop‑based binary) [F10].  
* **Deploy endpoint detection and response (EDR)** solutions that monitor for process‑injection behaviors (ATT&CK T1055) and alert on RWX memory allocations [F8] [F9].