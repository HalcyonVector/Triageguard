# Incident Report  

## Summary  
A memory image from a Windows workstation shows multiple suspicious injected code regions, notably a **high‑severity** RWX injection in **RuntimeBroker.exe** (PID 7068) that matches ATT&CK technique **T1055 – Process Injection**【F7】. Numerous RSA keys with weak parameters (1024‑bit modulus, small exponents) are present in memory, indicating poor cryptographic hygiene【F33】【F34】【F35】【F36】【F38】【F39】【F40】【F41】【F42】【F43】【F44】【F45】【F46】【F47】【F49】【F50】【F51】【F52】【F53】【F54】【F55】【F56】【F57】【F58】【F59】【F60】【F61】【F62】【F63】. No malicious network connections were directly observed in the captured network table【F3】, but the breadth of low‑severity injected regions across common system binaries suggests a potentially active foothold【F6】【F8】【F9】【F10】【F11】.  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 100.0% | implementation constants | 【F23】 |

### RSA Keys  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F33】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F34】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F35】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F36】 |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | 【F38】 |
| 1536 bits | 65537 | 62 | legacy size (80‑bit security) | 【F39】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F40】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F41】 |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | 【F42】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F43】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F44】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F45】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F46】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F47】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F49】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F50】 |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | 【F51】 |
| 4096 bits | 3 | 100 | non‑compliant small exponent (FIPS 186‑5) | 【F52】 |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | 【F53】 |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | 【F54】 |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | 【F55】 |
| 2048 bits | 43147 | 88 | non‑compliant exponent | 【F56】 |
| 4096 bits | 3 | 100 | non‑compliant small exponent (FIPS 186‑5) | 【F57】 |
| 4096 bits | 3 | 100 | non‑compliant small exponent (FIPS 186‑5) | 【F58】 |
| 2048 bits | 3 | 88 | non‑compliant small exponent (FIPS 186‑5) | 【F59】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F60】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F61】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F62】 |
| 1024 bits | 65537 | 62 | legacy size (80‑bit security) | 【F63】 |

## Credentials  
No credential artifacts (passwords, tokens, hashes) were extracted from the provided findings【F1】【F2】.  

## Processes and Network  

| Category | Detail | Finding |
|----------|--------|---------|
| Suspicious process | **RuntimeBroker.exe** (PID 7068) with RWX injected region – high severity – ATT&CK T1055 | 【F7】 |
| Other injected processes | SearchApp.exe (PID 2128) – low severity injected code | 【F6】 |
| Other injected processes | smartscreen.ex (PID 7484) – low severity injected code | 【F8】 |
| Other injected processes | OneDrive.exe (PID 7780) – low severity injected region (zero‑byte start) | 【F9】 |
| Other injected processes | WWAHost.exe (PID 5912) – low severity injected code | 【F10】 |
| Executable from writable folder | ChromeSetup.exe run from user Downloads folder | 【F11】 |
| Process list count | 127 processes captured | 【F1】 |
| Command‑line list count | 127 command‑line entries captured | 【F2】 |
| Network connections | 86 network rows captured (no obvious malicious endpoints) | 【F3】 |
| USB device activity | 28 USB entries captured | 【F5】 |

## Risk Score  

- **Overall risk score:** **82** (rule‑based).  
- **Compromise (80)** – driven by the high‑severity RuntimeBroker injection (ATT&CK T1055) and the presence of multiple low‑severity injected regions across system binaries【F7】【F6】【F8】【F9】【F10】.  
- **Crypto exposure (20)** – driven by the large number of weak RSA keys (1024‑bit modulus, small exponents) that provide only 80‑bit security or violate FIPS exponent requirements【F33】…【F63】.  

No findings contradict the rule‑based scores, so they are retained.  

## Recommendations  

- **Isolate the host** from the network to prevent lateral movement and data exfiltration【F7】.  
- **Terminate and replace the injected RuntimeBroker.exe instance**; perform a full system scan for additional implants (ATT&CK T1055)【F7】.  
- **Remove or quarantine all identified injected code regions** in the low‑severity processes (SearchApp.exe, smartscreen.ex, WWAHost.exe, OneDrive.exe)【F6】【F8】【F9】【F10】.  
- **Rotate all RSA‑1024 keys** and replace them with RSA‑2048 or stronger keys using a compliant exponent (e.g., 65537)【F33】.  
- **Regenerate RSA‑2048/4096 keys with a standard exponent** (65537) to comply with FIPS 186‑5; avoid exponent 3【F38】【F42】【F56】.  
- **Audit applications that load RSA keys with small exponents** and update them to use approved cryptographic libraries【F38】【F42】【F56】.  
- **Block execution of binaries from user‑writable locations** such as the ChromeSetup.exe observed in the Downloads folder【F11】.  
- **Enable and enforce DEP/NX and ASLR** system‑wide to mitigate future RWX memory injections【F7】.  
- **Review network traffic logs** for any anomalous outbound connections that may have been missed in the snapshot【F3】.  
- **Conduct a full forensic review of USB device activity** to rule out data exfiltration via removable media【F5】.  