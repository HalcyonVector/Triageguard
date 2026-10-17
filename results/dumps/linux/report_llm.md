# Incident Report  

**Date:** 2026‑10‑17  

---  

## Summary  
Memory analysis identified a malicious binary named **`nettstat`** that imitates the legitimate `netstat` utility and is executed by cron, providing persistence (ATT&CK T1036.005, T1053.003)【F58】【F59】. The same binary injects identical RWX code into four processes, indicating a system‑wide hooking technique (ATT&CK T1055)【F7】. The injected code is used to launch an ELF payload (`youtube_downloader.elf`) with root privileges via `sudo`, a technique associated with privilege escalation and user execution (ATT&CK T1548.003, T1204.002)【F60】【F61】【F62】【F63】【F64】.  

Credential artefacts recovered include three expired JWTs (two RS256, one HS256)【F94】【F95】【F96】, an AWS access‑key ID【F97】, and a Bearer token【F98】. The HS256 token relies on a symmetric secret that may be weak, exposing the system to offline guessing attacks【F95】.  

Based on the high‑severity masquerading process and the presence of system‑wide code injection, the overall risk is assessed as high, matching the supplied baseline score【F58】.  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RS256 | 99.9% | API/string references only | 【F94】 |
| RS256 | 99.9% | API/string references only | 【F96】 |
| HS256 | 99.9% | API/string references only | 【F95】 |

*Confidence reflects the direct observation of the `alg` field in each JWT header*【F94】【F95】【F96】.  

### RSA Key Details  
No RSA private key material was recovered; only `kid` references appear in the JWT headers, so no RSA key table is applicable【F94】【F96】.  

---  

## Credentials  

| Type | Identifier (truncated) | Issue | Finding |
|------|------------------------|-------|---------|
| JWT (RS256) | `eyJhbG…psbQ` | Expired (exp = 1720124022) | 【F94】 |
| JWT (HS256) | `eyJhbG…n2Xk` | Expired; symmetric secret may be weak, offline guessing possible | 【F95】 |
| JWT (RS256) | `eyJhbG…NGxg` | Expired | 【F96】 |
| AWS Access Key ID | `AKIAIS…ITAL` | Exposed credential | 【F97】 |
| Bearer token | `SG.e9c…PD8m` | Exposed credential | 【F98】 |

---  

## Processes and Network  

| PID | Process | Observation | ATT&CK Technique(s) | Finding |
|-----|---------|-------------|----------------------|---------|
| 6422 | `nettstat` | Name mimics `netstat`; launched by cron → persistence | T1036.005, T1053.003 | 【F58】【F59】 |
| 1032 | `unattended-upgr` | Identical RWX code injected into four processes → system‑wide hook | T1055 | 【F7】 |
| 4453 | `bash` | Executed `chmod 755 youtube_downloader.elf` | T1059.004 | 【F60】 |
| 4453 | `bash` | Executed `sudo ./youtube_downloader.elf` | T1059.004, T1548.003, T1204.002 | 【F61】 |
| 4908 | `sudo` | Ran `./youtube_downloader.elf` from current directory as root | T1548.003, T1204.002 | 【F62】 |
| 4909 | `sudo` | Same as above (duplicate instance) | T1548.003, T1204.002 | 【F63】 |
| 4910 | `youtube_downloa` | Executed ELF payload from current folder | T1204.002 | 【F64】 |

Low‑severity RWX regions observed in legitimate JIT processes (e.g., `gnome-shell`, `firefox`) are expected and not indicative of malicious activity【F8】【F9】【F10】【F11】【F12】【F13】【F14】【F15】【F16】【F17】【F18】【F19】【F20】.  

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|---------------|
| **Overall** | 89 | The supplied baseline score is retained because no cited finding contradicts it【F58】. |
| **Compromise** | 80 | High‑severity masquerading (`nettstat`) and system‑wide code injection demonstrate active attacker control【F58】【F7】. |
| **Crypto Exposure** | 93 | Expired JWTs and a weak HS256 token increase exposure; AWS and Bearer tokens further raise risk【F94】【F95】【F96】【F97】【F98】. |

---  

## Recommendations  

- **Terminate and Remove Malicious Binary** – Kill the `nettstat` process and delete its executable; search for similarly named files to prevent reinfection【F58】.  
- **Remove Persistence** – Delete the cron entry that launches `nettstat` and audit all crontabs for unknown jobs【F59】.  
- **Remediate Code Injection** – Investigate the RWX region reported in `unattended-upgr` and restore the original binary from trusted packages【F7】.  
- **Revoke and Rotate Exposed Credentials** – Invalidate the AWS access key ID and generate a new, least‑privilege key【F97】; revoke the Bearer token and issue a new one【F98】; replace expired JWTs with freshly signed tokens and, for HS256, use a high‑entropy secret or migrate to an asymmetric algorithm【F94】【F95】【F96】.  
- **Enforce Strict `sudo` Policies** – Require full path specifications and disallow execution of files from the current directory; enable detailed `sudo` logging and alert on `sudo ./` patterns【F62】【F63】【F64】.  
- **Deploy Detection Rules** – Create EDR signatures for processes whose names differ by a single character from known system binaries (e.g., `nettstat`)【F58】; alert on creation of new RWX memory regions in non‑JIT processes【F7】.  
- **Conduct Full Forensic Review** – Perform a host‑wide forensic analysis to identify any lateral movement or data exfiltration that may have occurred during the compromise window【F58】【F7】.  

---  

*Prepared by the Malware Triage Team.*  
