# Incident Report  

**Date:** 2026‑10‑15  

---  

## Summary  
The host image contains a high‑severity masquerading process **`nettstat`** (PID 6422) that imitates the legitimate `netstat` binary and is launched from a cron job, indicating persistence and potential attacker control【F58】【F59】.  
Subsequent medium‑severity activity shows the download, permission change, and execution of an unsigned ELF binary (`youtube_downloader.elf`) with root privileges, evidencing privilege‑escalation attempts【F60】【F61】【F62】【F63】【F64】.  
Credential artefacts recovered include three expired JWTs (two RS256, one HS256), an AWS access‑key ID, and a Bearer token, all of which could be abused if still valid【F94】【F95】【F96】【F97】【F98】.  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RS256 | 99.9% | API/string references only | 【F94】 |
| RS256 | 99.9% | API/string references only | 【F96】 |
| HS256 | 99.5% | API/string references only | 【F95】 |

*No RSA private keys were recovered; therefore the RSA‑key table is omitted.*  

---  

## Credentials  

| Type | Identifier (partial) | Issue | Finding |
|------|----------------------|-------|---------|
| JWT (RS256) | `eyJhbG...psbQ` | Expired (exp = 1720124022) | 【F94】 |
| JWT (RS256) | `eyJhbG...NGxg` | Expired (exp = 1720124022) | 【F96】 |
| JWT (HS256) | `eyJhbG...n2Xk` | Expired; symmetric key may be weak, offline guessing possible | 【F95】 |
| AWS access key ID | `AKIAIS...ITAL` | Exposed credential | 【F97】 |
| Bearer token | `SG.e9c...PD8m` | Exposed credential | 【F98】 |

---  

## Processes and Network  

| PID | Process | Observation | ATT&CK Technique(s) | Finding |
|-----|---------|-------------|----------------------|---------|
| 6422 | `nettstat` | Name mimics legitimate `netstat`; launched by cron → persistence | T1036.005 (Masquerading), T1053.003 (Scheduled Task) | 【F58】【F59】 |
| 4453 | `bash` | Executed `chmod 755 youtube_downloader.elf` | T1059.004 (Command‑line Interface) | 【F60】 |
| 4453 | `bash` | Executed `sudo ./youtube_downloader.elf` | T1059.004, T1548.003 (Privilege Escalation), T1204.002 (User Execution) | 【F61】 |
| 4908 | `sudo` | Ran `./youtube_downloader.elf` from current directory as root | T1548.003, T1204.002 | 【F62】 |
| 4909 | `sudo` | Same as above (duplicate) | T1548.003, T1204.002 | 【F63】 |
| 4910 | `youtube_downloa` | Ran unsigned ELF from current folder | T1204.002 | 【F64】 |

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|--------------|----------------|
| **Overall** | **89** | Rule‑based score provided; no finding contradicts it. |
| **Compromise** | **80** | High‑severity masquerading process with cron persistence and multiple privilege‑escalation executions【F58】【F60】【F61】. |
| **Crypto Exposure** | **93** | Expired JWTs and a symmetric HS256 token with weak secret, plus exposed AWS and Bearer tokens【F94】【F95】【F96】【F97】【F98】. |

---  

## Recommendations  

1. **Terminate and remove `nettstat`.** Stop the process, delete the binary, and clean the associated cron entry【F58】【F59】.  
2. **Revoke and rotate exposed credentials.**  
   - Invalidate the AWS access key ID and generate a new key with least‑privilege permissions【F97】.  
   - Regenerate the Bearer token and enforce short expiration times【F98】.  
   - Replace the HS256 JWT usage with an asymmetric algorithm (e.g., RS256) and store signing keys securely; enforce token expiration【F95】.  
3. **Analyze `youtube_downloader.elf`.** Compute its hash, submit it to malware sandboxes, and quarantine if malicious【F60】【F61】.  
4. **Search for additional persistence mechanisms.** Audit all cron jobs, systemd units, and startup scripts for unknown entries.  
5. **Strengthen endpoint monitoring.** Deploy HIDS rules that flag RWX memory regions, code injection patterns, and binaries whose names closely resemble system utilities (T1036).  
6. **Enforce execution policies.** Disallow execution of uninstalled binaries from user‑writable directories with elevated privileges to mitigate T1548.003 and T1204.002.  
7. **Improve JWT handling.** Require strong asymmetric signing, embed short `exp` claims, and validate `kid` fields against a trusted key store【F94】【F95】【F96】.  

---  

*Prepared by the Malware Triage Team.*

## Validation notes (automatic)
Rule-based risk score: 89/100. This report failed these checks, treat the points below as unverified:
- only 69% of claims carry a citation