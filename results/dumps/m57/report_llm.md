# Incident Report  

**Date:** 2026‑10‑15  

---  

## Summary  
Memory forensics revealed high‑severity code injection in three privileged Windows processes (`csrss.exe`, `winlogon.exe`, `soffice.bin`) and a **critical** RSA‑512 key that provides essentially no security. In addition, a large set of legacy RSA‑1024 keys and several RSA‑2048 keys with a non‑standard exponent (e = 3) were found, exposing the host to trivial cryptographic attacks. [F110][F6][F7][F9]  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA | 100% | implementation constants | [F110] |
| RSA | 100% | implementation constants | [F30] |
| RSA | 100% | implementation constants | [F31] |
| RSA | 100% | implementation constants | [F32] |
| RSA | 100% | implementation constants | [F33] |
| RSA | 100% | implementation constants | [F34] |
| RSA | 100% | implementation constants | [F35] |
| RSA | 100% | implementation constants | [F36] |
| RSA | 100% | implementation constants | [F37] |
| RSA | 100% | implementation constants | [F38] |
| RSA | 100% | implementation constants | [F39] |
| RSA | 100% | implementation constants | [F40] |
| RSA | 100% | implementation constants | [F41] |
| RSA | 100% | implementation constants | [F42] |
| RSA | 100% | implementation constants | [F43] |
| RSA | 100% | implementation constants | [F44] |
| RSA | 100% | implementation constants | [F45] |
| RSA | 100% | implementation constants | [F46] |
| RSA | 100% | implementation constants | [F47] |
| RSA | 100% | implementation constants | [F48] |
| RSA | 100% | implementation constants | [F49] |
| RSA | 100% | implementation constants | [F50] |
| RSA | 100% | implementation constants | [F51] |
| RSA | 100% | implementation constants | [F52] |
| RSA | 100% | implementation constants | [F53] |
| RSA | 100% | implementation constants | [F54] |
| RSA | 100% | implementation constants | [F55] |
| RSA | 100% | implementation constants | [F56] |
| RSA | 100% | implementation constants | [F57] |
| RSA | 100% | implementation constants | [F58] |
| RSA | 100% | implementation constants | [F59] |
| RSA | 100% | implementation constants | [F60] |
| RSA | 100% | implementation constants | [F61] |
| RSA | 100% | implementation constants | [F62] |
| RSA | 100% | implementation constants | [F63] |
| RSA | 100% | implementation constants | [F64] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0 | 0‑bit security – completely factorable (critical) | [F110] |
| 1024 bits | 65537 | 62 | Legacy size, < 112‑bit security (low) | [F30] |
| 2048 bits | 3 | 88 | Non‑standard small exponent (FIPS 186‑5 non‑compliant) | [F39] |
| 2048 bits | 3 | 88 | Non‑standard small exponent (low) | [F52] |
| 2048 bits | 3 | 88 | Non‑standard small exponent (low) | [F53] |
| 2048 bits | 3 | 88 | Non‑standard small exponent (low) | [F61] |
| 1536 bits | 65537 | 62 | Legacy size, < 112‑bit security (low) | [F60] |
| 1024 bits | 3 | 62 | Small exponent (low) | [F63] |

---  

## Credentials  
No credential artifacts (password hashes, clear‑text passwords, tokens) were reported in the findings. []  

---  

## Processes and Network  

| PID | Process | Observation | ATT&CK Technique |
|-----|---------|-------------|-------------------|
| 924 | csrss.exe | 1 RWX‑injected memory region containing unique executable code | T1055 – Process Injection [F6] |
| 948 | winlogon.exe | 10 RWX‑injected regions (2 with unique code, 8 zero‑filled) | T1055 – Process Injection [F7] |
| 3088 | soffice.bin | 1 RWX‑injected region with unique executable code | T1055 – Process Injection [F9] |

No network‑related findings were present in the supplied data. []  

---  

## Risk Score  

**Overall score:** **86** (rule‑based).  

- **Compromise (80)** – justified by multiple high‑severity process‑injection detections in privileged system processes. [F6][F7][F9]  
- **Crypto exposure (55)** – justified by the presence of a critical RSA‑512 key (strength 0) together with many legacy RSA‑1024 keys and RSA‑2048 keys using a weak exponent (e = 3). [F110][F30][F39][F52][F53][F61][F63]  

No finding provides evidence to materially change either sub‑score, so the rule‑based values are retained.  

---  

## Compromise Assessment (0‑100)  

**Score: 80** – The high‑severity injected code in `csrss.exe`, `winlogon.exe`, and `soffice.bin` demonstrates active malicious execution with system privileges, satisfying the compromise criteria. [F6][F7][F9]  

---  

## Crypto Exposure Assessment (0‑100)  

**Score: 55** – The critical RSA‑512 key (strength 0) alone drives the exposure rating upward, while the numerous RSA‑1024 keys (strength 62) and the RSA‑2048 keys with a non‑standard exponent (strength 88 but non‑compliant) add further risk, resulting in a moderate‑high exposure score that matches the rule‑based value. [F110][F30][F39][F52][F53][F61][F63]  

---  

## Recommendations  

1. **Immediate key rotation**  
   - Replace the RSA‑512 key (critical) and **all** RSA‑1024 keys with RSA‑3072 or stronger keys using the standard exponent 65537. [F110][F30]  
   - Re‑issue any certificates, signed binaries, or tokens that rely on the compromised keys. [F110]  

2. **Enforce a strict cryptographic policy**  
   - Disallow RSA keys < 2048 bits and forbid exponents other than 65537 (per FIPS 186‑5). [F39][F52][F53][F61][F63]  

3. **Process‑injection remediation**  
   - Terminate the compromised instances of `csrss.exe`, `winlogon.exe`, and `soffice.bin`. [F6][F7][F9]  
   - Perform a full system integrity verification (e.g., Windows System File Checker, Trusted Boot) to ensure no persistent backdoors remain. []  

4. **Endpoint Detection & Response (EDR) hardening**  
   - Deploy or tune EDR to alert on RWX memory regions in privileged processes. [F6][F7][F9]  
   - Enable Windows Defender Credential Guard and Code Integrity Guard to block unauthorized code injection. []  

5. **Patch and update**  
   - Apply the latest Windows security patches, especially those addressing known injection techniques. []  

6. **Audit and continuous monitoring**  
   - Log all process‑creation and memory‑mapping events.  
   - Review outbound network traffic for anomalous connections that could indicate command‑and‑control activity. []  

7. **Future forensics readiness**  
   - Schedule regular memory captures and run automated key‑extraction tooling to detect weak cryptographic material before it becomes a liability. []  

---  

*Prepared by the Malware Triage Team*  

## Validation notes (automatic)
Rule-based risk score: 86/100. This report failed these checks, treat the points below as unverified:
- crypto exposure 512 differs from rule-based 55 by more than 20
- only 75% of claims carry a citation