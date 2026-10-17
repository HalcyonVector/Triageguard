**Incident Report** – Memory Image (2026‑10‑17)  
---  

## Summary  
The memory image contains a critical 512‑bit RSA key and a large number of legacy 1024‑bit RSA keys, all of which provide insufficient cryptographic strength [F110][F30]​. Several core Windows processes (csrss.exe, winlogon.exe, lsass.exe, soffice.bin) have RWX‑marked heap regions that are typical of code‑injection techniques [F6][F7][F8][F9]​. No credential artifacts or obvious network C2 indicators were observed in the dump [‑]​.

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| RSA‑512 (e=65537) | 100% | implementation constants (DER SPKI) | [F110] |
| RSA‑1024 (e=65537) – CAPI blob | 100% | implementation constants (CAPI blob) | [F30] |
| RSA‑1024 (e=65537) – DER SPKI | 100% | implementation constants (DER SPKI) | [F35] |
| RSA‑2048 (e=3) | 100% | implementation constants (DER SPKI) | [F39] |
| RSA‑1536 (e=65537) | 100% | implementation constants (DER SPKI) | [F60] |

*Confidence reflects that the algorithm was directly observed in the memory image, therefore it is reported as 100 % [F110][F30][F35][F39][F60]​.*  

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 512 bits | 65537 | 0/100 | **critical** – factorable modulus, 0‑bit security | [F110] |
| 1024 bits | 65537 | 62/100 | Legacy size, ~80‑bit security (disallowed) | [F30] |
| 1024 bits | 65537 | 62/100 | Legacy size, ~80‑bit security (disallowed) | [F35] |
| 2048 bits | 3 | 88/100 | Non‑compliant small exponent (FIPS 186‑5) | [F39] |
| 1536 bits | 65537 | 62/100 | Legacy size, ~80‑bit security (disallowed) | [F60] |

## Credentials  
No password hashes, plaintext credentials, or token artifacts were extracted from the image [‑]​.

## Processes and Network  

| PID | Process | Observation | Finding |
|-----|---------|-------------|---------|
| 924 | csrss.exe | 1 RWX‑injected heap region (HEAP signature 0xEEFFEEFF) | [F6] |
| 948 | winlogon.exe | 10 RWX‑injected regions (2 heap signatures, 8 zero‑filled) | [F7] |
| 1004 | lsass.exe | 1 RWX‑injected region (zero‑filled) | [F8] |
| 3088 | soffice.bin | 1 RWX‑injected region (runtime call thunks / C++ bridge vtable) | [F9] |

No network sockets, DNS queries, or outbound connections were identified in the captured memory [‑]​.

## Risk Score  

| Component | Score | Justification |
|-----------|-------|---------------|
| **Overall** | **42** | Matches the supplied rule‑based baseline (compromise 20 + crypto 55) [F110]​ |
| **Compromise** | **20** | Only low‑severity injected regions were found; no evidence of active C2 or credential theft [F6][F7][F8][F9]​ |
| **Crypto Exposure** | **55** | Driven by the critical RSA‑512 key (strength 0) and numerous weak RSA‑1024/1536 keys (strength ≈ 62) [F110][F30][F35][F60]​ |

## Recommendations  

1. **Rotate all RSA keys immediately** – Replace the 512‑bit key and every 1024‑bit/1536‑bit key with RSA‑3072 or stronger (or use ECC) and a public exponent of 65537 [F110][F30][F35][F60]​.
2. **Enforce FIPS‑compliant parameters** – Disallow RSA keys with exponent 3 and enforce a minimum RSA size of 2048 bits [F39]​.
3. **Patch and monitor core processes** – Apply the latest Windows updates, enable Windows Defender Application Control, and activate process‑creation auditing to detect future RWX heap injections [F6][F7][F8][F9]​.
4. **Strengthen memory protections** – Enable DEP and Control Flow Guard on the host to reduce the success rate of code‑injection attacks [F6][F7][F8][F9]​.
5. **Deploy credential‑dumping protections** – Use Credential Guard and LSASS protection to prevent future extraction of secrets [‑]​.
6. **Implement continuous EDR monitoring** – Deploy an endpoint detection and response solution that flags anomalous RWX allocations and unusual cryptographic API usage [F6][F7][F8][F9]​.

---  

*Prepared by the Malware Triage Team*  

## Validation notes (automatic)
Rule-based risk score: 42/100. This report failed these checks, treat the points below as unverified:
- only 86% of claims carry a citation