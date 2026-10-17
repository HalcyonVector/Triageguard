# Incident Report  

**Date:** 2026‑10‑17  
**Analyst:** Malware Triage Team  

---  

## Summary  
Memory analysis revealed two high‑severity processes that provide a reverse/bind shell and upgrade it to a full interactive terminal → [F7][F8].  

---  

## Cryptography  

### Identified Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 94.2% | implementation constants | [F9] |
| RSA | 91.0% | implementation constants | [F10] |
| ChaCha20/Salsa20 | 89.2% | implementation constants | [F11] |
| AES‑GCM | 76.0% | implementation constants | [F12] |
| 3DES | 50.0% | API/string references only | [F13] |
| Curve25519 | 40.0% | API/string references only | [F14] |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 2048‑bit | 43147 | 88 | non‑compliant small exponent | [F15] |
| 2048‑bit | 3 | 88 | non‑compliant small exponent | [F16] |
| 2048‑bit | 3 | 88 | non‑compliant small exponent | [F17] |

---  

## Credentials  
No credential‑type findings were present among the supplied IDs → [F1].  

---  

## Processes and Network  

- **Process inventory:** 220 processes enumerated in the dump → [F1].  
- **Command‑line inventory:** 220 command‑line strings captured → [F2].  
- **Network data:** enumeration was skipped due to a parsing error → [F3].  
- **Injected memory region:** one RWX/injected region observed (no code at base) → [F6].  
- **High‑severity reverse shell:** `bash` launched by `ncat` (PID 2876) → [F7].  
- **Shell upgrade:** `python` executing `pty.spawn("/bin/bash")` (PID 2886) → [F8].  

---  

## Risk Assessment  

- **Overall risk:** High, driven by active attacker‑controlled shells → [F7][F8].  
- **Compromise component:** High because of the two high‑severity reverse‑shell processes → [F7][F8].  
- **Crypto‑exposure component:** Moderate; weak RSA exponents and the presence of legacy 3DES and low‑confidence Curve25519 increase exposure, while modern primitives (AES, RSA, ChaCha20) remain dominant → [F15][F16][F17][F13][F14].  

---  

## Recommendations  

- **Terminate malicious processes** immediately to stop the reverse shell and its upgrade → [F7][F8].  
- **Block the network ports** used by `ncat` (identified by the reverse‑shell process) to prevent further connections → [F7].  
- **Re‑run network enumeration** with a correct symbol table to capture active sockets that were previously skipped → [F3].  
- **Replace all RSA keys** that use small exponents (e = 3 or 43147) with keys using a public exponent of 65537 and a minimum size of 3072 bits to meet current standards → [F15][F16][F17].  
- **Deprecate legacy ciphers**: discontinue 3DES usage and any code paths that reference Curve25519 only via API strings; migrate to AES‑GCM or ChaCha20‑Poly1305 for symmetric encryption → [F13][F14].  
- **Validate cryptographic library integrity** by confirming that the implementation constants for AES, RSA, ChaCha20, and AES‑GCM match expected values → [F9][F10][F11][F12].  
- **Deploy host‑based detection rules** for `ncat` execution (ATT&CK T1059.004 – Unix Shell) and `pty.spawn` usage (ATT&CK T1059.001 – Command‑Line Interface) to alert on future attempts → [F7][F8].  
- **Enable comprehensive process and socket logging** to capture creation events for shells and network connections → [F1].  

---  

*Prepared by the Malware Triage Analyst team.*

## Validation notes (automatic)
Rule-based risk score: 82/100. This report failed these checks, treat the points below as unverified:
- no risk score stated
