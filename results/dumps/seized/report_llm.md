# Incident Report  

## Summary  
Memory analysis revealed two high‑severity suspicious processes that provide a reverse shell and upgrade it to a full interactive terminal, indicating active attacker control【F7】【F8】. Additional low‑severity anomalies include an injected memory region with zero‑filled base and several RSA‑2048 keys that use non‑compliant small exponents【F6】【F15】【F16】【F17】. Cryptographic artifacts show the presence of multiple algorithms; some (3DES, Curve25519) are only referenced via APIs and are therefore weakly indicated【F13】【F14】. No clear credential artifacts (passwords, hashes, tokens) were extracted from the dump【F1】.  

## Cryptography  

The analysis identified the following algorithms with associated confidence levels and evidence sources【F9】.  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 94.2% | implementation constants | F9 |
| RSA | 91.0% | implementation constants | F10 |
| ChaCha20/Salsa20 | 89.2% | implementation constants | F11 |
| AES‑GCM | 76.0% | implementation constants | F12 |
| 3DES | 50.0% | API/string references only | F13 |
| Curve25519 | 40.0% | API/string references only | F14 |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 2048 | 43147 | 88 | small exponent | F15 |
| 2048 | 3 | 88 | small exponent | F16 |
| 2048 | 3 | 88 | small exponent | F17 |

## Credentials  
No credential artifacts (passwords, hashes, tokens) were found in the memory image【F1】.  

## Processes and Network  

- Total processes enumerated: 220 rows【F1】.  
- Total command‑line entries: 220 rows【F2】.  
- **bash** (PID 2876) launched by **ncat**, providing a reverse or bind shell【F7】.  
- **python** (PID 2886) that upgrades the reverse shell to a full terminal via `pty.spawn`【F8】.  
- One injected memory region with an anomalous zero‑filled base【F6】.  
- Network data could not be parsed; the analysis skipped network information due to a symbol‑table error【F3】.  
- No injected bash history rows were present【F5】.  

## Risk Score  

| Component | Score | Justification |
|-----------|-------|---------------|
| Compromise | 80 | High‑severity reverse‑shell processes (bash via ncat and python PTY spawn) demonstrate active attacker foothold【F7】【F8】 |
| Crypto Exposure | 20 | RSA keys are 2048‑bit but use small exponents; 3DES and Curve25519 are only weakly referenced, yet overall cryptographic strength remains moderate【F15】【F16】【F17】【F13】【F14】 |
| Overall Risk | 82 | Matches the rule‑based baseline (compromise 80 + crypto 20) and is supported by the cited findings【F7】【F8】【F15】【F16】【F17】 |

## Recommendations  

- **Terminate and investigate the reverse‑shell processes** (bash via ncat and python PTY spawn) to stop attacker activity【F7】【F8】.  
- **Block outbound traffic on the ports used by ncat** and enforce strict egress filtering to prevent future reverse‑shell establishment【F7】.  
- **Rotate all RSA keys that use small exponents** (e = 3 or e = 43147) and generate new keys with a compliant exponent (e ≥ 65537)【F15】【F16】【F17】.  
- **Deprecate 3DES** and replace it with AES‑GCM or ChaCha20 where feasible, as 3DES is only weakly referenced and offers limited security【F13】.  
- **Review and harden cryptographic implementations** to ensure only strong algorithms (AES‑GCM, ChaCha20) are used; consider removing low‑confidence Curve25519 references【F14】.  
- **Capture full network traffic** to replace the skipped network analysis and identify any C2 communications missed due to the parsing error【F3】.  
- **Conduct a comprehensive system integrity check** for additional injected code or memory anomalies beyond the single region reported【F6】.  
- **Deploy continuous endpoint monitoring** for suspicious process creation (e.g., shells spawned by network utilities) and integrate with an EDR solution to alert on similar activity【F7】【F8】.  