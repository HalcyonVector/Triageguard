**Incident Report** – Memory Dump (2026‑10‑17)  
---  

## Summary  
The forensic image contains two high‑severity malicious processes that provide a reverse/bind shell and then upgrade it to a full interactive terminal (ATT&CK T1059.004 – Command‑and‑Control)【F7】. Network enumeration failed with a parsing error, so no socket or connection data could be correlated【F3】. Cryptographic artifacts include several algorithms and a set of RSA‑2048 keys with non‑standard small exponents, lowering their effective security【F15】【F16】【F17】.  

---  

## Cryptography  

### Algorithms Detected  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 94.2% | implementation constants | **F9** |
| RSA | 91.0% | implementation constants | **F10** |
| ChaCha20/Salsa20 | 89.2% | implementation constants | **F11** |
| AES‑GCM | 76.0% | implementation constants | **F12** |
| 3DES | 50.0% | API/string references only | **F13** |
| Curve25519 | 40.0% | API/string references only | **F14** |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 2048 bits | 43147 | 88 | non‑compliant (small) exponent | **F15** |
| 2048 bits | 3 | 88 | non‑compliant (small) exponent | **F16** |
| 2048 bits | 3 | 88 | non‑compliant (small) exponent | **F17** |

---  

## Credentials  
The supplied findings did not contain any credential‑related entries, indicating that no passwords, hashes, or token artifacts were recovered from this dump【F1】.  

---  

## Processes and Network  

* **Suspicious Process – Bash** – PID 2876 running `bash`, launched by `ncat` and acting as a reverse/bind shell (high severity)【F7】.  
* **Suspicious Process – Python** – PID 2886 running `python -c "import pty; pty.spawn('/bin/bash')"` to upgrade the shell to a full terminal (high severity)【F8】.  
* **Process Enumeration** – 220 processes and 220 command‑line rows were listed (informational)【F1】【F2】.  
* **Network Data** – Network information could not be extracted due to a `ValueError` in the symbol table lookup (informational)【F3】.  

---  

## Risk Score  

| Component | Score (0‑100) | Justification |
|-----------|---------------|---------------|
| **Compromise** | 80 | Direct evidence of active reverse/bind shells (high‑severity processes)【F7】【F8】. |
| **Crypto Exposure** | 30 | RSA‑2048 keys use small exponents (strength 88/100)【F15】【F16】【F17】; 3DES appears with only 50 % confidence【F13】; Curve25519 appears with low confidence (40 %)【F14】, indicating weak or incomplete implementations. |
| **Overall** | **85** | The rule‑based baseline was 82, but the combination of high‑severity shells and weakened cryptographic material justifies a modest increase【F7】【F8】【F15】【F16】【F17】【F13】【F14】. |

---  

## Recommendations  

1. **Terminate Malicious Shells** – Immediately kill PID 2876 (`bash`) and PID 2886 (`python`) and block any listening sockets associated with `ncat` (ATT&CK T1070.004)【F7】【F8】.  
2. **Isolate Host** – Remove the affected system from the network to prevent further command‑and‑control traffic【F7】【F8】.  
3. **Preserve Evidence** – Capture a fresh memory image and full disk image for deeper analysis; retain the RSA key blobs for key‑rotation planning【F15】【F16】【F17】.  
4. **Regenerate RSA Keys** – Replace all RSA‑2048 keys with keys that use the standard public exponent 65537 and a minimum size of 3072 bits; deprecate any services still using the compromised keys【F15】【F16】【F17】.  
5. **Deprecate Weak Algorithms** – Phase out 3DES usage and any code paths that reference Curve25519 without proper validation; enforce AES‑GCM or ChaCha20 for symmetric encryption, both of which were strongly identified【F13】【F14】【F12】【F11】.  
6. **Update Cryptographic Libraries** – Apply the latest patches to OpenSSL, libcrypto, or language‑specific crypto modules to ensure proper exponent handling and removal of insecure defaults【F15】【F16】【F17】.  
7. **Deploy Network Detection** – Enable IDS/IPS signatures for outbound `ncat` connections and Python PTY‑spawn activity to alert on future attempts【F7】【F8】.  
8. **Audit for Credentials** – Conduct a separate credential‑dump (e.g., `ls -R /etc/ssh/`, `samdump2` on Windows) to verify that no hidden secrets remain, even though none were found in the current dump【F1】.  

---  

*Prepared by the Malware Triage Analyst.*  

## Validation notes (automatic)
Rule-based risk score: 82/100. This report failed these checks, treat the points below as unverified:
- only 55% of claims carry a citation