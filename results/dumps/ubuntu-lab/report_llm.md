# Incident Report  

**System:** Ubuntu‑lab (snapshot `ubuntu‑lab‑Snapshot1.vmem`)  
**Analysis date:** 2026‑10‑16  

---  

## Summary  
- A **high‑severity** injected code region was discovered in process **`unattended‑upgr`** (PID 931), indicating process‑injection (ATT&CK T1055)【F6】.  
- Two RSA‑2048 keys use **small public exponents** (e = 3 and e = 43147), which are non‑compliant with FIPS 186‑5 and vulnerable to Hastad‑style attacks【F27】【F21】.  
- Five processes (`updater`, `syncd`, `keysvc`, `legacy_rsa`, `python3`) execute custom encryption code and contain the string “encrypt” on their command lines, matching ATT&CK T1486 (Data Encrypted for Impact)【F7】【F8】【F9】【F10】【F11】.  
- Private keys for **`keysvc`** and **`legacy_rsa`** and an **AES‑256 key** for `updater` were recovered from memory, allowing decryption of data encrypted by those processes【F26】【F28】【F29】.  

These artifacts collectively demonstrate an active compromise with cryptographic misuse.  

---  

## Cryptography  

### Identified Algorithms  

| Algorithm | Confidence | Basis | Finding |
|-----------|------------|-------|---------|
| AES | 100.0% | implementation constants | 【F12】 |
| ECC P‑256 | 99.1% | implementation constants | 【F13】 |
| AES‑GCM | 97.6% | implementation constants | 【F14】 |
| ChaCha20/Salsa20 | 95.5% | implementation constants | 【F15】 |
| secp256k1 | 92.8% | implementation constants | 【F16】 |
| DES | 80.0% | implementation constants | 【F17】 |
| Curve25519 | 78.4% | API/string references only | 【F18】 |
| RSA | 70.0% | implementation constants | 【F19】 |
| 3DES | 50.0% | API/string references only | 【F20】 |

### RSA Key Details  

| Key size | Exponent | Strength | Issue | Finding |
|----------|----------|----------|-------|---------|
| 2048 bits | 3 | 88 | small exponent (vulnerable to Hastad attacks) | 【F27】 |
| 2048 bits | 43147 | 88 | small exponent (non‑compliant) | 【F21】 |

---  

## Credentials  
No credential artifacts (passwords, tokens, or secret strings) were extracted from the memory image; the findings list only cryptographic keys and process information【F1】【F2】.  

---  

## Processes and Network  

| PID | Process | ATT&CK technique | Evidence |
|-----|---------|------------------|----------|
| 931 | unattended‑upgr | T1055 – Process Injection (RWX injected region) | 【F6】 |
| 1275 | updater | T1486 – Data Encrypted for Impact (command line contains “encrypt”) | 【F7】 |
| 1276 | syncd | T1486 – Data Encrypted for Impact (command line contains “encrypt”) | 【F8】 |
| 1277 | keysvc | T1486 – Data Encrypted for Impact (command line contains “encrypt”) | 【F9】 |
| 1278 | legacy_rsa | T1486 – Data Encrypted for Impact (command line contains “encrypt”) | 【F10】 |
| 1279 | python3 | T1486 – Data Encrypted for Impact (command line contains “encrypt”) | 【F11】 |

Network information is present (299 rows) but no malicious connections are identified in the supplied findings【F3】.  

---  

## Risk Score  

- **Overall risk:** **86** (rule‑based)【F1】.  
- **Compromise component:** **80** (rule‑based) – supported by the injected process (F6) and the suite of suspicious encryption processes (F7‑F11)【F6】【F7】【F8】【F9】【F10】【F11】.  
- **Crypto exposure component:** **55** (rule‑based) – supported by weak RSA exponents (F27, F21), presence of legacy ciphers (DES, 3DES) (F17, F20), and recovered private keys that enable decryption (F26, F28, F29)【F27】【F21】【F17】【F20】【F26】【F28】【F29】.  

No cited finding contradicts the supplied rule‑based scores, so they are retained.  

---  

## Compromise (Score 80) – Justification  

- **Process injection** in `unattended‑upgr` provides direct evidence of attacker‑controlled code execution (ATT&CK T1055)【F6】.  
- **Multiple processes** running custom encryption commands indicate deliberate data encryption activity, matching ATT&CK T1486 (Data Encrypted for Impact)【F7】【F8】【F9】【F10】【F11】.  

These observations satisfy a high likelihood of active compromise.  

---  

## Crypto Exposure (Score 55) – Justification  

- **Small RSA exponents** (e = 3, e = 43147) are non‑compliant with FIPS 186‑5 and expose the keys to Hastad broadcast attacks, reducing effective security despite the 2048‑bit size【F27】【F21】.  
- **Legacy ciphers** DES and 3DES are present, both considered insecure and unsuitable for protecting sensitive data【F17】【F20】.  
- **Recovered private keys** (keysvc, legacy_rsa) and an AES‑256 key for `updater` allow decryption of data that was encrypted by the compromised software, demonstrating a concrete exposure【F26】【F28】【F29】.  

These factors justify the moderate crypto‑exposure rating.  

---  

## Recommendations  

1. **Containment & Eradication**  
   - Immediately terminate the injected process `unattended‑upgr` (PID 931) and all suspicious encryption processes (PIDs 1275‑1279) to stop further malicious activity【F6】【F7】【F8】【F9】【F10】【F11】.  
   - Reboot the host from trusted media to clear any residual injected code from memory【F6】.  

2. **Key Management**  
   - Regenerate all RSA key pairs with a **public exponent of 65537** and a minimum key size of **3072 bits**; replace the compromised keys identified in F27 and F21【F27】【F21】.  
   - Rotate the recovered AES‑256 key (updater) and any other symmetric keys disclosed in the findings【F29】.  
   - Store private keys in hardware‑backed keystores (TPM or HSM) to prevent future memory exposure【F26】【F28】.  

3. **Algorithm Hardening**  
   - Deprecate and remove **DES** and **3DES** from all code bases; migrate to **AES‑GCM** or **ChaCha20‑Poly1305** for symmetric encryption【F17】【F20】【F14】【F15】.  
   - Enforce RSA encryption with OAEP padding and approved exponents, or switch to elliptic‑curve schemes (e.g., P‑256, Curve25519) that are already present with high confidence【F13】【F18】.  

4. **Monitoring & Detection**  
   - Deploy host‑based intrusion detection rules that alert on RWX memory regions and process‑injection events (T1055)【F6】.  
   - Log all invocations of the `cryptography` library and command‑line arguments containing the word “encrypt” to detect future misuse【F7】【F8】【F9】【F10】【F11】.  

5. **Patch & Update**  
   - Apply the latest OS security patches and update the Python `cryptography` package to the newest stable version to mitigate known vulnerabilities【F5】.  

6. **Forensic Follow‑up**  
   - Conduct a full forensic review of the disk image to locate any persisted malicious binaries or scheduled tasks that may have survived the memory wipe【F4】.  
   - Correlate the 299 network rows with external threat‑intel feeds to rule out command‑and‑control activity【F3】.  

Implementing these actions will remove the current malicious foothold, eliminate weak cryptographic artifacts, and strengthen the environment against future compromise.  

## Validation notes (automatic)
Rule-based risk score: 86/100. This report failed these checks, treat the points below as unverified:
- only 80% of claims carry a citation