# Where every number comes from

Every score TriageGuard prints is computed in code, never by the LLM. This page lists each one, the formula,
the source it rests on, and what is our own choice because no standard covers it.

| Score | Formula | Based on | Our own choice |
|---|---|---|---|
| Entropy region | Shannon `H = -sum p log2 p` over 4 KB windows, flag `H >= 7.2` | Shannon 1948; threshold from Lyda and Hamrock 2007 (encrypted executables average 7.18, packed 6.80) | window size |
| Cipher confidence | `Bel(A) = 1 - prod(1 - w_i)` over matched signatures | Dempster's rule for simple support functions on one hypothesis (Shafer 1976), same as noisy-OR (Pearl 1988) | the masses `w_i`, set in fixed tiers |
| AES from AES-GCM | `Bel(AES) = 1 - (1 - Bel_AES)(1 - Bel_GCM)` | belief is monotone over subsets: AES-GCM is a subset of AES | none |
| RSA security bits | SP 800-57 table for n >= 1024; below that `E(n) = (1.923 cbrt(n ln2) (ln(n ln2))^(2/3) - 4.69) / ln2` | NIST SP 800-57 Part 1 Rev. 5 Table 2; FIPS 140-2 IG 7.5 (also SP 800-56B Rev. 2) | none |
| RSA broken | 0 bits if a test recovered the key, shared modulus with standard e, or n <= 829 bits | RSA-250 (829 bits) factored, Boudot et al. 2020 | none |
| RSA strength 0-100 | `100 * min(bits, 128) / 128` | 128 bits is SP 800-57's target beyond 2030 | the linear 0-100 scale |
| RSA status | broken / disallowed (< 112 bits) / non-compliant exponent / acceptable | NIST SP 800-131A Rev. 2; FIPS 186-5 A.1.1 (e > 2^16) | none |
| Finding mass | middle of its CVSS v3.1 band / 10: 0.95, 0.80, 0.55, 0.20, 0 | CVSS v3.1 qualitative rating scale (FIRST 2019) | taking the band midpoint |
| Risk 0-100 | `100 * (1 - prod over sources (1 - max mass in source))`, at most 99 | Dempster's rule across independent sources; Denoeux's cautious rule (2008) within a dependent source | grouping a source by module/kind |
| Risk band | 90+ critical, 70+ high, 40+ medium, else low | CVSS v3.1 bands times 10 | none |
| OTP secret | flag under 128 bits | RFC 4226 section 4 (128 required, 160 recommended) | none |
| JWT | `alg=none` high, HS* noted | RFC 8725 (JWT best current practice) | severities |
| Weak TLS | SSL 3.0, TLS 1.0/1.1, RC4, DES/3DES, NULL/export, static RSA, CBC | RFC 7568, RFC 8996, RFC 7465, NIST SP 800-52 Rev. 2 | none |
| Attack success rate | successes / trials, 95% Wilson interval | Wilson 1927 | none |
| Defence effect | two-sided Fisher exact test, baseline vs defended | Fisher 1922 | none |
| Citation rate | cited claim lines / claim lines, pass at 90% | our objective O6 | the 90% bar |
| Cross-check | risk within 20 points; table numbers within 1 point | our design | both tolerances |

Not standard, and said so in the report: the signature masses, the malfind grading (MZ header critical,
JIT and zero-filled regions low, shared code medium), command-line keywords, and the severity given to each
finding type. These are heuristics tuned on the three public dumps.

## What changed (2026-10-11)

Before, three scores were ad hoc: RSA strength was a base of 100/90/60 minus a penalty per issue, risk was
points per severity (25/12/5/2) with a cap per severity, and AES-GCM evidence lifted AES by a fixed 0.8 factor.

| Saved result | Before | After |
|---|---|---|
| Windows 7 risk | 30 | 64 (medium band) |
| Windows 10 risk | 85 | 99 (critical: injected PE, RSA-512 key) |
| Windows 11 risk | 55 | 99 (critical: RSA-512 key) |
| RSA-1024, e=65537 | 35 | 62 (80-bit, disallowed) |
| RSA-2048, e=3 | 40 | 88 (112-bit, non-compliant exponent) |
| RSA-4096, e=3 | 50 | 100 (non-compliant exponent) |
| RSA-512 | 0 | 0 (broken) |
| Synthetic sound RSA-2048 | 90 | 88 |
| Synthetic AES confidence | 60% | 95.2% (AES-GCM tables also count for AES) |
| Synthetic ChaCha20 confidence | 75% | 70% (constant moved to the 0.7 tier) |

Risk values for the dumps are recomputed from the saved `findings.json`. Cipher confidences on the real dumps
need a fresh run, because the saved findings keep only titles, not the matched signatures.
