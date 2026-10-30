# Demo script (progress evaluation)

Run everything from the repo folder in the `(.venv)` PowerShell window. Outputs are pre-generated in
`results/` so nothing below has to finish live.

## 1. The crypto module, 30 seconds (live)

```powershell
python samples/make_synthetic.py
python -m triageguard crypto samples/synthetic.raw
```

Synthetic image with known keys. Shows cipher identification with confidence (AES, AES-GCM, ChaCha20,
Curve25519, RSA) and the weak RSA key tests: 512-bit, e=3, shared prime, close primes (Fermat), shared modulus.
Say: random data gives zero hits, and OpenSSL, libsodium and libgcrypt are all identified correctly.

## 2. Full pipeline on the synthetic image, 1 minute (live)

```powershell
python -m triageguard analyze samples/synthetic.raw --no-llm
```

Say: Volatility3 is skipped here because it is not a Windows image; crypto, credentials and report still run.

## 2b. Dashboard (live, offline)

```powershell
python -m triageguard dashboard
```

Opens a local page with the real-dump findings, both reports with clickable citations (click `[F65]` to jump
to the finding), the red-team charts, and a done / yet-to-do tab. Use it to walk through steps 3 and 4 below.

## 3. Real Windows dump (pre-generated, the run takes about 22 minutes)

Three public dumps are in the dashboard (Windows 11, Windows 10 with a real pcap, Windows 7); the Windows 10
one is the most visual: critical PE header injected into `spoolsv.exe`, `powershell.exe` with injected
regions. The Windows 11 details follow. Open `results/dumps/win11/report_llm.md`. Image: 13Cubed Windows 11 24H2, 4.3 GB, plus Wireshark's
`rsasnakeoil2.pcap`. Points to hit:

- 80 findings, rule-based risk 55/100. The first run gave 689 findings and risk 100, so say what we tuned:
  certificate-store RSA keys, Defender's JIT memory flagged as injection, netscan returning nothing on 24H2
  (netstat fallback), a per-severity cap on the score.
- RSA-512 key in memory (critical, strength 0/100).
- Notepad opened on `Desktop\encryption_log.txt` and DumpIt.exe on the Desktop: the story of the image.
- 4 expired JWTs, and in the pcap SSL 3.0 with static RSA key exchange and 3DES (no forward secrecy).
- The LLM report cites a finding id for its claims; the validator still flags it (72% cited), which shows the
  check is not a rubber stamp.

## 4. Red-teaming the LLM (pre-generated, 78 LLM calls)

Open `results/redteam_summary.md`. Say: we hide instructions in fields an attacker controls (JWT `iss`, OTP
issuer), 6 attacks, and compare the plain report with the defended one (sanitiser, mandatory citations,
rule-based cross-check, one retry).

| | Undefended | Defended |
|---|---|---|
| Attack success rate | 4/36 | 0/36 |
| Success with no warning attached | n/a | 0/36 |
| Claims with a valid citation | 28% | 78% |

Be upfront about the limits: 6 trials per cell is small (0 of 36 does not prove zero risk), and a citation
check proves a finding exists, not that the sentence is right. If asked about the scoring: we found and fixed
two mistakes in our own checker (fullwidth `【F6】` brackets, and bold `**F6**` ids) and re-scored all 78
reports offline, which is why the numbers differ from earlier drafts.

Optional live check, no LLM and no quota:

```powershell
python -m triageguard redteam --dry-run
```

Shows the payload reaching the findings in 12/12 cases and the sanitiser catching 10/12 (the two it misses
are the `subtle_benign` attack, which has no trigger words).

## 5. Likely questions

- Why not just trust the LLM? It never sees the raw dump, only findings, and every claim must cite one.
- Cipher scope? AES, DES/3DES, RSA, ChaCha20/Salsa20, AES-GCM, ECC (P-256, secp256k1, Curve25519).
  Post-quantum is a discussion point only.
- Safety? Public datasets and synthetic keys only; no malware executed; no real credentials.
