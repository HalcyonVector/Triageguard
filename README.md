# TriageGuard

**Memory forensics and cryptographic malware triage, with an LLM report you can verify.**

TriageGuard takes a memory image (and optionally a packet capture), finds injected code, suspicious processes,
ciphers, weak or recoverable keys and leaked credentials, scores the risk with documented formulas, and writes
an incident report in which every claim cites the finding it rests on. The LLM never sees the raw dump, and a
validator checks its report against the rule-based results before anyone reads it.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![Volatility](https://img.shields.io/badge/Volatility-3-informational) ![Images](https://img.shields.io/badge/images-Windows%20%7C%20Linux-lightgrey) ![Tests](https://img.shields.io/badge/tests-68%20passing-brightgreen)

## Highlights

- **Windows and Linux images** through Volatility 3, with the OS detected automatically (Windows XP to 11 and Server, Ubuntu, CentOS).
- **Cipher identification** for AES, DES/3DES, RSA, ChaCha20/Salsa20, AES-GCM, ECC and Curve25519, each with a confidence score.
- **Key recovery from memory:** RSA private keys rebuilt from leftover primes (the WannaCry flaw), AES key schedules and ChaCha20 keys.
- **RSA weak-key tests:** key size against NIST SP 800-57, small exponents, shared moduli, shared primes (batch GCD), close primes (Fermat).
- **Credential decoding:** JWTs, OAuth and API tokens, `otpauth://` secrets, always stored redacted.
- **Network analysis** of pcaps: conversations, DNS, TLS versions and cipher suites.
- **ATT&CK mapping** of findings, and **campaign linking** that joins dumps from the same intrusion by rare shared evidence.
- **Defended LLM reports:** input sanitisation, mandatory citations and a rule-based cross-check, tested against 15 prompt-injection attacks.
- **Local dashboard** to browse results and analyse new images with one click.

## Quick start

### Windows (one click)

```bash
git clone https://github.com/HalcyonVector/Triageguard.git
```

Then double-click **`TriageGuard.bat`** in the cloned folder. On first run it creates a virtual environment,
installs the requirements and opens the dashboard in your browser. Results for 14 public and lab memory images
are included, so the dashboard works without downloading any dumps.

### Any platform

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m triageguard dashboard
```

Optional extras:

| For | Install |
|---|---|
| LLM reports | a free [Groq](https://console.groq.com) key in a `.env` file: `GROQ_API_KEY=...` |
| pcap analysis | Wireshark (provides `tshark`) |
| Linux images | the kernel's Volatility symbol table (ISF) in `symbols/` |

Without an LLM key, TriageGuard still produces the full rule-based report.

## Usage

**From the dashboard:** click **Analyse a dump**, paste the path to a memory image (and optionally a pcap), and
press Run. The log streams live and the result appears on the board when it finishes.

**From the command line:**

```bash
python -m triageguard analyze memory.raw --pcap traffic.pcap   # full pipeline
python -m triageguard crypto suspicious.bin                     # crypto analysis on any file
python -m triageguard report run.db --out report_llm.md         # (re)write the LLM report
python -m triageguard check run.db                              # sanity-check an analysed dump
python -m triageguard redteam --trials 3                        # attack the LLM report, baseline vs defended
python -m triageguard benchmark                                 # ground-truth cipher and key test (Linux)
```

On Windows, `add_dump.ps1` wraps download, unpacking, analysis, export and the LLM report for large public
images, and resumes safely if interrupted.

## How it works

| Stage | Module | What it does |
|---|---|---|
| Memory | `memory.py` | Volatility 3 processes, command lines, network, `malfind`, USB history; classifies injected regions |
| Static | `static.py` | strings, PE headers, section entropy, crypto imports, YARA rules |
| Crypto | `crypto/` | cipher identification, high-entropy regions, RSA extraction and weak-key tests, key recovery |
| Credentials | `credentials.py` | JWT, OAuth/API token and OTP secret detection, redacted |
| Network | `network.py` | conversations, DNS, TLS SNI, versions and cipher suites |
| Fusion | `report.py` | ATT&CK mapping, compromise and crypto-exposure scores, Dempster-Shafer fusion |
| Report | `report.py`, `defences.py` | defended LLM report with citations, or the rule-based report |

Every finding is stored in SQLite with a citation id (`F1`, `F2`, ...). Every score names its formula and the
standard or paper behind it in [`docs/FORMULAS.md`](docs/FORMULAS.md). For a plain-language walkthrough, see
[`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md).

## LLM defences

Any field in a finding can come from attacker-controlled memory (JWT claims, OTP labels, TLS SNI, command
lines), so the report generator treats findings as hostile input:

1. **Sanitisation:** instruction-like text and forged citations are stripped, and each hit becomes its own
   `prompt_injection` finding.
2. **Spotlighting and mandatory citation:** findings are marked as untrusted data, and every fact, table row
   and recommendation must cite a valid finding id.
3. **Cross-check:** the report's scores, algorithms and numbers are compared with the rule-based results,
   critical findings must be mentioned, and dangerous advice is flagged. A failing report is retried once and
   then shipped with visible validation notes.

## Evaluation

**Memory images.** 14 images: CTF and DFIR challenges, a WannaCry sample and two self-built Ubuntu VMs.

| Image | OS | Risk |
|---|---|---|
| 13Cubed Windows challenge | Windows 11 24H2 | 74 |
| DFIR Madness case 001 (desktop, domain controller) | Windows 10, Server 2012 R2 | 96, 96 |
| Hacktoria Memory Mystery | Windows 7 SP1 | 60 |
| WannaCry | Windows 7 | 95 |
| M57-Patents | Windows XP SP3 | 42 |
| CyberDefenders Reveal, Brave, RedLine, Ramnit | Windows 10 | 86, 89, 97, 82 |
| 13Cubed Linux challenge | Ubuntu 22.04 | 89 |
| CyberDefenders Seized | CentOS 7.7 | 82 |
| Lab VM with planted keys | Ubuntu 24.04 | 67 |
| Lab VM, clean baseline | Ubuntu 24.04 | 28 |

All 14 LLM reports pass validation: 90 to 100% of claims cited, and every stated risk matches the rule-based score.

**Ground truth.**
- **Lab VM:** passes 12 of 12 checks. Each planted process has its cipher identified and its AES-GCM, ChaCha20
  or RSA key recovered, and the small RSA exponent is flagged.
- **Benchmark:** over 5 trials per case, cipher identification scores 45 of 45, and live AES, ChaCha20 and RSA
  keys are recovered every time.
- **WannaCry:** four RSA-2048 private keys are rebuilt from its memory.

**Red team.** 15 attacks, including adaptive ones, each hidden in two fields over 3 trials:

| | Undefended | Defended |
|---|---|---|
| Attack success | 2/90 | 0/90 |
| Misleading report reaching a reader unflagged | n/a | 0/90 |
| Cross-check passed | 84/93 | 91/93 |

## Project layout

```
triageguard/   pipeline, crypto, credentials, network, report, defences, dashboard server
dashboard/     single-page dashboard (no build step, works offline)
results/       exported results for every image, red-team rounds, benchmark
tools/         lab key planting and scoring, Volatility 2 to ISF converter
docs/          HOW_IT_WORKS.md, FORMULAS.md
tests/         pytest suite
```

## Responsible use

TriageGuard is meant for memory images you are authorised to examine. The evaluation uses public datasets and
synthetic keys and tokens only. It never executes malware, and recovered credentials are stored redacted.
