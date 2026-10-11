"""Report generation. The LLM only ever sees the structured findings from
SQLite (never raw dump bytes) and is asked to cite finding ids like [F3].

Without GROQ_API_KEY (or TRIAGEGUARD_LLM_URL), a rule-based report is produced instead, which is also
the baseline the LLM output can be cross-checked against later.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request

from . import attack
from .crypto.identify import combine

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# llama-3.3-70b-versatile was shut down by Groq on 2026-08-16 (404 model not found);
# gpt-oss-120b is their listed replacement. Override with TRIAGEGUARD_MODEL or --model.
FALLBACK_MODEL = "openai/gpt-oss-120b"
DEFAULT_MODEL = None  # resolved at call time so --model / TRIAGEGUARD_MODEL set after import still apply
MAX_RETRIES = 6
MAX_WAIT = 120  # seconds; longer waits mean the daily quota is gone

SYSTEM_PROMPT = """You are a malware triage analyst. You receive structured findings from a memory
forensics and crypto analysis pipeline. Write a concise incident report in Markdown with sections:
Summary, Cryptography (algorithms with confidence, key strength), Credentials, Processes and Network,
Risk score (0-100) with justification, Recommendations. Where a finding carries ATT&CK technique ids,
name them next to it.
Cite the finding id in square brackets, e.g. [F3], after every factual claim.
In Cryptography use two Markdown tables. First: Algorithm | Confidence | Basis | Finding, one row per
identified algorithm, with only the percentage in the Confidence column (for example 99.2%) and either
"implementation constants" or "API/string references only" in Basis. Second, if RSA keys are present:
Key size | Exponent | Strength | Issue | Finding, with only the 0-100 number in the Strength column."""


# CVSS v3.1 qualitative severity rating scale (FIRST, CVSS v3.1 specification, section 5):
# None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0. A finding of a
# given severity counts as the middle of its band, on a 0-1 scale.
SEV_MASS = {"critical": 0.95, "high": 0.80, "medium": 0.55, "low": 0.20, "info": 0.0}


def finding_mass(f):
    """Mass one finding commits to "this host is compromised or exposed": its CVSS band
    midpoint, scaled by the detector's own confidence when it has one (cipher ID)."""
    m = SEV_MASS.get(f["severity"], 0.0)
    conf = (f.get("data") or {}).get("confidence")
    if isinstance(conf, (int, float)):
        m *= conf / 100
    return m


def risk_breakdown(findings):
    """One row per evidence source (module/kind), strongest finding first.

    Findings from one detector are not independent (37 certificates from one
    certificate store, several RWX regions from one malfind pass), and Dempster's rule
    must not count the same evidence twice. Denoeux's cautious rule for non-distinct
    evidence (Artificial Intelligence 172, 2008) combines simple support functions on
    the same hypothesis by keeping the largest mass, so each source counts once, at
    its strongest finding."""
    src = {}
    for f in findings:
        key = f"{f.get('module', '?')}/{f.get('kind', '?')}"
        m = finding_mass(f)
        row = src.setdefault(key, {"source": key, "mass": 0.0, "ref": None, "count": 0})
        row["count"] += 1
        if m > row["mass"]:
            row["mass"], row["ref"] = m, f["ref"]
    return sorted((r for r in src.values() if r["mass"] > 0), key=lambda r: -r["mass"])


def risk_score(findings):
    """Evidence-fusion risk, 0-100: Dempster's rule across independent sources
    (memory, RSA, credentials, network, ...) of each source's cautious-rule mass,
    risk = 100 * (1 - prod(1 - m_source)). One critical source alone gives 95; two
    independent medium sources give 80; low-severity context cannot pile up because
    a source counts once. Belief never reaches 1, so 99 is the ceiling."""
    return min(99, round(100 * combine(r["mass"] for r in risk_breakdown(findings))))


def risk_band(score):
    """The CVSS v3.1 qualitative rating for a 0-100 risk (the same bands, times 10)."""
    return "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low" if score > 0 else "none"


def key_strength(findings):
    scores = [f["data"]["strength"] for f in findings if f["kind"] == "rsa_key" and f["data"].get("strength") is not None]
    return min(scores) if scores else None


def compact(findings, max_chars=10_000):
    """Trim findings to fit the free tier: one Groq request may not exceed 8k tokens,
    and the defended retry sends the findings plus the first answer, so keep this
    around 3k tokens (JSON and hex run at roughly 3 characters per token)."""
    out = []
    # most severe first, so truncation drops info rows rather than the incident
    order = ["critical", "high", "medium", "low", "info"]
    for f in sorted(findings, key=lambda f: order.index(f["severity"]) if f["severity"] in order else len(order)):
        line = f"[{f['ref']}] ({f['module']}/{f['kind']}, {f['severity']}) {f['title']}"
        if tech := attack.techniques(f):
            line += f" (ATT&CK {', '.join(tech)})"
        if f["severity"] not in ("low", "info"):  # the title already says enough for context rows
            d = json.dumps(f["data"], default=str)
            line += " | " + (d[:400] + "...(truncated)" if len(d) > 400 else d)
        out.append(line)
    text = "\n".join(out)
    return text[:max_chars]


def llm_available():
    return bool(os.environ.get("TRIAGEGUARD_LLM_URL") or os.environ.get("GROQ_API_KEY"))


def chat(messages, model=DEFAULT_MODEL, temperature=0.2):
    """One chat completion against Groq, or any OpenAI-compatible endpoint set in
    TRIAGEGUARD_LLM_URL (e.g. a local Ollama at http://localhost:11434/v1/chat/completions)."""
    url = os.environ.get("TRIAGEGUARD_LLM_URL") or GROQ_URL
    headers = {"Content-Type": "application/json", "User-Agent": "triageguard"}
    if os.environ.get("GROQ_API_KEY") and url == GROQ_URL:
        headers["Authorization"] = f"Bearer {os.environ['GROQ_API_KEY']}"
    model = model or os.environ.get("TRIAGEGUARD_MODEL") or FALLBACK_MODEL
    body = {"model": model, "temperature": temperature, "messages": messages}
    # opt-in knobs for reasoning models, whose hidden reasoning can use up the output budget
    # and leave the report cut off: TRIAGEGUARD_REASONING_EFFORT=low, TRIAGEGUARD_MAX_TOKENS=4096
    if effort := os.environ.get("TRIAGEGUARD_REASONING_EFFORT"):
        body["reasoning_effort"] = effort
    if limit := os.environ.get("TRIAGEGUARD_MAX_TOKENS"):
        body["max_completion_tokens"] = int(limit)
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers=headers)
    for attempt in range(MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                choice = json.load(r)["choices"][0]
            if choice.get("finish_reason") == "length":
                print("      warning: the model's answer was cut off at its output limit "
                      "(try TRIAGEGUARD_REASONING_EFFORT=low); the validator will flag the report", flush=True)
            return choice["message"]["content"]
        except urllib.error.HTTPError as e:
            # the API explains itself in the body (model retired, bad key, rate limit); surface it
            detail = e.read().decode(errors="replace")[:500]
            # free tier is 8k tokens/min, so 429 is normal: wait as long as the API says and retry.
            # A daily (TPD) limit asks for minutes or hours, which is not worth waiting for here.
            wait = _retry_after(e, detail)
            if e.code == 429 and attempt < MAX_RETRIES and wait is not None and wait <= MAX_WAIT:
                print(f"      rate limited, waiting {wait:.0f}s (retry {attempt + 1}/{MAX_RETRIES})", flush=True)
                time.sleep(wait + 1)
                continue
            raise RuntimeError(f"LLM request failed: HTTP {e.code} from {url} (model {model}): {detail}") from None


def _retry_after(err, detail):
    """Seconds to wait from the Retry-After header or Groq's 'try again in 1m2.5s' text."""
    if h := err.headers.get("Retry-After"):
        try:
            return float(h)
        except ValueError:
            pass
    if m := re.search(r"try again in (?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?", detail):
        h, mins, s = (float(x) if x else 0.0 for x in m.groups())
        return h * 3600 + mins * 60 + s if any(m.groups()) else None
    return None


def llm_report(findings, model=DEFAULT_MODEL):
    """Baseline (undefended) LLM report."""
    if not llm_available():
        return None
    return chat([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Rule-based risk score: {risk_score(findings)}\n\nFindings:\n{compact(findings)}"},
    ], model)


def rule_report(findings):
    lines = ["# TriageGuard report (rule-based)", ""]
    risk = risk_score(findings)
    lines.append(f"**Risk score:** {risk}/100 ({risk_band(risk)}, CVSS v3.1 bands)")
    ks = key_strength(findings)
    if ks is not None:
        lines.append(f"**Weakest RSA key strength:** {ks}/100")
    lines.append("")
    if rows := risk_breakdown(findings):
        lines += ["Risk is the Dempster-Shafer combination of independent evidence sources, each counted once "
                  "at its strongest finding (severity as CVSS v3.1 band midpoint).", "",
                  "| Evidence source | Findings | Strongest | Mass |", "|---|---|---|---|"]
        lines += [f"| {r['source']} | {r['count']} | [{r['ref']}] | {r['mass']:.2f} |" for r in rows]
        lines.append("")

    def section(title, pred):
        rows = [f for f in findings if pred(f)]
        if rows:
            lines.append(f"## {title}")
            lines.extend(f"- [{f['ref']}] **{f['severity']}** {f['title']}" for f in rows)
            lines.append("")

    section("Cipher identification", lambda f: f["kind"] == "algorithm")
    section("RSA keys", lambda f: f["kind"] in ("rsa_key", "rsa_summary"))
    section("Encrypted / packed regions", lambda f: f["kind"] == "entropy")
    section("Credentials", lambda f: f["module"] == "credentials")
    section("Processes and memory", lambda f: f["module"] == "memory")
    section("Static analysis", lambda f: f["module"] == "static")
    section("Network", lambda f: f["module"] == "network")
    if view := attack.matrix(findings):
        lines += ["## MITRE ATT&CK view", "", "| Tactic | Technique | Findings |", "|---|---|---|"]
        for tactic, techs in view.items():
            for t, refs in techs.items():
                lines.append(f"| {tactic} | {t} {attack.TECHNIQUES[t][0]} | {', '.join(f'[{r}]' for r in refs)} |")
        lines.append("")
    return "\n".join(lines)


def generate(findings, use_llm=True, defended=True):
    if use_llm:
        try:
            if defended:
                from .defences import defended_report
                text = defended_report(findings)
            else:
                text = llm_report(findings)
            if text:
                return text, "llm-defended" if defended else "llm"
        except Exception as e:
            print(f"[report] LLM call failed ({e}); falling back to rule-based report")
    return rule_report(findings), "rules"
