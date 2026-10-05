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

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# llama-3.3-70b-versatile was shut down by Groq on 2026-08-16 (404 model not found);
# gpt-oss-120b is their listed replacement. Override with TRIAGEGUARD_MODEL or --model.
FALLBACK_MODEL = "openai/gpt-oss-120b"
DEFAULT_MODEL = None  # resolved at call time so --model / TRIAGEGUARD_MODEL set after import still apply
MAX_RETRIES = 6
MAX_WAIT = 120  # seconds; longer waits mean the daily quota is gone
SEV_POINTS = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}

SYSTEM_PROMPT = """You are a malware triage analyst. You receive structured findings from a memory
forensics and crypto analysis pipeline. Write a concise incident report in Markdown with sections:
Summary, Cryptography (algorithms with confidence, key strength), Credentials, Processes and Network,
Risk score (0-100) with justification, Recommendations.
Cite the finding id in square brackets, e.g. [F3], after every factual claim."""


# max findings counted per severity, so a pile of low-severity context (e.g. the
# certificate store in a full dump) cannot add up to a critical score on its own
SEV_CAP = {"critical": 4, "high": 4, "medium": 4, "low": 5}


def risk_score(findings):
    """Rule-based risk score: severity points with a per-tier cap, at most 100."""
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return min(100, sum(SEV_POINTS.get(s, 0) * min(n, SEV_CAP.get(s, 0)) for s, n in counts.items()))


def key_strength(findings):
    scores = [f["data"]["strength"] for f in findings if f["kind"] == "rsa_key" and f["data"].get("strength") is not None]
    return min(scores) if scores else None


def compact(findings, max_chars=24_000):
    """Trim findings to fit a free-tier context window."""
    out = []
    # most severe first, so truncation drops info rows rather than the incident
    order = ["critical", "high", "medium", "low", "info"]
    for f in sorted(findings, key=lambda f: order.index(f["severity"]) if f["severity"] in order else len(order)):
        d = json.dumps(f["data"], default=str)
        if len(d) > 400:  # free tier is 8k tokens/min, keep each call small
            d = d[:400] + "...(truncated)"
        out.append(f"[{f['ref']}] ({f['module']}/{f['kind']}, {f['severity']}) {f['title']} | {d}")
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
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers=headers)
    for attempt in range(MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)["choices"][0]["message"]["content"]
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
    lines.append(f"**Risk score:** {risk_score(findings)}/100")
    ks = key_strength(findings)
    if ks is not None:
        lines.append(f"**Weakest RSA key strength:** {ks}/100")
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
