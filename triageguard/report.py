"""Report generation. The LLM only ever sees the structured findings from
SQLite (never raw dump bytes) and is asked to cite finding ids like [F3].

Without GROQ_API_KEY, a rule-based report is produced instead, which is also
the baseline the LLM output can be cross-checked against later.
"""

import json
import os
import urllib.request

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = os.environ.get("TRIAGEGUARD_MODEL", "llama-3.3-70b-versatile")
SEV_POINTS = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}

SYSTEM_PROMPT = """You are a malware triage analyst. You receive structured findings from a memory
forensics and crypto analysis pipeline. Write a concise incident report in Markdown with sections:
Summary, Cryptography (algorithms with confidence, key strength), Credentials, Processes and Network,
Risk score (0-100) with justification, Recommendations.
Cite the finding id in square brackets, e.g. [F3], after every factual claim."""


def risk_score(findings):
    """Rule-based risk score: sum of severity points, capped at 100."""
    return min(100, sum(SEV_POINTS.get(f["severity"], 0) for f in findings))


def key_strength(findings):
    scores = [f["data"]["strength"] for f in findings if f["kind"] == "rsa_key"]
    return min(scores) if scores else None


def compact(findings, max_chars=24_000):
    """Trim findings to fit a free-tier context window."""
    out = []
    for f in findings:
        d = json.dumps(f["data"], default=str)
        if len(d) > 800:
            d = d[:800] + "...(truncated)"
        out.append(f"[{f['ref']}] ({f['module']}/{f['kind']}, {f['severity']}) {f['title']} | {d}")
    text = "\n".join(out)
    return text[:max_chars]


def llm_report(findings, model=DEFAULT_MODEL):
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        return None
    body = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Rule-based risk score: {risk_score(findings)}\n\nFindings:\n{compact(findings)}"},
        ],
    }
    req = urllib.request.Request(GROQ_URL, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                                          "User-Agent": "triageguard"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)["choices"][0]["message"]["content"]


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
    section("RSA keys", lambda f: f["kind"] == "rsa_key")
    section("Encrypted / packed regions", lambda f: f["kind"] == "entropy")
    section("Credentials", lambda f: f["module"] == "credentials")
    section("Processes and memory", lambda f: f["module"] == "memory")
    section("Static analysis", lambda f: f["module"] == "static")
    section("Network", lambda f: f["module"] == "network")
    return "\n".join(lines)


def generate(findings, use_llm=True):
    if use_llm:
        try:
            text = llm_report(findings)
            if text:
                return text, "llm"
        except Exception as e:
            print(f"[report] LLM call failed ({e}); falling back to rule-based report")
    return rule_report(findings), "rules"
