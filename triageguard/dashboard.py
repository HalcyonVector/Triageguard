"""Local dashboard: findings, reports and red-team results in one page.

    python -m triageguard dashboard            # then open http://127.0.0.1:8765

Standard library only, binds to localhost, and serves two things: the page and one
JSON document. Each analysed dump lives in results/dumps/<name>/ (see export_dump):
meta.json, findings.json, report_rules.md and, when an LLM key was available,
report_llm.md. The red-team table comes from results/redteam_results.csv.
"""

import csv
import json
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import report
from .store import Store

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "dashboard" / "index.html"
LIST_FIELDS = ("ref", "module", "kind", "title", "severity", "source", "location")


def _read(path):
    p = Path(path)
    return p.read_text(encoding="utf-8") if p.exists() else ""


def export_dump(db_path, out_dir, run_id=1, meta=None):
    """Write one dump's results as plain files the dashboard (and git) can use.

    Findings are saved without their bulky JSON detail; the rule-based report is
    regenerated from the full findings so it always matches the database."""
    store = Store(db_path)
    try:
        full = store.findings(run_id)
    finally:
        store.close()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    slim = [{k: f[k] for k in LIST_FIELDS} for f in full]
    (out / "findings.json").write_text(json.dumps(slim, indent=1), encoding="utf-8")
    (out / "report_rules.md").write_text(report.rule_report(full), encoding="utf-8")
    info = dict(meta or {})
    info.update({"findings": len(full), "risk": report.risk_score(full)})
    (out / "meta.json").write_text(json.dumps(info, indent=1), encoding="utf-8")
    return info


NOTES = "\n\n## Validation notes (automatic)"


def llm_check(text, findings):
    """Citation coverage and risk score of a saved LLM report, for the dashboard.

    Uses only the slim findings (ref, severity), so it covers the citation and risk
    checks, not the algorithm check that needs each finding's full detail."""
    from . import defences
    body = text.split(NOTES)[0]
    cites = defences.check_citations(body, findings)
    m = defences.RISK_RE.search(body)
    return {"citation_rate": cites["citation_rate"], "claim_lines": cites["claim_lines"],
            "invalid_refs": cites["invalid_refs"], "cited_refs": len(cites["cited_refs"]),
            "llm_risk": int(m.group(1)) if m else None, "rule_risk": report.risk_score(findings),
            "flagged": NOTES in text}


def load(results_dir):
    results = Path(results_dir)
    dumps = []
    for d in sorted((results / "dumps").glob("*")) if (results / "dumps").exists() else []:
        if not (d / "findings.json").exists():
            continue
        meta = json.loads(_read(d / "meta.json") or "{}")
        findings = json.loads(_read(d / "findings.json"))
        llm = _read(d / "report_llm.md")
        dumps.append({
            "id": d.name,
            "meta": meta,
            "findings": findings,
            "report_llm": llm,
            "llm_check": llm_check(llm, findings) if llm else None,
            "report_rules": _read(d / "report_rules.md"),
        })
    dumps.sort(key=lambda x: x["meta"].get("order", 99))
    redteam = []
    if (results / "redteam_results.csv").exists():
        with open(results / "redteam_results.csv", newline="", encoding="utf-8") as f:
            redteam = list(csv.DictReader(f))
    return {"dumps": dumps, "redteam": redteam}


def serve(port=8765, results_dir="results", open_browser=True):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, body, ctype):
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(_read(PAGE), "text/html; charset=utf-8")
            elif self.path == "/api/data":
                self._send(json.dumps(load(results_dir)), "application/json; charset=utf-8")
            else:
                self.send_error(404)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"TriageGuard dashboard at {url} (Ctrl+C to stop)")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
