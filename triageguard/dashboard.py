"""Local dashboard: findings, reports and red-team results in one page.

    python -m triageguard dashboard            # then open http://127.0.0.1:8765

Standard library only, binds to localhost, and serves two things: the page and one
JSON document. Findings come from the SQLite db when it exists, otherwise from the
snapshot in results/real_dump_findings.json, so it also works on a fresh clone.
"""

import csv
import json
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .store import Store

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "dashboard" / "index.html"
LIST_FIELDS = ("ref", "module", "kind", "title", "severity", "source", "location")


def _read(path):
    p = Path(path)
    return p.read_text(encoding="utf-8") if p.exists() else ""


def snapshot_findings(db_path, run_id=1):
    """Findings without their bulky JSON detail, as the dashboard needs them."""
    store = Store(db_path)
    try:
        rows = store.findings(run_id)
    finally:
        store.close()
    return [{k: f[k] for k in LIST_FIELDS} for f in rows]


def load(results_dir, db_path):
    results = Path(results_dir)
    findings, source = [], "none"
    if Path(db_path).exists():
        try:
            findings, source = snapshot_findings(db_path), f"database {db_path}"
        except Exception:
            findings = []
    if not findings and (results / "real_dump_findings.json").exists():
        findings = json.loads(_read(results / "real_dump_findings.json"))
        source = "results/real_dump_findings.json"
    redteam = []
    if (results / "redteam_results.csv").exists():
        with open(results / "redteam_results.csv", newline="", encoding="utf-8") as f:
            redteam = list(csv.DictReader(f))
    return {
        "findings": findings,
        "findings_source": source,
        "report_llm": _read(results / "real_dump_report_llm.md"),
        "report_rules": _read(results / "real_dump_report_rules.md"),
        "redteam": redteam,
    }


def serve(port=8765, results_dir="results", db_path="triageguard.db", open_browser=True):
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
                self._send(json.dumps(load(results_dir, db_path)), "application/json; charset=utf-8")
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
