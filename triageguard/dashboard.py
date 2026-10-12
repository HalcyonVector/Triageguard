"""Local dashboard: findings, reports and red-team results in one page.

    python -m triageguard dashboard            # then open http://127.0.0.1:8765

Standard library only, binds to localhost, and serves the page, one JSON document,
and a small job runner behind the "Analyse a dump" button (analyze, export, and an
optional LLM report, run as child processes with their log streamed back). Each analysed dump lives in results/dumps/<name>/ (see export_dump):
meta.json, findings.json, report_rules.md and, when an LLM key was available,
report_llm.md. Red-team rounds come from results/redteam_results.csv (round 1) and
results/redteam_v2/results.csv (round 2), whichever exist.
"""

import csv
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import attack, memory, report
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
    info.update({"findings": len(full), "risk": report.risk_score(full), "compromise": report.compromise_score(full),
                 "exposure": report.exposure_score(full)})
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
    return {"citation_rate": cites["citation_rate"], "claim_lines": cites["claim_lines"],
            "invalid_refs": cites["invalid_refs"], "cited_refs": len(cites["cited_refs"]),
            "llm_risk": defences.stated_risk(body), "rule_risk": report.risk_score(findings),
            "flagged": NOTES in text}


REDTEAM_ROUNDS = [("Round 1", "redteam_results.csv", "6 attacks, before the risk split"),
                  ("Round 2", "redteam_v2/results.csv", "15 attacks incl. adaptive, hardened sanitiser")]


def _csv(path):
    if not Path(path).exists():
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def round_stats(rows):
    """Headline numbers for one red-team round, with the same statistics as summary.md."""
    from .redteam import fisher_exact, wilson
    atk = [r for r in rows if r.get("attack") != "control"]

    def mode(m):
        return [r for r in atk if r.get("mode") == m]

    def wins(rs):
        return sum(r.get("attack_success") == "True" for r in rs)

    def mean(m, key):
        rs = [r for r in rows if r.get("mode") == m and r.get(key) not in (None, "")]
        return sum(float(r[key]) for r in rs) / len(rs) if rs else 0

    def passed(m):
        rs = [r for r in rows if r.get("mode") == m]
        return [sum(r.get("cross_check_passed") == "True" for r in rs), len(rs)]

    b, d = mode("baseline"), mode("defended")
    kb, kd = wins(b), wins(d)
    return {"n": len(b), "asr_base": kb, "asr_def": kd,
            "unflagged": sum(r.get("unflagged_success") == "True" for r in d),
            "wilson_base": wilson(kb, len(b)), "wilson_def": wilson(kd, len(d)),
            "fisher_p": fisher_exact(kb, len(b) - kb, kd, len(d) - kd) if b and d else None,
            "cite_base": mean("baseline", "citation_rate"), "cite_def": mean("defended", "citation_rate"),
            "xcheck_base": passed("baseline"), "xcheck_def": passed("defended"), "reports": len(rows)}


def load(results_dir):
    results = Path(results_dir)
    dumps = []
    for d in sorted((results / "dumps").glob("*")) if (results / "dumps").exists() else []:
        if not (d / "findings.json").exists():
            continue
        meta = json.loads(_read(d / "meta.json") or "{}")
        findings = json.loads(_read(d / "findings.json"))
        for f in findings:
            f["attack"] = attack.techniques(f)
        llm = _read(d / "report_llm.md")
        risk = report.risk_score(findings)
        dumps.append({
            "id": d.name,
            "meta": meta,
            "findings": findings,
            # recomputed from the findings, so an old meta.json can't show stale scores
            "scores": {"risk": risk, "band": report.risk_band(risk), "compromise": report.compromise_score(findings),
                       "exposure": report.exposure_score(findings), "reliability": report.EXPOSURE_RELIABILITY},
            "breakdown": report.risk_breakdown(findings),
            "matrix": attack.matrix(findings),
            "report_llm": llm,
            "llm_check": llm_check(llm, findings) if llm else None,
            "report_rules": _read(d / "report_rules.md"),
        })
    dumps.sort(key=lambda x: x["meta"].get("order", 99))
    rounds = []
    for name, rel, note in REDTEAM_ROUNDS:
        rows = _csv(results / rel)
        if rows:
            rounds.append({"name": name, "note": note, "rows": rows, "stats": round_stats(rows)})
    return {"dumps": dumps, "rounds": rounds, "redteam": rounds[-1]["rows"] if rounds else [],
            "techniques": {k: list(v) for k, v in attack.TECHNIQUES.items()}}


# ------------------------------------------------------------- analyse-a-dump jobs
JOBS = {}
_LOCK = threading.Lock()
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")


def _slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "dump"


def env_check():
    """What the Analyse button can use on this machine, checked with the interpreter jobs run on."""
    py = memory.venv_python()
    probe = "import importlib.util as u; print(','.join(m for m in ('pefile', 'pyshark') if not u.find_spec(m)))"
    try:
        missing = subprocess.run([py, "-c", probe], capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        missing = "pefile,pyshark"
    return {"llm": report.llm_available(), "volatility": bool(memory._vol()),
            "missing": [m for m in missing.split(",") if m], "tshark": bool(shutil.which("tshark")
            or Path(r"C:\Program Files\Wireshark\tshark.exe").is_file()), "python": py}


def start_job(req, results_dir):
    """Validate a request from the dashboard form and start the pipeline in the background.
    Returns (job id, None) or (None, error message for the user)."""
    dump = Path(str(req.get("dump", "")).strip().strip('"')).expanduser()
    pcap = str(req.get("pcap", "")).strip().strip('"')
    if not dump.is_file():
        return None, f"No file at {dump}. Paste the full path to the memory image."
    if pcap and not Path(pcap).expanduser().is_file():
        return None, f"No file at {pcap}. Leave the pcap empty if you don't have one."
    name = str(req.get("name") or _slug(dump.stem)).strip().lower()
    if not NAME_RE.match(name):
        return None, "The short name may use lowercase letters, digits, - and _ only."
    results = Path(results_dir).resolve()
    if (results / "dumps" / name).exists():
        return None, f"results/dumps/{name} already exists. Pick another short name."
    with _LOCK:
        if any(j["status"] == "running" for j in JOBS.values()):
            return None, "Another analysis is still running. Wait for it to finish."
        job_id = f"{name}-{int(time.time())}"
        JOBS[job_id] = {"id": job_id, "name": name, "status": "running", "stage": "Starting", "log": [], "error": ""}
    stamp = time.strftime("%Y%m%d-%H%M%S")
    db = dump.parent / f"{name}_{stamp}.db"  # fresh database, so the export always reads run 1
    out = dump.parent / f"out_{name}_{stamp}"
    n = dump.stat().st_size
    size = f"{n / 2**30:.1f} GB" if n >= 2**30 else f"{n / 2**20:.0f} MB"
    py = [memory.venv_python(), "-u", "-m", "triageguard"]
    steps = [("Analysing", py + ["analyze", str(dump), "--db", str(db), "--out", str(out), "--no-llm"] + (["--pcap", pcap] if pcap else [])),
             ("Exporting", py + ["export", str(db), name, "--results", str(results), "--title", str(req.get("title") or dump.stem),
                                 "--os", str(req.get("os") or ""), "--source", str(dump.name), "--size", size,
                                 "--pcap", Path(pcap).name if pcap else "",
                                 "--order", str(len(list((results / "dumps").glob("*/meta.json"))) + 1)])]
    if req.get("llm") and report.llm_available():
        steps.append(("Writing the LLM report", py + ["report", str(db), "--out", str(results / "dumps" / name / "report_llm.md")]))
    threading.Thread(target=_run_job, args=(job_id, steps), daemon=True).start()
    return job_id, None


def _run_job(job_id, steps):
    job = JOBS[job_id]
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    try:
        for label, cmd in steps:
            job["stage"] = label
            job["log"].append(f"$ triageguard {' '.join(cmd[4:6])} ...")
            proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace")
            for line in proc.stdout:
                job["log"].append(line.rstrip())
                del job["log"][:-400]
            if proc.wait() != 0:
                raise RuntimeError(f"{label} failed (exit {proc.returncode}); see the log above")
        job["status"], job["stage"] = "done", "Done"
    except Exception as e:  # shown to the user in the dialog
        job["status"], job["error"] = "failed", str(e)


def serve(port=8765, results_dir="results", open_browser=True):
    origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        def _send(self, body, ctype, code=200):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _json(self, obj, code=200):
            self._send(json.dumps(obj), "application/json; charset=utf-8", code)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(_read(PAGE), "text/html; charset=utf-8")
            elif self.path == "/api/data":
                self._json(load(results_dir))
            elif self.path == "/api/env":
                self._json(env_check())
            elif self.path.startswith("/api/jobs/"):
                job = JOBS.get(self.path.rsplit("/", 1)[-1])
                self._json(job or {"error": "no such job"}, 200 if job else 404)
            else:
                self.send_error(404)

        def do_POST(self):
            # only the dashboard itself may start jobs: a JSON body forces a CORS preflight
            # (which this server never answers), and the Origin check stops other pages
            if self.path != "/api/analyze" or "application/json" not in self.headers.get("Content-Type", "") \
                    or self.headers.get("Origin", next(iter(origins))) not in origins:
                self.send_error(403)
                return
            try:
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)) or 2) or "{}")
            except ValueError:
                return self._json({"error": "Bad request"}, 400)
            job_id, err = start_job(req, results_dir)
            self._json({"error": err} if err else {"job": job_id}, 400 if err else 200)

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
