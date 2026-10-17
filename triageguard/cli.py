import argparse
import json
import os
from pathlib import Path

from . import crypto, pipeline, redteam


def load_env_file(path=Path(__file__).resolve().parents[1] / ".env"):
    """Read KEY=value lines from the project's .env (git-ignored) into the environment,
    so the Groq key does not have to be set by hand in every new terminal."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        key, sep, val = line.strip().partition("=")
        if sep and key and not key.startswith("#"):
            os.environ.setdefault(key.strip(), val.strip().strip('"'))


def update(root=Path(__file__).resolve().parents[1]):
    """git pull for the launcher. Files that differ from the repo only in line endings
    (Windows editors and copies turn LF into CRLF) would block the pull, so they are
    restored first; real local edits are left alone and reported."""
    import subprocess

    def git(*a):
        return subprocess.run(["git", *a], cwd=root, capture_output=True, text=True)

    changed = git("diff", "--name-only").stdout.split()
    for f in changed:
        if git("diff", "--ignore-cr-at-eol", "--quiet", "--", f).returncode == 0:
            git("checkout", "--", f)
            print(f"restored {f} (only line endings differed)")
    branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    r = git("pull", "--ff-only", "origin", branch)
    print((r.stdout + r.stderr).strip())
    if r.returncode:
        print("Could not update the code. Run 'git status' to see which local change is in the way.")
    return r.returncode


def main(argv=None):
    load_env_file()
    ap = argparse.ArgumentParser(prog="triageguard", description="Memory forensics + crypto malware triage")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="run the full pipeline on a memory dump")
    a.add_argument("dump")
    a.add_argument("--pcap")
    a.add_argument("--binary", action="append", default=[], help="extra suspicious binary (repeatable)")
    a.add_argument("--db", default="triageguard.db")
    a.add_argument("--out", default="out")
    a.add_argument("--no-llm", action="store_true", help="rule-based report only")
    a.add_argument("--undefended", action="store_true", help="baseline LLM report without defences")
    a.add_argument("--model", help="LLM model id (default: TRIAGEGUARD_MODEL or openai/gpt-oss-120b)")

    c = sub.add_parser("crypto", help="crypto analysis only, on any file")
    c.add_argument("file")

    r = sub.add_parser("redteam", help="attack the LLM report and measure baseline vs defended")
    r.add_argument("--trials", type=int, default=3)
    r.add_argument("--dry-run", action="store_true", help="no LLM: check payload delivery and sanitiser only")
    r.add_argument("--rescore", action="store_true", help="no LLM: recompute the summary from reports already saved in --out")
    r.add_argument("--out", default="redteam_results")
    r.add_argument("--only", nargs="+", help="run only these attacks (names from the summary table)")
    r.add_argument("--model", help="LLM model id (default: TRIAGEGUARD_MODEL or openai/gpt-oss-120b)")

    d = sub.add_parser("dashboard", help="open the local results dashboard")
    d.add_argument("--port", type=int, default=8765)
    d.add_argument("--results", default="results", help="folder with the saved dumps and red-team CSV")
    d.add_argument("--no-browser", action="store_true")

    rs = sub.add_parser("rescore-results", help="recompute scores and rule reports of every exported dump after a scoring change")
    rs.add_argument("--results", default="results")
    e = sub.add_parser("export", help="save one analysed dump's results under results/dumps/<name> for the dashboard")
    e.add_argument("db")
    e.add_argument("name", help="folder name, e.g. win10")
    e.add_argument("--run", type=int, default=1)
    e.add_argument("--results", default="results")
    e.add_argument("--title", default="")
    e.add_argument("--os", default="")
    e.add_argument("--source", default="")
    e.add_argument("--size", default="")
    e.add_argument("--pcap", default="")
    e.add_argument("--order", type=int, default=99, help="position in the dashboard")
    e.add_argument("--clean", action="store_true", help="drop an older LLM report for this name first")
    b = sub.add_parser("benchmark", help="ground-truth test: processes with known ciphers and synthetic keys (Linux/WSL)")
    b.add_argument("--trials", type=int, default=5)
    b.add_argument("--out", default="results/benchmark")

    ck = sub.add_parser("check", help="sanity-check an analysed dump: missing stages, noisy detectors")
    ck.add_argument("db")
    ck.add_argument("--run", type=int, default=0, help="run id (default: the latest)")

    sub.add_parser("update", help="pull the latest code, first dropping local changes that are only line endings")

    g = sub.add_parser("report", help="(re)generate the LLM report for an analysed dump from its database")
    g.add_argument("db")
    g.add_argument("--run", type=int, default=1)
    g.add_argument("--out", required=True, help="markdown file to write, e.g. results/dumps/win10/report_llm.md")
    g.add_argument("--undefended", action="store_true", help="baseline prompt without defences")
    g.add_argument("--model", help="LLM model id")
    g.add_argument("--findings", help="results/dumps/<name>/findings.json: use its (rescored) severities and titles")

    args = ap.parse_args(argv)
    if getattr(args, "model", None):
        os.environ["TRIAGEGUARD_MODEL"] = args.model
    if args.cmd == "analyze":
        res = pipeline.run(args.dump, args.pcap, args.binary, args.db, args.out,
                           use_llm=not args.no_llm, defended=not args.undefended)
        print(json.dumps(res, indent=2))
    elif args.cmd == "crypto":
        r = crypto.analyse(args.file)
        for alg in r["algorithms"]:
            print(f"{alg['algorithm']:18} {alg['confidence']:5.1f}%  {alg['basis']}")
        for k in r["rsa_keys"]:
            print(f"RSA-{k['bits']} e={k['e']} strength={k['strength']} issues={[i['test'] for i in k['issues']]}")
        print(f"{len(r['high_entropy_regions'])} high-entropy regions")
    elif args.cmd == "rescore-results":
        from . import dashboard
        print(json.dumps(dashboard.rescore(args.results)))
    elif args.cmd == "benchmark":
        from . import benchmark
        print(json.dumps(benchmark.run(args.trials, args.out), indent=1))
    elif args.cmd == "check":
        from . import health
        from .store import Store
        store = Store(args.db)
        run = args.run or store.db.execute("select max(id) from runs").fetchone()[0]
        print(f"check of {args.db} run {run}:")
        raise SystemExit(health.print_check(store.findings(run)))
    elif args.cmd == "update":
        raise SystemExit(update())
    elif args.cmd == "dashboard":
        from . import dashboard
        dashboard.serve(args.port, args.results, not args.no_browser)
    elif args.cmd == "export":
        from . import dashboard
        meta = {k: getattr(args, k) for k in ("title", "os", "source", "size", "pcap", "order")}
        out = Path(args.results) / "dumps" / args.name
        if args.clean:
            (out / "report_llm.md").unlink(missing_ok=True)
        print(json.dumps(dashboard.export_dump(args.db, out, args.run, meta)), "->", out)
    elif args.cmd == "report":
        from . import report
        from .store import Store
        if not report.llm_available():
            # the key lives only in the terminal window where it was set, so a new window has none
            raise SystemExit('No LLM key found. Put GROQ_API_KEY=your key in a file called .env in the project folder.')
        store = Store(args.db)
        try:
            findings = store.findings(args.run)
        finally:
            store.close()
        if args.findings:
            # findings.json may have been rescored after the database was written
            fresh = {f["ref"]: f for f in json.loads(Path(args.findings).read_text(encoding="utf-8-sig"))}
            for f in findings:
                new = fresh.get(f["ref"])
                if new and (new["severity"], new["title"]) != (f["severity"], f["title"]):
                    f["severity"], f["title"] = new["severity"], new["title"]
                    if isinstance(f.get("data"), dict) and "reason" in f["data"] and ": " in new["title"]:
                        f["data"].update(severity=new["severity"], reason=new["title"].split(": ", 1)[1])
        text, mode = report.generate(findings, True, not args.undefended)
        if mode == "rules":  # the LLM call failed; keep any existing report rather than overwrite it
            raise SystemExit("LLM report failed (see the message above), nothing written")
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(mode, "->", args.out)
    elif args.cmd == "redteam":
        try:
            print(redteam.run(args.trials, args.dry_run, args.out, rescore=args.rescore, only=args.only))
        except RuntimeError as e:
            if "429" not in str(e):
                raise
            # finished trials are already in progress.jsonl, so this is a pause, not a failure
            raise SystemExit(f"Groq rate limit hit, stopping here. Finished trials are saved in {args.out}/progress.jsonl.\n"
                             "Run the same command again later (or with another key) to carry on.\n" + str(e)[-200:])


if __name__ == "__main__":
    main()
