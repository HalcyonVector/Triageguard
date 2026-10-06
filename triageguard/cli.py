import argparse
import json
import os
from pathlib import Path

from . import crypto, pipeline, redteam


def main(argv=None):
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
    r.add_argument("--model", help="LLM model id (default: TRIAGEGUARD_MODEL or openai/gpt-oss-120b)")

    d = sub.add_parser("dashboard", help="open the local results dashboard")
    d.add_argument("--port", type=int, default=8765)
    d.add_argument("--results", default="results", help="folder with the saved dumps and red-team CSV")
    d.add_argument("--no-browser", action="store_true")

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

    g = sub.add_parser("report", help="(re)generate the LLM report for an analysed dump from its database")
    g.add_argument("db")
    g.add_argument("--run", type=int, default=1)
    g.add_argument("--out", required=True, help="markdown file to write, e.g. results/dumps/win10/report_llm.md")
    g.add_argument("--undefended", action="store_true", help="baseline prompt without defences")
    g.add_argument("--model", help="LLM model id")

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
    elif args.cmd == "dashboard":
        from . import dashboard
        dashboard.serve(args.port, args.results, not args.no_browser)
    elif args.cmd == "export":
        from . import dashboard
        meta = {k: getattr(args, k) for k in ("title", "os", "source", "size", "pcap", "order")}
        out = Path(args.results) / "dumps" / args.name
        print(json.dumps(dashboard.export_dump(args.db, out, args.run, meta)), "->", out)
    elif args.cmd == "report":
        from . import report
        from .store import Store
        store = Store(args.db)
        try:
            findings = store.findings(args.run)
        finally:
            store.close()
        text, mode = report.generate(findings, True, not args.undefended)
        if mode == "rules":  # the LLM call failed; keep any existing report rather than overwrite it
            raise SystemExit("LLM report failed (see the message above), nothing written")
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(mode, "->", args.out)
    elif args.cmd == "redteam":
        print(redteam.run(args.trials, args.dry_run, args.out, rescore=args.rescore))


if __name__ == "__main__":
    main()
