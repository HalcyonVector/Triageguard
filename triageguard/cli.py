import argparse
import json
import os

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
    elif args.cmd == "redteam":
        print(redteam.run(args.trials, args.dry_run, args.out, rescore=args.rescore))


if __name__ == "__main__":
    main()
