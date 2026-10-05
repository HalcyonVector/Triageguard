"""Runs every stage and records findings in SQLite."""

from pathlib import Path

from . import credentials, memory, network, report, static
from . import crypto
from .store import Store

SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _worst(sevs):
    return max(sevs, key=SEV_ORDER.index, default="info")


def record_crypto(db, path, result, is_full_dump):
    for a in result["algorithms"]:
        strong = a["confidence"] >= 70 and a["basis"] == "implementation constants"
        # crypto libraries are loaded in almost every process, so in a full dump
        # this is context; in an injected region or dropped binary it matters
        sev = "medium" if strong and not is_full_dump else "info"
        db.add("crypto", "algorithm", f"{a['algorithm']} identified ({a['confidence']}%, {a['basis']}) in {Path(path).name}",
               a, sev, path, a["evidence"][0]["offsets"][0] if a["evidence"] else "")
    for k in result["rsa_keys"]:
        sev = _worst([i["severity"] for i in k["issues"]])
        issues = "; ".join(i["test"] for i in k["issues"]) or "no weaknesses found"
        db.add("rsa", "rsa_key", f"RSA-{k['bits']} key e={k['e']} ({k['format']}), strength {k['strength']}/100: {issues}",
               k, sev, path, k["offset"])
    regions = result["high_entropy_regions"]
    if regions:
        total = sum(r["size"] for r in regions)
        db.add("crypto", "entropy", f"{len(regions)} high-entropy regions ({total} bytes) in {Path(path).name}",
               {"regions": regions[:20]}, "info", path, regions[0]["start"])


def run(dump, pcap=None, binaries=(), db_path="triageguard.db", workdir="out", use_llm=True, defended=True, memory_stage=True, log=print):
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    db = Store(db_path)
    run_id = db.start_run(dump, pcap)

    log("[1/6] Volatility3 extraction")
    vol, dumped = memory.extract(dump, workdir / "malfind") if memory_stage else ({}, [])
    for label, rows in vol.items():
        if isinstance(rows, dict) and "skipped" in rows:
            log(f"      {label}: skipped ({rows['skipped']})")
            continue
        db.add("memory", label, f"{label}: {len(rows)} rows", {"rows": rows[:200]}, "info", dump)
    for flag in memory.suspicious_processes(vol):
        db.add("memory", "suspicious_process", f"PID {flag['pid']} {flag['process']}: {flag['reason']}", flag, "high", dump, flag["pid"])

    log("[2/6] Static analysis of binaries")
    for b in [*binaries, *dumped]:
        s = static.analyse(b)
        pe = s["pe"] if "error" not in s["pe"] else {}
        sev = "high" if s["yara"] else "medium" if (pe.get("crypto_imports") or pe.get("packed_sections")) else "info"
        db.add("static", "binary", f"{Path(b).name}: entropy {s['entropy']}, crypto imports {pe.get('crypto_imports', [])}, yara {s['yara']}",
               s, sev, b)

    log("[3/6] Crypto analysis")
    record_crypto(db, dump, crypto.analyse(dump), is_full_dump=True)
    for b in [*binaries, *dumped]:
        record_crypto(db, b, crypto.analyse(b), is_full_dump=False)

    log("[4/6] Credential scan")
    for c in credentials.scan(dump):
        issues = (c["decoded"] or {}).get("issues", [])
        sev = "high" if any("alg=none" in i for i in issues) else "medium"
        db.add("credentials", c["type"], f"{c['type']} {c['preview']}" + (f": {'; '.join(issues)}" if issues else ""),
               c, sev, dump, c["offset"])

    log("[5/6] PCAP")
    if pcap:
        net = network.parse(pcap)
        if "skipped" in net:
            log(f"      skipped ({net['skipped']})")
        else:
            sev = "medium" if net["weak_tls"] else "info"
            db.add("network", "pcap_summary",
                   f"{len(net['conversations'])} conversations, TLS SNI {net['tls_sni'][:5]}, weak TLS {list(net['weak_tls'])}",
                   net, sev, pcap)
    else:
        log("      no pcap given")
    db.commit()

    log("[6/6] Report")
    findings = db.findings()
    text, mode = report.generate(findings, use_llm, defended)
    out = workdir / f"report_run{run_id}.md"
    out.write_text(text)
    return {"run_id": run_id, "findings": len(findings), "report": str(out), "report_mode": mode,
            "risk_score": report.risk_score(findings)}
