"""Runs every stage and records findings in SQLite."""

from pathlib import Path

from . import campaign, credentials, memory, network, report, static
from . import crypto
from .crypto import aes_keyfind, key_recovery, rsa_weak
from .store import Store

SEV_ORDER = ["info", "low", "medium", "high", "critical"]
# one finding per distinct AES key up to this many; the rest are summed into one line
MAX_AES_FINDINGS = 10


def _worst(sevs):
    return max(sevs, key=SEV_ORDER.index, default="info")


MAX_PUBLIC_RECOVERY = 8  # public keys tried per process; a browser can hold hundreds of certificates


def record_crypto(db, path, result, is_full_dump):
    for a in result["algorithms"]:
        strong = a["confidence"] >= 70 and a["basis"] == "implementation constants"
        # crypto libraries are loaded in almost every process, so in a full dump
        # this is context; in an injected region or dropped binary it matters
        sev = "medium" if strong and not is_full_dump else "info"
        db.add("crypto", "algorithm", f"{a['algorithm']} identified ({a['confidence']}%, {a['basis']}) in {Path(path).name}",
               a, sev, path, a["evidence"][0]["offsets"][0] if a["evidence"] else "")
    clean, corrupt = [], []
    for k in result["rsa_keys"]:
        if k.get("corrupt"):
            corrupt.append(k)
            continue
        if not k["issues"] and is_full_dump:
            clean.append(k)
            continue
        sev = _worst([i["severity"] for i in k["issues"]])
        if is_full_dump and not k["factored"] and sev in ("high", "medium"):
            # a full dump holds the whole certificate store (old 1024-bit roots, e=3
            # legacy certs), so size/exponent alone is context, not an incident
            sev = "low"
        issues = "; ".join(i["test"] for i in k["issues"]) or "no weaknesses found"
        db.add("rsa", "rsa_key", f"RSA-{k['bits']} key e={k['e']} ({k['format']}), strength {k['strength']}/100 "
               f"({k['security_bits']}-bit security, {k['nist_status']}): {issues}",
               k, sev, path, k["offset"])
    if clean or corrupt:
        db.add("rsa", "rsa_summary",
               f"{len(clean)} RSA keys with no weaknesses and {len(corrupt)} corrupt key-like structures in {Path(path).name}",
               {"clean": [{x: k[x] for x in ("bits", "e", "format", "offset", "fingerprint")} for k in clean[:50]],
                "corrupt": [{x: k[x] for x in ("bits", "e", "format", "offset")} for k in corrupt[:20]]},
               "info", path)
    tor = result.get("tor_keys") or {}
    if tor.get("count", 0) >= 10:
        db.add("memory", "tor_client",
               f"Tor directory data in {Path(path).name}: {tor['count']} relay onion keys, so a Tor client ran on this host "
               "(command and control over Tor)", tor, "medium", path, tor["first_offset"])
    regions = result["high_entropy_regions"]
    if regions:
        total = sum(r["size"] for r in regions)
        db.add("crypto", "entropy", f"{len(regions)} high-entropy regions ({total} bytes) in {Path(path).name}",
               {"regions": regions[:20]}, "info", path, regions[0]["start"])


def record_aes_keys(db, keys):
    """One finding per distinct AES key. A key found in several processes is mapped from a
    shared image (a library's built-in test key, for example), not a key one program made."""
    own = [k for k in keys.values() if len(k["procs"]) == 1]
    for k in own[:MAX_AES_FINDINGS]:
        (pid, p), = k["procs"].items()
        db.add("crypto", "aes_key",
               f"AES-{k['bits']} key of {p['name']} (PID {pid}) recovered from its expanded key schedule at {p['offset']}"
               + (f" ({p['copies']} copies)" if p["copies"] > 1 else "") + f", key id {k['key_id']}: data encrypted under this key can be decrypted",
               {"bits": k["bits"], "layout": k["layout"], "key_id": k["key_id"], "pid": pid, "process": p["name"], "copies": p["copies"]},
               "info", p["file"], p["offset"])
    if len(own) > MAX_AES_FINDINGS:
        db.add("crypto", "aes_key", f"{len(own) - MAX_AES_FINDINGS} more AES key(s) recovered from key schedules",
               {"keys": [k["key_id"] for k in own[MAX_AES_FINDINGS:]]}, "info")
    for k in keys.values():
        if len(k["procs"]) > 1:
            names = ", ".join(f"{p['name']} ({pid})" for pid, p in k["procs"].items())
            db.add("crypto", "aes_shared",
                   f"AES-{k['bits']} key schedule identical in {len(k['procs'])} processes ({names}), key id {k['key_id']}: "
                   "mapped from a shared library, so likely a built-in constant rather than a key the malware made",
                   {"bits": k["bits"], "key_id": k["key_id"], "pids": list(k["procs"])}, "info")


def run(dump, pcap=None, binaries=(), db_path="triageguard.db", workdir="out", use_llm=True, defended=True, memory_stage=True, log=print):
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    db = Store(db_path)
    run_id = db.start_run(dump, pcap)

    log("[1/6] Volatility3 extraction")
    vol, dumped = memory.extract(dump, workdir / "malfind") if memory_stage else ({}, [])
    for label, rows in vol.items():
        if label.startswith("_"):
            continue
        if isinstance(rows, dict) and "skipped" in rows:
            log(f"      {label}: skipped ({rows['skipped']})")
            # kept as a finding so `triageguard check` and the report can say what is missing
            db.add("memory", "skipped", f"{label}: skipped ({str(rows['skipped'])[:200]})",
                   {"stage": label, "reason": str(rows["skipped"])}, "info", dump)
            continue
        keep = rows[:200]
        if label == "network":  # every connection to a public address, which campaign linking compares
            keep += [r for r in rows[200:] if isinstance(r, dict) and campaign.public_ip(r.get("ForeignAddr"))]
        db.add("memory", label, f"{label}: {len(rows)} rows", {"rows": keep}, "info", dump)
    for flag in memory.suspicious_processes(vol):
        db.add("memory", "suspicious_process", f"PID {flag['pid']} {flag['process']}: {flag['reason']}", flag, flag["severity"], dump, flag["pid"])

    log("[2/6] Static analysis of binaries")
    blocked = set()
    for b in [*binaries, *dumped]:
        try:
            s = static.analyse(b)
        except OSError as e:
            # an antivirus on the analysis machine refuses to open extracted malware; that
            # is itself a strong signal, so record it and keep going
            blocked.add(b)
            db.add("static", "blocked", f"{Path(b).name}: could not be read ({str(e).strip()[:120]}); on Windows this usually means antivirus blocked it as malware",
                   {"file": str(b), "error": str(e)}, "high", b)
            continue
        pe = s["pe"] if "error" not in s["pe"] else {}
        sev = "high" if s["yara"] else "medium" if (pe.get("crypto_imports") or pe.get("packed_sections")) else "info"
        db.add("static", "binary", f"{Path(b).name}: entropy {s['entropy']}, crypto imports {pe.get('crypto_imports', [])}, yara {s['yara']}",
               s, sev, b)

    log("[3/6] Crypto analysis")
    full = crypto.analyse(dump)
    record_crypto(db, dump, full, is_full_dump=True)
    reported = {k["fingerprint"] for k in full["rsa_keys"] if k["issues"]}
    for b in [*binaries, *dumped]:
        if b not in blocked:
            record_crypto(db, b, crypto.analyse(b), is_full_dump=False)

    aes_keys = {}
    for pid, name in memory.keyscan_targets(vol) if memory_stage else []:
        log(f"      key recovery: dumping {name} (PID {pid})")
        pdump = memory.dump_process(dump, pid, workdir / "procs", vol.get("_os", "windows"))
        if not pdump:
            continue
        with open(pdump, "rb") as f:
            data = f.read()
        keys = rsa_weak.extract_keys(data, source=str(pdump))
        hits = key_recovery.recover(keys, data)
        if not hits:
            public = [k for k in keys if k["format"] in key_recovery.PUBLIC_FORMATS][:MAX_PUBLIC_RECOVERY]
            hits = key_recovery.recover(public, data, formats=key_recovery.PUBLIC_FORMATS)
        # a key whose structure crosses a page boundary is split in physical memory, so the
        # full-dump scan can miss it; the process's own (virtual) memory has it in one piece
        for k in rsa_weak.assess([k for k in keys if k["format"] != rsa_weak.TOR and k["fingerprint"] not in reported]):
            if k["issues"]:
                reported.add(k["fingerprint"])
                db.add("rsa", "rsa_key", f"RSA-{k['bits']} key e={k['e']} ({k['format']}) in {name} (PID {pid}), strength {k['strength']}/100 "
                       f"({k['security_bits']}-bit security, {k['nist_status']}): {'; '.join(i['test'] for i in k['issues'])}",
                       rsa_weak.to_serialisable([k])[0], _worst([i["severity"] for i in k["issues"]]), pdump, k["offset"])
        for h in hits:
            db.add("rsa", "key_recovered",
                   f"RSA-{h['bits']} private key of {name} (PID {pid}) recovered from "
                   + ("a CryptoAPI private key blob still in its memory" if h["where"] == "private key blob"
                      else "a prime left in its memory")
                   + f" at {h['prime_offset']}: data encrypted under this key can be decrypted",
                   h, "info", pdump, h["prime_offset"])
        for k in aes_keyfind.find_keys(data):
            k.pop("key")  # never stored: the fingerprint is enough to tell keys apart
            e = aes_keys.setdefault(k["key_id"], {**k, "procs": {}})
            e["procs"].setdefault(pid, {"name": name, "offset": k["offset"], "file": pdump, "copies": 0})["copies"] += 1
        if not hits:
            db.add("rsa", "key_recovery", f"No RSA prime found in {name} (PID {pid}) for its {len(keys)} RSA key(s)",
                   {"pid": pid, "keys": len(keys)}, "info", pdump)

    record_aes_keys(db, aes_keys)

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
    db.close()
    text, mode = report.generate(findings, use_llm, defended)
    out = workdir / f"report_run{run_id}.md"
    out.write_text(text, encoding="utf-8")  # LLM output often has non-cp1252 characters
    return {"run_id": run_id, "findings": len(findings), "report": str(out), "report_mode": mode,
            "risk_score": report.risk_score(findings), "risk_band": report.risk_band(report.risk_score(findings)),
            "compromise": report.compromise_score(findings), "crypto_exposure": report.exposure_score(findings)}
