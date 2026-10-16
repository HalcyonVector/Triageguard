"""Score a pipeline run on a lab dump against the ground truth that plant_lab.py wrote.

    python tools/score_lab.py ..\\data\\vm\\ubuntu-lab\\ground_truth.json results\\dumps\\ubuntu-lab

Prints one line per planted process and writes ground_truth_score.json next to the
findings, so the dashboard folder carries the measured result with the dump.
"""
import hashlib
import json
import re
import sys
from pathlib import Path


def score(truth, findings):
    titles = [(f["kind"], f["title"]) for f in findings]
    algos = {t.split(" identified")[0] for k, t in titles if k == "algorithm"}
    rows = []
    for c in truth["cases"]:
        name, pid = c["process"], c["pid"]
        mine = [(k, t) for k, t in titles if f"(PID {pid})" in t]
        row = {"process": name, "pid": pid, "planted": c["cipher"],
               "key_scanned": any(k in ("key_recovery", "key_recovered", "aes_key", "chacha_key") for k, _ in mine)}
        if c["aes_key"]:
            want = hashlib.sha256(bytes.fromhex(c["aes_key"])).hexdigest()[:12]
            got = re.findall(r"key id ([0-9a-f]{12})", " ".join(t for k, t in mine if k == "aes_key"))
            row["aes_key_recovered"] = want in got
            row["cipher_identified"] = "AES-GCM" in algos
        if c["chacha20_key"]:
            want = hashlib.sha256(bytes.fromhex(c["chacha20_key"])).hexdigest()[:12]
            got = re.findall(r"key id ([0-9a-f]{12})", " ".join(t for k, t in mine if k == "chacha_key"))
            row["chacha20_key_recovered"] = want in got
            row["cipher_identified"] = "ChaCha20/Salsa20" in algos
        if c["rsa_n"]:
            row["rsa_private_key_recovered"] = any(k == "key_recovered" for k, _ in mine)
            if c["rsa_e"] < 65537:
                row["small_e_flagged"] = any(k == "rsa_key" and f"e={c['rsa_e']} " in t for k, t in titles)
        # schedules in a planted process that are not the planted key (OpenSSL's DRBG, say)
        row["other_aes_keys"] = sum(k == "aes_key" for k, _ in mine) - int(bool(row.get("aes_key_recovered")))
        if c["case"] == "control":
            row["false_alarm"] = row["key_scanned"] or row["other_aes_keys"] > 0 or any(k == "chacha_key" for k, _ in mine)
        rows.append(row)
    checks = [v for r in rows for k, v in r.items() if k in
              ("aes_key_recovered", "chacha20_key_recovered", "cipher_identified", "rsa_private_key_recovered", "small_e_flagged", "key_scanned")
              and r["planted"] != "none"]
    checks += [not r["false_alarm"] for r in rows if "false_alarm" in r]
    return {"kernel": truth.get("kernel"), "passed": sum(checks), "checks": len(checks), "cases": rows}


def main(truth_path, result_dir):
    truth = json.loads(Path(truth_path).read_text())
    findings = json.loads((Path(result_dir) / "findings.json").read_text())
    s = score(truth, findings)
    for r in s["cases"]:
        flags = ", ".join(f"{k}={v}" for k, v in r.items() if k not in ("process", "pid", "planted"))
        print(f"{r['process']:<11} {r['planted']:<17} {flags}")
    print(f"\n{s['passed']}/{s['checks']} checks passed")
    (Path(result_dir) / "ground_truth_score.json").write_text(json.dumps(s, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:3])
