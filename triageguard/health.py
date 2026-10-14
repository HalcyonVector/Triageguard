"""Sanity checks on one analysed dump, printed after a run so a broken or misleading
result is caught before it reaches the dashboard."""
from collections import Counter

# more high alerts than this from one detector usually means a program it does not know
# (the Linux run flagged 46 Firefox content processes before they were allowlisted)
NOISY = 10


def check(findings):
    """Returns [(level, message)], level is 'error' (result unusable), 'warn' or 'ok'."""
    out = []
    kinds = Counter(f["kind"] for f in findings)
    if not kinds.get("processes"):
        out.append(("error", "no process list: Volatility could not read this image (wrong format, or Linux symbols missing in symbols/linux/)"))
    skipped = {}
    for f in findings:
        if f["kind"] == "skipped":
            d = f.get("data") or {}
            skipped.setdefault(str(d.get("reason", ""))[:200], []).append(str(d.get("stage", "?")))
    for reason, stages in skipped.items():  # one line per cause, not per stage
        out.append(("warn", f"{', '.join(stages)} missing: {reason}"))
    high = [f for f in findings if f["kind"] == "suspicious_process" and f["severity"] in ("high", "critical")]
    if len(high) > NOISY:
        names = Counter(str((f.get("data") or {}).get("process", "?")) for f in high).most_common(4)
        out.append(("warn", f"{len(high)} high injected-code alerts, mostly {', '.join(f'{n} x{c}' for n, c in names)}: "
                            "check whether these are a browser or JIT program the allowlist does not know yet"))
    if not any(f["severity"] in ("medium", "high", "critical") for f in findings):
        out.append(("warn", "nothing medium or above: either a clean image or a detector missed the incident"))
    if not out:
        out.append(("ok", f"{len(findings)} findings, all stages ran"))
    return out


def print_check(findings, log=print):
    res = check(findings)
    for level, msg in res:
        log(f"  [{level.upper():5}] {msg}")
    return 1 if any(level == "error" for level, _ in res) else 0
