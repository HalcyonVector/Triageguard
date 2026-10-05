"""Volatility3 wrapper. Runs plugins via the `vol` CLI and returns parsed JSON.

If Volatility3 is not installed, or the dump is not a recognisable Windows
image, each plugin is reported as skipped and the rest of the pipeline still
runs (crypto and credential scans work on raw bytes).
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

# (label, plugin names to try in order, extra args). Newer vol3 releases moved
# some plugins under windows.malware.*, so we fall back between names.
PLUGINS = [
    ("processes", ["windows.pslist"], []),
    ("cmdlines", ["windows.cmdline"], []),
    ("network", ["windows.netscan"], []),
    ("injected", ["windows.malware.malfind", "windows.malfind"], ["--dump"]),
    ("usb", ["windows.registry.printkey"], ["--key", r"ControlSet001\Enum\USBSTOR"]),
]
TIMEOUT = 1800
# Offline symbol tables (ISF JSON) for networks that block the Microsoft symbol
# server, e.g. JPCERTCC/Windows-Symbol-Tables. Point this at the folder.
SYMBOLS = os.environ.get("TRIAGEGUARD_VOL_SYMBOLS")


def _vol():
    return shutil.which("vol") or shutil.which("vol3")


def run_plugin(dump, plugin, extra=(), outdir=None):
    cmd = [_vol(), "-q", "-r", "json", "-f", str(dump)]
    if SYMBOLS:
        cmd += ["-s", SYMBOLS]
    if outdir:
        cmd += ["-o", str(outdir)]
    cmd += [plugin, *extra]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"exit {proc.returncode}")
    return json.loads(proc.stdout or "[]")


def extract(dump, outdir):
    """Run all plugins. Returns {label: rows or {"skipped": reason}} and dumped region files."""
    results, dumped = {}, []
    if not _vol():
        return {label: {"skipped": "volatility3 not installed"} for label, _, _ in PLUGINS}, dumped
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    for label, names, extra in PLUGINS:
        err = None
        for name in names:
            try:
                results[label] = run_plugin(dump, name, extra, outdir if "--dump" in extra else None)
                break
            except Exception as e:  # wrong plugin name, unsupported OS profile, timeout...
                err = str(e)
        else:
            if "kernel.symbol_table_name" in (err or ""):
                # no Windows kernel found: every other plugin will fail the same way, so stop here
                reason = "no Windows kernel found (not a Windows image, or symbols could not be downloaded; see TRIAGEGUARD_VOL_SYMBOLS)"
                return {lbl: {"skipped": reason} for lbl, _, _ in PLUGINS}, dumped
            results[label] = {"skipped": err}
    # malfind --dump writes one .dmp per injected region; these go to crypto/static analysis
    dumped = sorted(outdir.glob("*.dmp"))
    return results, dumped


def suspicious_processes(results):
    """Simple heuristics over pslist + malfind output."""
    procs = results.get("processes")
    injected = results.get("injected")
    flags = []
    if isinstance(injected, list):
        for row in injected:
            flags.append({"pid": row.get("PID"), "process": row.get("Process"),
                          "reason": f"injected region at {row.get('Start VPN')} protection {row.get('Protection')}"})
    if isinstance(procs, list):
        lsass = [p for p in procs if str(p.get("ImageFileName", "")).lower() == "lsass.exe"]
        if len(lsass) > 1:
            for p in lsass:
                flags.append({"pid": p.get("PID"), "process": "lsass.exe", "reason": "more than one lsass.exe"})
    return flags
