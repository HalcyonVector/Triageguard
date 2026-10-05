"""Volatility3 wrapper. Runs plugins via the `vol` CLI and returns parsed JSON.

If Volatility3 is not installed, or the dump is not a recognisable Windows
image, each plugin is reported as skipped and the rest of the pipeline still
runs (crypto and credential scans work on raw bytes).
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# (label, plugin names to try in order, extra args). Newer vol3 releases moved
# some plugins under windows.malware.*, so we fall back between names.
PLUGINS = [
    ("processes", ["windows.pslist"], []),
    ("cmdlines", ["windows.cmdline"], []),
    # netscan pool-scans and finds nothing on Windows 11 24H2; netstat walks the
    # tcpip lists and still works, so it is tried when netscan comes back empty
    ("network", ["windows.netscan", "windows.netstat"], []),
    ("injected", ["windows.malware.malfind", "windows.malfind"], ["--dump"]),
    ("usb", ["windows.registry.printkey"], ["--key", r"ControlSet001\Enum\USBSTOR"]),
]
TIMEOUT = 1800
# Offline symbol tables (ISF JSON) for networks that block the Microsoft symbol
# server, e.g. JPCERTCC/Windows-Symbol-Tables. Point this at the folder.
SYMBOLS = os.environ.get("TRIAGEGUARD_VOL_SYMBOLS")


def _vol():
    # also look next to the running interpreter, so a venv works without being activated
    here = str(Path(sys.executable).parent)
    return shutil.which("vol") or shutil.which("vol3") or shutil.which("vol", path=here) or shutil.which("vol3", path=here)


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
                if results[label] or label != "network":
                    break
            except Exception as e:  # wrong plugin name, unsupported OS profile, timeout...
                err = str(e)
        else:
            if "kernel.symbol_table_name" in (err or ""):
                # no Windows kernel found: every other plugin will fail the same way, so stop here
                reason = "no Windows kernel found (not a Windows image, or symbols could not be downloaded; see TRIAGEGUARD_VOL_SYMBOLS)"
                return {lbl: {"skipped": reason} for lbl, _, _ in PLUGINS}, dumped
            if not isinstance(results.get(label), list):  # keep an empty-but-valid result
                results[label] = {"skipped": err}
    # malfind --dump writes one .dmp per injected region; these go to crypto/static analysis
    dumped = sorted(outdir.glob("*.dmp"))
    return results, dumped


# Processes that legitimately JIT code into private RWX memory (Defender's
# emulator, browser JS engines), a well-known malfind false positive
JIT_PROCESSES = {"msmpeng.exe", "msedge.exe", "msedgewebview2.exe", "chrome.exe", "firefox.exe", "mpdefendercoreservice.exe"}
CMDLINE_RE = re.compile(r"encrypt|decrypt|ransom|\.locked|vssadmin|shadowcopy|bcdedit|wbadmin|cipher(\.exe)?\s+/w", re.I)
USER_DIRS_RE = re.compile(r"\\Users\\[^\\]+\\(Desktop|Downloads|AppData\\Local\\Temp)\\", re.I)


def _hex(v):
    return hex(v) if isinstance(v, int) else str(v)


def _region_head(row):
    return bytes.fromhex("".join(str(row.get("Hexdump", "")).split()[:64]) or "")


def suspicious_processes(results):
    """Heuristics over pslist, cmdline and malfind output. Returns flags with a severity."""
    procs = results.get("processes")
    injected = results.get("injected")
    cmdlines = results.get("cmdlines")
    flags = []
    if isinstance(injected, list):
        by_pid = {}
        for row in injected:
            by_pid.setdefault((row.get("PID"), row.get("Process")), []).append(row)
        for (pid, name), rows in by_pid.items():
            heads = []
            for r in rows:
                try:
                    heads.append(_region_head(r))
                except ValueError:
                    heads.append(b"")
            regions = [f"{_hex(r.get('Start VPN'))} {r.get('Protection')}" for r in rows]
            if any(h.startswith(b"MZ") for h in heads):
                sev, why = "critical", "contains a PE header (MZ), likely injected DLL/EXE"
            elif str(name).lower() in JIT_PROCESSES:
                sev, why = "low", "known JIT process, RWX private memory is expected"
            elif all(not h[:16].strip(b"\x00") for h in heads):
                # shellcode starts executing at the region base; a zeroed head is a data/thunk block
                sev, why = "low", "regions start with zero bytes, no code at the region base"
            else:
                sev, why = "high", "executable private memory with code, not a known JIT process"
            flags.append({"pid": pid, "process": name, "severity": sev, "regions": regions,
                          "reason": f"{len(rows)} RWX/injected region(s): {why}"})
    if isinstance(procs, list):
        lsass = [p for p in procs if str(p.get("ImageFileName", "")).lower() == "lsass.exe"]
        if len(lsass) > 1:
            for p in lsass:
                flags.append({"pid": p.get("PID"), "process": "lsass.exe", "severity": "high", "reason": "more than one lsass.exe"})
    if isinstance(cmdlines, list):
        for r in cmdlines:
            args = str(r.get("Args") or "")
            if m := CMDLINE_RE.search(args):
                flags.append({"pid": r.get("PID"), "process": r.get("Process"), "severity": "medium", "cmdline": args[:500],
                              "reason": f"command line mentions '{m.group(0)}': {args[:200]}"})
            elif USER_DIRS_RE.search(args.split('" ')[0]):
                flags.append({"pid": r.get("PID"), "process": r.get("Process"), "severity": "low", "cmdline": args[:500],
                              "reason": f"runs from a user-writable folder: {args[:200]}"})
    return flags
