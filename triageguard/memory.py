"""Volatility3 wrapper. Runs plugins via the `vol` CLI and returns parsed JSON.

Windows images get the windows.* plugins; when no Windows kernel is found the
linux.* set is tried, and its rows are renamed to the Windows column names so every
later stage reads one shape. If Volatility3 is not installed, or the dump is neither,
each plugin is reported as skipped and the rest of the pipeline still
runs (crypto and credential scans work on raw bytes).
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
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
# Linux: the same five questions. Rows are renamed by LINUX_COLUMNS below.
PLUGINS_LINUX = [
    ("processes", ["linux.pslist"], []),
    ("cmdlines", ["linux.psaux"], []),
    ("network", ["linux.sockstat"], []),
    ("injected", ["linux.malware.malfind", "linux.malfind"], ["--dump-regions"]),
    ("bash", ["linux.bash"], []),
]
LINUX_COLUMNS = {"COMM": "ImageFileName", "ARGS": "Args", "Destination Addr": "ForeignAddr",
                 "Source Addr": "LocalAddr", "Process Name": "Owner"}
TIMEOUT = 1800
# linux.sockstat walks every open file of every task and ran past 30 minutes on a 4 GB
# desktop image with Firefox open; give up sooner and report the network table as skipped
# windows.memmap --dump on one big process (a browser installer on the 4 GB Ramnit image)
# can run for the full half hour; key recovery skips that process and moves on instead
PLUGIN_TIMEOUT = {"linux.sockstat": 600, "windows.memmap": 600}
# Offline symbol tables (ISF JSON) for networks that block the Microsoft symbol
# server, e.g. JPCERTCC/Windows-Symbol-Tables. Point this at the folder.
ROOT = Path(__file__).resolve().parents[1]
# A Linux image needs the ISF of its exact kernel; unzip it into <project>/symbols/linux/
SYMBOLS = os.environ.get("TRIAGEGUARD_VOL_SYMBOLS") or (str(ROOT / "symbols") if (ROOT / "symbols").is_dir() else None)


def venv_python():
    """The project's own venv interpreter if there is one, else the running one.
    Lets the dashboard run the pipeline with the right packages even when it was
    started from a plain `python` without activating the venv."""
    for rel in (".venv/Scripts/python.exe", ".venv/bin/python", "venv/Scripts/python.exe", "venv/bin/python"):
        if (ROOT / rel).is_file():
            return str(ROOT / rel)
    return sys.executable


def _vol():
    # also look next to the running interpreter and in the project venv, so it works without activating
    dirs = [str(Path(sys.executable).parent), str(Path(venv_python()).parent)]
    for d in [None, *dirs]:
        for name in ("vol", "vol3"):
            found = shutil.which(name, path=d) if d else shutil.which(name)
            if found:
                return found
    return None


def _run(cmd, limit):
    """subprocess.run with a timeout that also works on Windows. There vol.exe is a pip
    launcher that starts python.exe as a child; run() kills only the launcher, the child
    keeps the output pipes open and run() then waits on them forever. Kill the whole tree."""
    kw = {} if os.name == "nt" else {"start_new_session": True}
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw)
    try:
        out, err = proc.communicate(timeout=limit)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def _cache_file(dump, plugin, extra):
    """Where a plugin's output for this exact image is kept: next to the image, named by its
    size and modification time, so a re-run after a code change skips Volatility."""
    p = Path(dump)
    st = p.stat()
    tag = re.sub(r"[^\w.-]+", "_", " ".join([plugin, *extra]))
    return p.parent / ".triageguard_cache" / f"{p.name}.{st.st_size}.{int(st.st_mtime)}" / f"{tag}.json"


def run_plugin(dump, plugin, extra=(), outdir=None):
    # every plugin's output is cached next to the image, except whole-process dumps (--pid):
    # those are hundreds of MB each and cheap to redo for the few processes that need them.
    # Files a plugin writes (malfind --dump-regions) are cached too and copied back on a hit.
    cache = None
    if "--pid" not in extra and os.environ.get("TRIAGEGUARD_NO_CACHE") != "1":
        try:
            cache = _cache_file(dump, plugin, extra)
            if cache.is_file():
                rows = json.loads(cache.read_text(encoding="utf-8"))
                if isinstance(rows, dict) and "__failed__" in rows:
                    # a plugin that timed out once times out again; -Fresh / TRIAGEGUARD_NO_CACHE=1 retries it
                    raise RuntimeError(rows["__failed__"] + " (cached; run with -Fresh to try again)")
                files = cache.with_suffix(".files")
                if outdir and files.is_dir():
                    Path(outdir).mkdir(parents=True, exist_ok=True)
                    for f in files.iterdir():
                        if not (Path(outdir) / f.name).exists():
                            shutil.copy2(f, Path(outdir) / f.name)
                return rows
        except OSError:
            cache = None
    before = set(Path(outdir).iterdir()) if outdir and Path(outdir).is_dir() else set()
    cmd = [_vol(), "-q", "-r", "json", "-f", str(dump)]
    if SYMBOLS:
        cmd += ["-s", SYMBOLS]
    if outdir:
        cmd += ["-o", str(outdir)]
    cmd += [plugin, *extra]
    limit = PLUGIN_TIMEOUT.get(plugin, TIMEOUT)
    try:
        proc = _run(cmd, limit)
    except subprocess.TimeoutExpired:
        msg = f"{plugin} timed out after {limit // 60} minutes"
        if cache:
            try:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps({"__failed__": msg}), encoding="utf-8")
            except OSError:
                pass
        raise RuntimeError(msg) from None
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"exit {proc.returncode}")
    rows = json.loads(proc.stdout or "[]")
    if cache:
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            if outdir and Path(outdir).is_dir():
                files = cache.with_suffix(".files")
                files.mkdir(exist_ok=True)
                for f in set(Path(outdir).iterdir()) - before:
                    if f.is_file():
                        shutil.copy2(f, files / f.name)
            cache.write_text(proc.stdout or "[]", encoding="utf-8")  # last, so a half-written cache is never used
        except OSError:
            pass
    return rows


def _linux_rows(rows):
    if not isinstance(rows, list):
        return rows
    out = []
    for r in rows:
        r = {LINUX_COLUMNS.get(k, k): v for k, v in r.items()} if isinstance(r, dict) else r
        if isinstance(r, dict) and "COMM" not in r and "ImageFileName" in r and "Process" not in r:
            r["Process"] = r["ImageFileName"]
        out.append(r)
    return out


def detect_os(dump):
    """'windows', 'linux' or None, by which kernel Volatility can find."""
    for os_name, plugin in (("windows", "windows.info"), ("linux", "linux.pslist")):
        try:
            run_plugin(dump, plugin)
            return os_name
        except Exception:
            continue
    return None


def extract(dump, outdir):
    """Run all plugins. Returns {label: rows or {"skipped": reason}} and dumped region
    files; results["_os"] says which plugin set ran."""
    results, dumped = {}, []
    if not _vol():
        return {label: {"skipped": "volatility3 not installed"} for label, _, _ in PLUGINS}, dumped
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    print("      detecting the operating system ...", flush=True)
    os_name = detect_os(dump)
    if os_name is None:
        reason = ("no Windows or Linux kernel found (not a supported image, or symbols missing: Windows symbols "
                  "download automatically, a Linux image needs its kernel's ISF in symbols/linux/)")
        return {lbl: {"skipped": reason} for lbl, _, _ in PLUGINS}, dumped
    results["_os"] = os_name
    for label, names, extra in PLUGINS if os_name == "windows" else PLUGINS_LINUX:
        err = None
        for name in names:
            start = time.time()
            print(f"      {name} ...", end=" ", flush=True)  # a 4 GB image can sit in one plugin for minutes
            try:
                results[label] = run_plugin(dump, name, extra, outdir if "--dump" in extra else None)
                print(f"{time.time() - start:.0f}s", flush=True)
                if results[label] or label != "network":
                    break
            except Exception as e:  # wrong plugin name, unsupported OS profile, timeout...
                print(f"failed after {time.time() - start:.0f}s", flush=True)
                err = str(e)
        else:
            if not isinstance(results.get(label), list):  # keep an empty-but-valid result
                results[label] = {"skipped": err}
    if os_name == "linux":
        for label in results:
            if label != "_os":
                results[label] = _linux_rows(results[label])
    # malfind --dump writes one .dmp per injected region; these go to crypto/static analysis
    dumped = sorted(outdir.glob("*.dmp"))
    return results, dumped


# Processes that legitimately JIT code into private RWX memory (Defender's
# emulator, browser JS engines), a well-known malfind false positive
JIT_PROCESSES = {"msmpeng.exe", "msedge.exe", "msedgewebview2.exe", "chrome.exe", "firefox.exe", "mpdefendercoreservice.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe"}
SHELL_PARENTS = {"explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "windowsterminal.exe", "wt.exe"}
LINUX_JIT = {"java", "node", "chrome", "firefox", "dotnet", "qemu-system-x86", "Xorg", "gnome-shell"}
# Firefox content processes rename themselves, and the GNOME desktop runs its JavaScript in
# gjs (SpiderMonkey); Linux cuts names to 15 characters, so these match as prefixes
LINUX_JIT_PREFIXES = ("Isolated Web Co", "Isolated Servic", "Web Content", "WebExtensions", "Privileged Cont",
                      "RDD Process", "Socket Process", "Utility Process", "Forked Child", "gjs", "gnome-terminal",
                      "chromium", "thunderbird")
LINUX_SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "busybox"}
# a shell whose parent is a network service is the classic web shell or exploited daemon
SERVICE_PARENTS = {"apache2", "httpd", "nginx", "php-fpm", "php", "mysqld", "postgres", "java", "tomcat", "node", "python3", "perl"}
LINUX_TMP_RE = re.compile(r"^(?:\S*/)?(?:/tmp|/dev/shm|/var/tmp|/run/user/\d+)/")
LINUX_USER_DIRS_RE = re.compile(r"^(?:/home/[^/]+|/root|~)/(?:Downloads|Desktop)/")
# programs malware likes to impersonate with a one-letter change ("nettstat", "sshd-", "kworkerr")
SYSTEM_TOOLS = {"netstat", "sshd", "cron", "crond", "systemd", "rsyslogd", "syslogd", "dbus-daemon", "kworker",
                "kthreadd", "ksoftirqd", "agetty", "udevd", "auditd", "polkitd", "ifconfig", "iptables", "lsof",
                "ps", "top", "htop", "sudo", "passwd", "login", "bash", "dash", "python3", "perl", "apache2", "nginx",
                "httpd", "mysqld", "postgres", "dockerd", "containerd", "snapd", "NetworkManager", "gnome-shell",
                "Xorg", "pulseaudio", "pipewire", "firefox", "chrome", "atd", "anacron", "smbd", "named", "dhclient"}
CRON_NAMES = {"cron", "crond", "CRON", "anacron", "atd"}


def _one_edit(a, b):
    """True if a and b differ by exactly one inserted, deleted, replaced or swapped character."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1
                                  and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    short, long_ = sorted((a, b), key=len)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def imitated_tool(name):
    """The system program a process name imitates, or None. Short names are skipped: "ps"
    and "ls" are one edit away from far too many real programs."""
    from .campaign import _known  # stock Linux names: kauditd, ibus-daemon and snap are real, not imitations
    n = name.strip()
    if len(n) < 4 or n in SYSTEM_TOOLS or _known(n):
        return None
    return next((t for t in sorted(SYSTEM_TOOLS) if len(t) >= 4 and _one_edit(n, t)), None)
BASH_RE = re.compile(r"(curl|wget)[^|;]*\|\s*(ba)?sh|base64\s+-d[^|;]*\|\s*(ba)?sh|nc(at)?\s.*-e\s|/dev/tcp/|chmod\s+\+x\s+/(tmp|dev/shm)|"
                     r"openssl\s+enc|gpg\s+(-c|--symmetric)|shred\s|history\s+-c|crontab\s|"
                     # running a binary the user just downloaded, as root (no package manager vouches for it)
                     r"sudo\s+(?:-\S+\s+)*\./\S+|chmod\s+\S+\s+\S*\.(?:elf|bin|run)\b", re.I)
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
        parsed = []
        for row in injected:
            try:
                head = _region_head(row)
            except ValueError:
                head = b""
            parsed.append((row, head))
        # the same code in several unrelated processes is a system-wide component
        # (security product, hooking engine), not an injection aimed at one process
        pids_by_head = {}
        for row, head in parsed:
            if head[:16].strip(b"\x00"):
                pids_by_head.setdefault(head[:32], set()).add(row.get("PID"))
        by_pid = {}
        for row, head in parsed:
            name = str(row.get("Process"))
            if head.startswith(b"MZ"):
                sev, why = "critical", "contains a PE header (MZ), likely injected DLL/EXE"
            elif head.startswith(b"\x7fELF"):
                sev, why = "critical", "contains an ELF header, likely a loaded-from-memory binary"
            elif name.lower() in JIT_PROCESSES or name in LINUX_JIT or name.startswith(LINUX_JIT_PREFIXES):
                sev, why = "low", "known JIT process, RWX private memory is expected"
            elif not head[:16].strip(b"\x00"):
                # shellcode starts executing at the region base; a zeroed head is a data/thunk block
                sev, why = "low", "region starts with zero bytes, no code at the region base"
            elif len(pids_by_head.get(head[:32], ())) >= 3:
                sev, why = "medium", f"identical code in {len(pids_by_head[head[:32]])} processes, likely a system-wide hook"
            else:
                sev, why = "high", "executable private memory with code unique to this process"
            entry = by_pid.setdefault((row.get("PID"), name), {"regions": [], "sev": [], "why": {}})
            entry["regions"].append(f"{_hex(row.get('Start VPN', row.get('Start')))} {row.get('Protection')}")
            entry["sev"].append(sev)
            entry["why"][why] = entry["why"].get(why, 0) + 1
        order = ["info", "low", "medium", "high", "critical"]
        for (pid, name), e in by_pid.items():
            sev = max(e["sev"], key=order.index)
            why = "; ".join(f"{n} x {w}" for w, n in e["why"].items())
            flags.append({"pid": pid, "process": name, "severity": sev, "regions": e["regions"],
                          "reason": f"{len(e['regions'])} RWX/injected region(s): {why}"})
    if isinstance(procs, list):
        lsass = [p for p in procs if str(p.get("ImageFileName", "")).lower() == "lsass.exe"]
        if len(lsass) > 1:
            for p in lsass:
                flags.append({"pid": p.get("PID"), "process": "lsass.exe", "severity": "high", "reason": "more than one lsass.exe"})
    if isinstance(procs, list):
        names = {p.get("PID"): str(p.get("ImageFileName", "")).lower() for p in procs}
        for p in procs:
            if str(p.get("ImageFileName", "")).lower() in SHELLS:
                parent = names.get(p.get("PPID"))
                if parent and parent not in SHELL_PARENTS:
                    flags.append({"pid": p.get("PID"), "process": p.get("ImageFileName"), "severity": "medium",
                                  "reason": f"shell started by {parent} (PID {p.get('PPID')}), not by a user session or another shell"})
    if isinstance(procs, list) and results.get("_os") == "linux":
        names = {p.get("PID"): str(p.get("ImageFileName", "")) for p in procs}
        for p in procs:
            parent = names.get(p.get("PPID"), "")
            if str(p.get("ImageFileName", "")) in LINUX_SHELLS and parent in SERVICE_PARENTS:
                flags.append({"pid": p.get("PID"), "process": p.get("ImageFileName"), "severity": "high",
                              "reason": f"shell started by the network service {parent} (PID {p.get('PPID')}), likely a web shell or exploited daemon"})
    if isinstance(procs, list) and results.get("_os") == "linux":
        by_pid = {p.get("PID"): p for p in procs if isinstance(p, dict)}
        for p in procs:
            name = str(p.get("ImageFileName", ""))
            if tool := imitated_tool(name):
                flags.append({"pid": p.get("PID"), "process": name, "severity": "high",
                              "reason": f"name '{name}' imitates the system program '{tool}' (one letter different)"})
            # walk up a few parents: cron -> sh -c -> program
            chain, q = [], by_pid.get(p.get("PPID"))
            while q is not None and len(chain) < 3:
                chain.append(str(q.get("ImageFileName", "")))
                q = by_pid.get(q.get("PPID")) if q.get("PPID") != q.get("PID") else None
            if name not in LINUX_SHELLS and name not in CRON_NAMES and any(c in CRON_NAMES for c in chain):
                flags.append({"pid": p.get("PID"), "process": name, "severity": "medium",
                              "reason": f"started by cron ({' <- '.join([name, *chain])}): a scheduled job, a common way to keep malware running"})
    for r in results.get("bash") if isinstance(results.get("bash"), list) else []:
        cmd = str(r.get("Command") or "")
        if m := BASH_RE.search(cmd):
            flags.append({"pid": r.get("PID"), "process": r.get("Process"), "severity": "medium", "cmdline": cmd[:500],
                          "reason": f"bash history: '{m.group(0).strip()}' in {cmd[:200]}"})
    if isinstance(cmdlines, list):
        for r in cmdlines:
            args = str(r.get("Args") or "")
            if m := CMDLINE_RE.search(args):
                flags.append({"pid": r.get("PID"), "process": r.get("Process"), "severity": "medium", "cmdline": args[:500],
                              "reason": f"command line mentions '{m.group(0)}': {args[:200]}"})
            elif args.startswith("./") or re.match(r"sudo\s+(?:-\S+\s+)*\./", args):
                flags.append({"pid": r.get("PID"), "process": r.get("Process"), "severity": "medium", "cmdline": args[:500],
                              "reason": f"runs a program from the current folder{' as root through sudo' if args.startswith('sudo') else ''}"
                                        f", not an installed one: {args[:200]}"})
            elif LINUX_TMP_RE.search(args.split(" ")[0]):
                flags.append({"pid": r.get("PID"), "process": r.get("Process"), "severity": "medium", "cmdline": args[:500],
                              "reason": f"runs from a world-writable temp folder: {args[:200]}"})
            elif USER_DIRS_RE.search(args.split('" ')[0]) or LINUX_USER_DIRS_RE.search(args.split(" ")[0]):
                flags.append({"pid": r.get("PID"), "process": r.get("Process"), "severity": "low", "cmdline": args[:500],
                              "reason": f"runs from a user-writable folder: {args[:200]}"})
    return flags


# Ransomware that keeps its RSA key pair in process memory; its processes get a full
# memory dump so leftover primes can be searched (see crypto/key_recovery.py)
RANSOM_NAMES = re.compile(r"tasksche|wanadecrypt|wannacry|wcry|mssecsvc|@please_read|decryptor", re.I)
MAX_KEYSCAN = 4


def keyscan_targets(results):
    """PIDs worth a full process dump for key recovery: ransomware names, ransom-like
    command lines and programs started from user folders, at most MAX_KEYSCAN."""
    pids = {}
    for p in results.get("processes") or []:
        if isinstance(p, dict) and (RANSOM_NAMES.search(str(p.get("ImageFileName", "")))
                                    or (results.get("_os") == "linux" and imitated_tool(str(p.get("ImageFileName", ""))))):
            pids[p.get("PID")] = str(p.get("ImageFileName"))
    for r in results.get("cmdlines") or []:
        if not isinstance(r, dict):
            continue
        args = str(r.get("Args") or "")
        if CMDLINE_RE.search(args) or RANSOM_NAMES.search(args) or USER_DIRS_RE.search(args.split('" ')[0]) \
                or LINUX_TMP_RE.search(args.split(" ")[0]) or LINUX_USER_DIRS_RE.search(args.split(" ")[0]) \
                or (args.startswith("./") and results.get("_os") == "linux"):
            pids.setdefault(r.get("PID"), str(r.get("Process")))
    return list(pids.items())[:MAX_KEYSCAN]


def dump_process(dump, pid, outdir, os_name="windows"):
    """Write the whole address space of one process to pid.<pid>.dmp; returns the file or None.
    Windows: windows.memmap --dump. Linux: linux.proc.Maps --dump writes one file per
    mapping, joined here in address order."""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    plugin = "linux.proc.Maps" if os_name == "linux" else "windows.memmap"
    try:
        run_plugin(dump, plugin, ["--pid", str(pid), "--dump"], outdir)
    except Exception:
        for part in outdir.glob(f"pid.{pid}.*"):  # a half-written dump from a timed-out run
            part.unlink(missing_ok=True)
        return None
    if os_name == "linux":
        parts = sorted(outdir.glob(f"pid.{pid}.vma.*.dmp"), key=lambda f: int(f.name.split(".vma.")[1].split("-")[0], 16))
        if not parts:
            return None
        whole = outdir / f"pid.{pid}.dmp"
        with open(whole, "wb") as out:
            for part in parts:
                out.write(part.read_bytes())
                part.unlink()
        return whole
    files = sorted(outdir.glob(f"pid.{pid}.dmp"))
    return files[0] if files else None
