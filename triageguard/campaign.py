"""Link dumps that share attacker evidence into campaigns.

Each analysed dump leaves a list of indicators: process names that are not part of a
normal Windows install (the "know normal, find evil" baseline of the SANS Hunt Evil
poster), public IP addresses it talked to, hashes of injected code, keys it held and
injection patterns. Two dumps are linked when the indicators they share add up to
enough weight.

An indicator found on every dump says nothing (every Windows box runs svchost.exe and
holds the same Microsoft root keys), so each one is weighted by its type and by how rare
it is across the dumps, the inverse document frequency idf = ln((N + 1) / df) of Spärck
Jones (1972). Pairs at or above LINK score are joined, and campaigns are the connected
groups.
"""
import ipaddress
import json
import math
from pathlib import Path

# how much one shared indicator of each type says about a common attacker
WEIGHTS = {"process": 3.0, "code": 3.0, "key": 3.0, "ip": 2.0, "pattern": 1.0}
LINK = 2.5

# processes of a normal Windows install, VMware/VirtualBox guest tools and the memory
# acquisition tools a responder runs; sharing one of these links nothing
KNOWN_GOOD = {n.lower() for n in ["FTK Imager.exe", "Magnet RAM Capture.exe"] + """
System Registry smss.exe csrss.exe wininit.exe winlogon.exe services.exe lsass.exe lsaiso.exe svchost.exe
spoolsv.exe explorer.exe dwm.exe taskhost.exe taskhostw.exe taskhostex.exe taskeng.exe sihost.exe ctfmon.exe
conhost.exe dllhost.exe rundll32.exe WmiPrvSE.exe WMIADAP.exe msdtc.exe SearchIndexer.exe SearchApp.exe
SearchUI.exe SearchProtocolHost.exe SearchFilterHost.exe RuntimeBroker.exe ShellExperienceHost.exe
StartMenuExperienceHost.exe TextInputHost.exe ApplicationFrameHost.exe SystemSettings.exe fontdrvhost.exe
MemCompression audiodg.exe WUDFHost.exe SgrmBroker.exe SecurityHealthService.exe SecurityHealthSystray.exe
MsMpEng.exe NisSrv.exe smartscreen.exe backgroundTaskHost.exe browser_broker.exe MicrosoftEdge.exe
MicrosoftEdgeCP.exe MicrosoftEdgeSH.exe msedge.exe OneDrive.exe userinit.exe LogonUI.exe consent.exe
userinit.exe wlms.exe sppsvc.exe TrustedInstaller.exe TiWorker.exe wuauclt.exe MoUsoCoreWorker.exe
UsoClient.exe dasHost.exe lsm.exe wmpnetwk.exe msiexec.exe notepad.exe mspaint.exe calc.exe cmd.exe
powershell.exe mmc.exe ServerManager.exe dns.exe dfsrs.exe dfssvc.exe ismserv.exe vds.exe Microsoft.ActiveDirectory.WebServices.exe
msinfo32.exe Microsoft.Photos.exe iexplore.exe winword.exe excel.exe outlook.exe chrome.exe firefox.exe
vmtoolsd.exe vm3dservice.exe VGAuthService.exe VBoxService.exe VBoxTray.exe vmacthlp.exe
DumpIt.exe winpmem.exe RamCapture64.exe
AggregatorHost.exe ShellHost.exe SearchHost.exe Widgets.exe WidgetService.exe SecHealthUI.exe msedgewebview2.exe
vmicsvc.exe mscorsvw.exe EMET_Service.exe EMET_Agent.exe VSSVC.exe wbengine.exe vdsldr.exe ipconfig.exe
""".split()}


# Linux: kernel threads and the daemons and desktop of a stock Ubuntu/Debian/RHEL install,
# matched as name prefixes (kworker/0:1, gsd-power, systemd-journal, ...)
LINUX_KNOWN = tuple("""
kworker ksoftirqd migration rcu_ cpuhp idle_inject kthreadd irq/ watchdog scsi_ jbd2 ext4- kswapd khugepaged
oom_reaper kcompactd kblockd ata_sff md edac devfreq kdevtmpfs netns writeback kintegrityd kauditd khungtaskd
ksmd crypto kthrotld acpi_thermal ipv6_addrconf zswap card mm_percpu ttm vmw_ psimon pool_workqueue charger_manager
init systemd (sd-pam) sshd sh bash dash zsh cron atd rsyslogd dbus polkitd agetty login sudo su snapd snap
networkmanager networkd-dispat udisksd modemmanager accounts-daemon avahi-daemon cupsd cups-browsed gdm gnome-
gsd- xorg xwayland pulseaudio pipewire wireplumber gvfs at-spi ibus- tracker- evolution- vmtoolsd vgauthservice
containerd dockerd multipathd irqbalance thermald unattended-upgr packagekitd upowerd colord whoopsie kerneloops
rtkit-daemon switcheroo-cont power-profiles- wpa_supplicant fwupd update-notifier nautilus xdg- dconf-service
goa- gjs mutter-x11-fram ssh-agent gpg-agent less vim nano top ps journalctl avml lime insmod
""".split())
# names that come numbered or suffixed (kworker/0:1, systemd-journal, gsd-power); the rest match exactly
LINUX_FAMILIES = tuple(k for k in LINUX_KNOWN if k[-1] in "-_/" or k in (
    "kworker", "ksoftirqd", "migration", "cpuhp", "idle_inject", "watchdog", "jbd2", "kswapd", "kcompactd",
    "kblockd", "card", "systemd", "dbus", "gdm", "pipewire", "gvfs", "at-spi", "networkmanager"))


def _known(name):
    # Volatility cuts image names to 14 characters (Linux to 15), so compare on that prefix too
    n = name.lower()
    return (n in KNOWN_GOOD or any(k.startswith(n) for k in KNOWN_GOOD if len(n) >= 14)
            or n in LINUX_KNOWN or n.startswith(LINUX_FAMILIES))


def public_ip(addr):
    try:
        return ipaddress.ip_address(str(addr)).is_global
    except ValueError:
        return False


def indicators(findings):
    """Indicators of one dump from its full findings (with data): [{type, value, label}]."""
    out = {}

    def add(kind, value, label):
        out.setdefault((kind, value), {"type": kind, "value": value, "label": label})

    for f in findings:
        d, kind = f.get("data") or {}, f["kind"]
        if kind == "processes":
            for r in d.get("rows", []):
                name = str(r.get("ImageFileName") or "").strip()
                if name and not _known(name):
                    add("process", name.lower(), f"process {name}")
        elif kind == "network":
            for r in d.get("rows", []):
                if public_ip(r.get("ForeignAddr")):
                    add("ip", str(r["ForeignAddr"]), f"connection to {r['ForeignAddr']}")
        elif kind == "binary" and d.get("sha256") and (d.get("entropy") or 0) >= 1.0:
            add("code", d["sha256"], f"same code ({d['sha256'][:12]})")  # near-empty regions match everywhere
        elif kind == "key_recovered" and d.get("fingerprint"):
            add("key", d["fingerprint"], f"same RSA private key ({d['fingerprint'][:12]})")
        elif kind == "aes_key" and d.get("key_id"):
            add("key", d["key_id"], f"same AES key ({d['key_id']})")
        elif kind == "chacha_key" and d.get("key_id"):
            add("key", d["key_id"], f"same ChaCha20 key ({d['key_id']})")
        elif kind == "suspicious_process" and "PE header" in str(d.get("reason", "")):
            add("pattern", f"pe-in:{str(d.get('process', '')).lower()}", f"PE injected into {d.get('process')}")
        elif kind == "tor_client":
            add("pattern", "tor", "Tor client")
    return list(out.values())


def link(dumps):
    """dumps: {dump id: [indicator]}. Returns {"pairs": [...], "campaigns": [[ids]]}."""
    n = len(dumps)
    df = {}
    for inds in dumps.values():
        for i in {(x["type"], x["value"]) for x in inds}:
            df[i] = df.get(i, 0) + 1
    ids, pairs = sorted(dumps), []
    for a_i, a in enumerate(ids):
        mine = {(x["type"], x["value"]): x for x in dumps[a]}
        for b in ids[a_i + 1:]:
            shared = [mine[(x["type"], x["value"])] for x in dumps[b] if (x["type"], x["value"]) in mine]
            ev = sorted(({**x, "weight": round(WEIGHTS[x["type"]] * math.log((n + 1) / df[(x["type"], x["value"])]), 2)}
                         for x in shared), key=lambda x: -x["weight"])
            score = round(sum(x["weight"] for x in ev), 2)
            if ev:
                pairs.append({"a": a, "b": b, "score": score, "linked": score >= LINK, "shared": ev[:8], "n_shared": len(ev)})
    parent = {i: i for i in ids}

    def root(i):
        while parent[i] != i:
            i = parent[i]
        return i

    for p in pairs:
        if p["linked"]:
            parent[root(p["a"])] = root(p["b"])
    groups = {}
    for i in ids:
        groups.setdefault(root(i), []).append(i)
    pairs.sort(key=lambda p: -p["score"])
    return {"pairs": pairs, "campaigns": [g for g in groups.values() if len(g) > 1], "threshold": LINK}


def load(results_dir):
    """Link every dump in results/dumps that has an indicators.json."""
    dumps = {}
    for p in sorted(Path(results_dir, "dumps").glob("*/indicators.json")):
        dumps[p.parent.name] = json.loads(p.read_text(encoding="utf-8"))
    return link(dumps)
