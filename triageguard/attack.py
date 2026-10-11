"""Map findings to MITRE ATT&CK (Enterprise) techniques, and prompt-injection findings
to MITRE ATLAS, so every module's output lands in one shared vocabulary.

Only the finding's module, kind and title are used, so this also works on the slim
findings saved for the dashboard. Findings with no clear technique (most info rows,
weak RSA keys, which are a crypto hygiene issue, not an attacker action) get none.
"""

import re

TECHNIQUES = {
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Credential Access"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1027.002": ("Obfuscated Files or Information: Software Packing", "Defense Evasion"),
    "T1552": ("Unsecured Credentials", "Credential Access"),
    "T1528": ("Steal Application Access Token", "Credential Access"),
    "T1573": ("Encrypted Channel", "Command and Control"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "AML.T0051": ("LLM Prompt Injection (MITRE ATLAS)", "ML Attack"),
}

# (module, kind or None for any, title regex or None, technique ids)
RULES = [
    ("memory", "suspicious_process", r"PE header|unique to this process", ["T1055"]),
    ("memory", "suspicious_process", r"lsass", ["T1003.001"]),
    ("memory", "suspicious_process", r"powershell|pwsh", ["T1059.001"]),
    ("memory", "suspicious_process", r"cmd\.exe", ["T1059.003"]),
    ("memory", "suspicious_process", r"vssadmin|shadowcopy|bcdedit|wbadmin|cipher(\.exe)?\s+/w", ["T1490"]),
    ("memory", "suspicious_process", r"encrypt|ransom|\.locked", ["T1486"]),
    ("memory", "suspicious_process", r"user-writable folder", ["T1204.002"]),
    ("static", "binary", r"yara \[[^\]]", ["T1486"]),
    ("static", "binary", r"packed|entropy 7\.[2-9]", ["T1027.002"]),
    ("static", "blocked", None, ["T1204.002"]),
    ("credentials", "JWT", None, ["T1528", "T1552"]),
    ("credentials", "Google OAuth access token", None, ["T1528", "T1552"]),
    ("credentials", "OAuth refresh token", None, ["T1528", "T1552"]),
    ("credentials", "Bearer token", None, ["T1528", "T1552"]),
    ("credentials", None, None, ["T1552"]),
    ("network", "pcap_summary", r"TLS", ["T1573"]),
    ("defence", "prompt_injection", None, ["AML.T0051"]),
]


def techniques(f):
    """Technique ids for one finding, in rule order, no duplicates. Info and low findings
    get none: those are the heuristics' context rows (JIT regions, the analyst's own
    acquisition tool), and tagging them would make benign activity look like an attack."""
    if f.get("severity") in ("info", "low"):
        return []
    out = []
    for module, kind, rx, ids in RULES:
        if f.get("module") != module or (kind and f.get("kind") != kind):
            continue
        if rx and not re.search(rx, f.get("title", ""), re.I):
            continue
        out += [t for t in ids if t not in out]
    # a dangerous-advice payload asking to switch off the antivirus is its own technique
    if f.get("kind") == "prompt_injection" and "disable" in str(f.get("data", "")).lower():
        out.append("T1562.001")
    return out


def matrix(findings):
    """{tactic: {technique id: [refs]}} for the report's ATT&CK view."""
    view = {}
    for f in findings:
        for t in techniques(f):
            tactic = TECHNIQUES[t][1]
            view.setdefault(tactic, {}).setdefault(t, []).append(f["ref"])
    return view
