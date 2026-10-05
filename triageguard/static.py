"""Static analysis of suspicious binaries: strings, PE headers, imports, YARA."""

import hashlib
import re
from pathlib import Path

from .crypto.entropy import shannon

ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
INTERESTING = re.compile(r"https?://|\.onion|bitcoin|ransom|decrypt|\.locked|vssadmin|shadowcopy|bcdedit|wallet", re.I)
CRYPTO_IMPORTS = {"CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptImportKey", "CryptExportKey",
                  "CryptAcquireContextA", "CryptAcquireContextW", "CryptDeriveKey", "BCryptEncrypt",
                  "BCryptDecrypt", "BCryptGenerateSymmetricKey", "BCryptImportKeyPair", "BCryptOpenAlgorithmProvider",
                  "BCryptSetProperty", "CryptGenRandom", "BCryptGenRandom"}
RULES = Path(__file__).resolve().parent.parent / "rules"


def strings(data, limit=5000):
    out = [m.group(0).decode() for m in ASCII_RE.finditer(data)]
    out += [m.group(0).decode("utf-16le") for m in WIDE_RE.finditer(data)]
    return out[:limit]


def pe_info(path):
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed"}
    try:
        pe = pefile.PE(str(path))
    except Exception as e:
        return {"error": f"not a PE: {e}"}
    imports = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        imports[entry.dll.decode(errors="replace")] = [i.name.decode() for i in entry.imports if i.name]
    flat = {f for fns in imports.values() for f in fns}
    sections = [{"name": s.Name.rstrip(b"\x00").decode(errors="replace"), "size": s.SizeOfRawData,
                 "entropy": round(s.get_entropy(), 3)} for s in pe.sections]
    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "imphash": pe.get_imphash(),
        "sections": sections,
        "packed_sections": [s["name"] for s in sections if s["entropy"] > 7.2],
        "imports": imports,
        "crypto_imports": sorted(flat & CRYPTO_IMPORTS),
    }


def yara_matches(path):
    try:
        import yara
    except ImportError:
        return None
    rules = yara.compile(filepaths={p.stem: str(p) for p in RULES.glob("*.yar")})
    return [m.rule for m in rules.match(str(path))]


def analyse(path):
    data = Path(path).read_bytes()
    strs = strings(data)
    return {
        "file": str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": round(shannon(data), 3),
        "interesting_strings": sorted({s for s in strs if INTERESTING.search(s)})[:100],
        "pe": pe_info(path),
        "yara": yara_matches(path),
    }
