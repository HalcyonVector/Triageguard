#!/usr/bin/env python3
"""Turn a Volatility 2 Linux profile into a Volatility 3 symbol file (ISF).

Many public Linux memory challenges (CyberDefenders, CTFs) ship a Volatility 2
profile zip instead of a Volatility 3 ISF. That zip holds a `module.dwarf`
(the text output of `dwarfdump -di`, NOT an ELF, so `dwarf2json` cannot read it)
and a `System.map`. This rebuilds the ISF `dwarf2json` would have produced, so
the dump works with our Volatility 3 pipeline.

    # straight from the bundled profile zip, banner read from the image:
    python tools/vol2_to_isf.py --profile Centos7.3.10.1062.zip --dump dump.mem \
        symbols/linux/CentOS_3.10.0-1062.json

    # or point at already-extracted files:
    python tools/vol2_to_isf.py --dwarf module.dwarf --system-map System.map \
        --banner-b64 <base64> out.json

Volatility 3 matches an ISF to an image by the kernel banner, so either --dump
(read the exact banner out of the image) or --banner-b64 is needed for the file
to be picked up automatically.
"""
import sys, re, json, base64, argparse, zipfile, io, os

LINE_RE = re.compile(r"^<(\d+)><0x([0-9a-fA-F]+)(?:\+0x[0-9a-fA-F]+)?><(DW_TAG_\w+)>\s*(.*)$")
ATTR_RE = re.compile(r"(DW_AT_\w+)<(.*?)>(?=\s+DW_AT_\w+<|\s*$)")
ENC_KIND = {
    "DW_ATE_signed": ("int", True), "DW_ATE_unsigned": ("int", False),
    "DW_ATE_signed_char": ("char", True), "DW_ATE_unsigned_char": ("char", False),
    "DW_ATE_boolean": ("bool", False), "DW_ATE_float": ("float", True),
}


def to_int(s):
    if s is None:
        return None
    s = s.strip()
    if not s:
        return None
    tok = s.split()[0]
    try:
        return int(tok, 16) if tok.lower().startswith("0x") else int(tok, 10)
    except ValueError:
        return None


def ref_offset(val):
    m = re.search(r"0x([0-9a-fA-F]+)", val)
    return int(m.group(1), 16) if m else None


class DIE:
    __slots__ = ("depth", "off", "tag", "attrs", "children")

    def __init__(self, depth, off, tag, attrs):
        self.depth = depth; self.off = off; self.tag = tag
        self.attrs = attrs; self.children = []


def parse_dwarf(text):
    dies, stack = {}, []
    for line in text.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        depth, off = int(m.group(1)), int(m.group(2), 16)
        die = DIE(depth, off, m.group(3),
                  {a.group(1): a.group(2) for a in ATTR_RE.finditer(m.group(4))})
        dies[off] = die
        while stack and stack[-1][0] >= depth:
            stack.pop()
        if stack:
            stack[-1][1].children.append(die)
        stack.append((depth, die))
    return dies


def find_banner(image_path, version_hint=b"Linux version "):
    """Return base64 of the newline-terminated kernel banner (plus trailing NUL),
    matching how dwarf2json stores linux_banner."""
    best = None
    with open(image_path, "rb") as f:
        prev = b""
        while True:
            chunk = f.read(32 * 1024 * 1024)
            if not chunk:
                break
            buf = prev + chunk
            start = 0
            while True:
                i = buf.find(version_hint, start)
                if i == -1:
                    break
                end = buf.find(b"\x00", i)
                if end != -1 and end - i < 512:
                    b = buf[i:end]
                    if b.endswith(b"\n") and (best is None or len(b) > len(best)):
                        best = b
                start = i + 1
            prev = buf[-512:]
    if best is None:
        return None
    return base64.b64encode(best + b"\x00").decode()


def build_isf(dwarf_text, sysmap_text, banner_b64=None):
    dies = parse_dwarf(dwarf_text)
    base_types = {
        "void": {"size": 0, "signed": False, "kind": "void", "endian": "little"},
        "pointer": {"size": 8, "signed": False, "kind": "int", "endian": "little"},
    }

    def agg_name(die):
        return die.attrs.get("DW_AT_name") or "unnamed_%x" % die.off

    def resolve(off):
        if off is None or off not in dies:
            return {"kind": "base", "name": "void"}
        die = dies[off]; tag = die.tag
        if tag == "DW_TAG_base_type":
            name = die.attrs.get("DW_AT_name", "void")
            if name not in base_types:
                enc = die.attrs.get("DW_AT_encoding", "DW_ATE_signed")
                kind, signed = ENC_KIND.get(enc, ("int", True))
                base_types[name] = {"size": to_int(die.attrs.get("DW_AT_byte_size", "0")) or 0,
                                    "signed": signed, "kind": kind, "endian": "little"}
            return {"kind": "base", "name": name}
        if tag == "DW_TAG_pointer_type":
            return {"kind": "pointer",
                    "subtype": resolve(ref_offset(die.attrs.get("DW_AT_type", "")))}
        if tag == "DW_TAG_structure_type":
            return {"kind": "struct", "name": agg_name(die)}
        if tag == "DW_TAG_union_type":
            return {"kind": "union", "name": agg_name(die)}
        if tag == "DW_TAG_enumeration_type":
            return {"kind": "enum", "name": agg_name(die)}
        if tag == "DW_TAG_array_type":
            count = 0
            for c in die.children:
                if c.tag == "DW_TAG_subrange_type":
                    if "DW_AT_upper_bound" in c.attrs:
                        ub = to_int(c.attrs["DW_AT_upper_bound"])
                        count = ub + 1 if ub is not None else 0
                    elif "DW_AT_count" in c.attrs:
                        count = to_int(c.attrs["DW_AT_count"]) or 0
                    break
            return {"kind": "array", "count": count,
                    "subtype": resolve(ref_offset(die.attrs.get("DW_AT_type", "")))}
        if tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
                   "DW_TAG_restrict_type"):
            return resolve(ref_offset(die.attrs.get("DW_AT_type", "")))
        if tag == "DW_TAG_subroutine_type":
            return {"kind": "function"}
        return {"kind": "base", "name": "void"}

    def member_descriptor(mem):
        base = resolve(ref_offset(mem.attrs.get("DW_AT_type", "")))
        if "DW_AT_bit_size" in mem.attrs:
            bit_size = to_int(mem.attrs["DW_AT_bit_size"]) or 0
            byte_size = to_int(mem.attrs.get("DW_AT_byte_size", "0")) or 0
            if "DW_AT_data_bit_offset" in mem.attrs:
                dbo = to_int(mem.attrs["DW_AT_data_bit_offset"]) or 0
                bit_pos = dbo % (byte_size * 8) if byte_size else dbo
            else:
                bit_off = to_int(mem.attrs.get("DW_AT_bit_offset", "0")) or 0
                bit_pos = byte_size * 8 - bit_off - bit_size
            return {"kind": "bitfield", "bit_length": bit_size,
                    "bit_position": bit_pos, "type": base}
        return base

    user_types, enums = {}, {}
    for die in dies.values():
        if die.tag not in ("DW_TAG_structure_type", "DW_TAG_union_type"):
            continue
        if "DW_AT_declaration" in die.attrs:
            continue
        fields = {}
        for mem in die.children:
            if mem.tag != "DW_TAG_member":
                continue
            name = mem.attrs.get("DW_AT_name") or "__unnamed_field_%x" % mem.off
            loc = mem.attrs.get("DW_AT_data_member_location", "0")
            m = re.search(r"DW_OP_plus_uconst\s+(\d+)", loc)
            offset = int(m.group(1)) if m else (to_int(loc) or 0)
            fields[name] = {"offset": offset, "type": member_descriptor(mem)}
        name = agg_name(die)
        kind = "struct" if die.tag == "DW_TAG_structure_type" else "union"
        if name not in user_types or len(fields) > len(user_types[name]["fields"]):
            user_types[name] = {"size": to_int(die.attrs.get("DW_AT_byte_size", "0")) or 0,
                                "fields": fields, "kind": kind}

    for die in dies.values():
        if die.tag != "DW_TAG_enumeration_type":
            continue
        consts = {c.attrs.get("DW_AT_name", ""): (to_int(c.attrs.get("DW_AT_const_value", "0")) or 0)
                  for c in die.children if c.tag == "DW_TAG_enumerator"}
        if not consts:
            continue
        size = to_int(die.attrs.get("DW_AT_byte_size", "4")) or 4
        base = {1: "unsigned char", 2: "short unsigned int", 4: "unsigned int",
                8: "long unsigned int"}.get(size, "unsigned int")
        name = agg_name(die)
        if name not in enums or len(consts) > len(enums[name]["constants"]):
            enums[name] = {"size": size, "base": base, "constants": consts}

    symbols = {}
    for line in sysmap_text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            symbols[parts[2]] = {"address": int(parts[0], 16)}
        except ValueError:
            continue
    if banner_b64 and "linux_banner" in symbols:
        symbols["linux_banner"]["constant_data"] = banner_b64

    return {"metadata": {"producer": {"name": "vol2-to-isf", "version": "0.1"},
                         "format": "6.2.0"},
            "base_types": base_types, "user_types": user_types,
            "enums": enums, "symbols": symbols}


def read_profile(path):
    """Return (dwarf_text, sysmap_text) from a vol2 profile zip or a directory."""
    if zipfile.is_zipfile(path):
        z = zipfile.ZipFile(path)
        dwarf = sysmap = None
        for n in z.namelist():
            base = os.path.basename(n)
            if base == "module.dwarf":
                dwarf = z.read(n).decode(errors="replace")
            elif base.startswith("System.map"):
                sysmap = z.read(n).decode(errors="replace")
        return dwarf, sysmap
    raise SystemExit("not a profile zip: %s" % path)


def main():
    ap = argparse.ArgumentParser(description="Volatility 2 Linux profile -> Volatility 3 ISF")
    ap.add_argument("out", help="output ISF path (e.g. symbols/linux/foo.json)")
    ap.add_argument("--profile", help="vol2 profile zip (module.dwarf + System.map)")
    ap.add_argument("--dwarf", help="module.dwarf (if not using --profile)")
    ap.add_argument("--system-map", help="System.map (if not using --profile)")
    ap.add_argument("--dump", help="memory image to read the exact kernel banner from")
    ap.add_argument("--banner-b64", help="base64 banner (overrides --dump)")
    a = ap.parse_args()

    if a.profile:
        dwarf_text, sysmap_text = read_profile(a.profile)
    elif a.dwarf and a.system_map:
        dwarf_text = open(a.dwarf, errors="replace").read()
        sysmap_text = open(a.system_map, errors="replace").read()
    else:
        ap.error("give --profile, or both --dwarf and --system-map")
    if not dwarf_text or not sysmap_text:
        raise SystemExit("profile is missing module.dwarf or System.map")

    banner = a.banner_b64
    if not banner and a.dump:
        banner = find_banner(a.dump)
        if not banner:
            print("warning: no kernel banner found in %s" % a.dump, file=sys.stderr)
    if not banner:
        print("warning: no banner set; Volatility 3 won't auto-match this ISF "
              "(pass --dump or --banner-b64)", file=sys.stderr)

    isf = build_isf(dwarf_text, sysmap_text, banner)
    with open(a.out, "w") as f:
        json.dump(isf, f)
    print("wrote %s  (base_types=%d user_types=%d enums=%d symbols=%d, banner=%s)"
          % (a.out, len(isf["base_types"]), len(isf["user_types"]),
             len(isf["enums"]), len(isf["symbols"]), "yes" if banner else "NO"))


if __name__ == "__main__":
    main()
