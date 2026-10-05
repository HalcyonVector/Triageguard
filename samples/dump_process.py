"""Dump the readable memory of a running Linux process to a raw file (needs root
or ptrace rights). Handy for testing the crypto and credential scans on real
process memory when no public Windows image is at hand.

    python samples/dump_process.py <pid> out.raw
"""

import re
import sys

pid, out_path = int(sys.argv[1]), sys.argv[2]
with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", 0) as mem, open(out_path, "wb") as out:
    for line in maps:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) r", line)
        if not m or "[vvar]" in line or "[vsyscall]" in line:
            continue
        start, end = int(m[1], 16), int(m[2], 16)
        try:
            mem.seek(start)
            out.write(mem.read(end - start))
        except OSError:
            pass
