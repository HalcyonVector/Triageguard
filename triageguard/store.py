"""SQLite store. Every finding gets a short id (F1, F2, ...) that the LLM report
must cite, which is what the citation defence later checks against."""

import json
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    started TEXT,
    dump TEXT,
    pcap TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    run_id INTEGER REFERENCES runs(id),
    ref TEXT,            -- citation id, e.g. F12
    module TEXT,         -- memory | static | crypto | rsa | credentials | network
    kind TEXT,           -- e.g. algorithm, rsa_key, jwt, process
    title TEXT,
    severity TEXT,       -- info | low | medium | high | critical
    source TEXT,         -- file the evidence came from
    location TEXT,       -- offset / pid / packet
    data TEXT            -- JSON detail
);
"""


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)
        self.run_id = None
        self.n = 0

    def start_run(self, dump, pcap=None):
        cur = self.db.execute("INSERT INTO runs (started, dump, pcap) VALUES (?, ?, ?)",
                              (datetime.now(timezone.utc).isoformat(), str(dump), str(pcap) if pcap else None))
        self.run_id = cur.lastrowid
        self.n = 0
        return self.run_id

    def add(self, module, kind, title, data, severity="info", source="", location=""):
        self.n += 1
        ref = f"F{self.n}"
        self.db.execute(
            "INSERT INTO findings (run_id, ref, module, kind, title, severity, source, location, data) VALUES (?,?,?,?,?,?,?,?,?)",
            (self.run_id, ref, module, kind, title, severity, str(source), str(location), json.dumps(data, default=str)))
        return ref

    def findings(self, run_id=None):
        rows = self.db.execute(
            "SELECT ref, module, kind, title, severity, source, location, data FROM findings WHERE run_id=? ORDER BY id",
            (run_id or self.run_id,)).fetchall()
        keys = ("ref", "module", "kind", "title", "severity", "source", "location", "data")
        return [dict(zip(keys, r[:-1] + (json.loads(r[-1]),))) for r in rows]

    def commit(self):
        self.db.commit()

    def close(self):
        # Windows cannot delete an open SQLite file, so callers using temp dirs must close
        self.db.close()
