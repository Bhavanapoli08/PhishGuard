"""
SQLite Logging — SIEM-style audit trail
---------------------------------------
Every scan is recorded so analysts can:
  * Review historical scans
  * Spot trending phishing domains
  * Track verdict distributions over time
  * Export for compliance / forensics

Schema is intentionally simple — one row per scan, JSON blob for full report
so we never lose information.
"""

import json
import os
import sqlite3
from datetime import datetime

_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "scans.db")


def _conn():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    c = sqlite3.connect(_DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ts            TEXT    NOT NULL,
                url           TEXT    NOT NULL,
                domain        TEXT,
                client_ip_hash TEXT,
                verdict       TEXT    NOT NULL,
                final_score   REAL    NOT NULL,
                ml_score      INTEGER,
                ti_score      INTEGER,
                whois_score   INTEGER,
                dns_score     INTEGER,
                typo_score    INTEGER,
                full_report   TEXT    NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_ts ON scans(ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_domain ON scans(domain)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_verdict ON scans(verdict)")


def log_scan(url, domain, client_ip_hash, verdict, final_score,
             signals, full_report):
    with _conn() as c:
        c.execute("""
            INSERT INTO scans
            (ts, url, domain, client_ip_hash, verdict, final_score,
             ml_score, ti_score, whois_score, dns_score, typo_score, full_report)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(timespec="seconds"),
            url, domain, client_ip_hash, verdict, final_score,
            signals.get("ml", {}).get("score", 0),
            signals.get("threat_intel", {}).get("score", 0),
            signals.get("whois", {}).get("score", 0),
            signals.get("dns", {}).get("score", 0),
            signals.get("typosquat", {}).get("score", 0),
            json.dumps(full_report),
        ))


def recent_scans(limit=50):
    with _conn() as c:
        rows = c.execute(
            "SELECT id, ts, url, domain, verdict, final_score "
            "FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def stats():
    """Aggregate statistics for the dashboard."""
    with _conn() as c:
        total = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        by_verdict = {r["verdict"]: r["n"] for r in c.execute(
            "SELECT verdict, COUNT(*) AS n FROM scans GROUP BY verdict")}
        top_bad_domains = [dict(r) for r in c.execute("""
            SELECT domain, COUNT(*) AS hits, AVG(final_score) AS avg_score
            FROM scans
            WHERE verdict IN ('SUSPICIOUS','DANGEROUS') AND domain IS NOT NULL
            GROUP BY domain ORDER BY hits DESC LIMIT 10
        """).fetchall()]
        # last 24h hourly bucket
        hourly = [dict(r) for r in c.execute("""
            SELECT substr(ts,1,13) AS hour, COUNT(*) AS n
            FROM scans WHERE ts >= datetime('now','-1 day')
            GROUP BY hour ORDER BY hour
        """).fetchall()]
    return {
        "total": total,
        "by_verdict": by_verdict,
        "top_bad_domains": top_bad_domains,
        "hourly": hourly,
    }


def get_scan(scan_id):
    with _conn() as c:
        row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["full_report"] = json.loads(d["full_report"])
        return d
