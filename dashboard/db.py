"""
SQLite layer — the single source of truth for scans, findings, logs, chat.

Design principles:
- DB is the source of truth. SSE/Redis are notification channels only.
- Every state transition (queued → running → done/failed/stopped) is committed.
- Workers can crash and the next process can resume the right view from DB.
"""

import sqlite3
import json
import os
from contextlib import contextmanager
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnhive.db")


@contextmanager
def get_db():
    """Context-managed connection. Always closes, always WAL mode."""
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─── Schema ──────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_name TEXT,
    status TEXT NOT NULL DEFAULT 'queued',     -- queued | running | done | failed | stopped
    mode TEXT DEFAULT 'multi-agent',
    llm_backend TEXT DEFAULT 'ollama',
    progress INTEGER DEFAULT 0,                 -- 0-100
    phase TEXT DEFAULT 'queued',
    started_at TEXT,
    finished_at TEXT,
    duration_sec REAL DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    config_json TEXT DEFAULT '{}',
    error TEXT,
    rq_job_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    vuln_type TEXT,
    severity TEXT,
    url TEXT,
    method TEXT,
    param_name TEXT,
    payload TEXT,
    evidence TEXT,
    source TEXT,
    validated INTEGER DEFAULT 0,
    status TEXT DEFAULT 'open',             -- open | fixed | ignored | false_positive
    cvss REAL,
    cwe TEXT,
    confidence REAL DEFAULT 0.8,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    details_json TEXT DEFAULT '{}',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    level TEXT DEFAULT 'info',
    message TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_logs_scan ON scan_logs(scan_id, id);

CREATE TABLE IF NOT EXISTS recon (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    recon_type TEXT,
    data_json TEXT DEFAULT '{}',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    backend TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_chat_scan ON chat_messages(scan_id, id);
"""


def init_db():
    """Create schema. Idempotent — safe to call from any process."""
    with get_db() as conn:
        conn.executescript(SCHEMA)


def recover_stale_running_scans():
    """
    Mark any 'running' or 'queued' scans as 'failed' if their underlying RQ job
    is dead (failed, abandoned, never enqueued, or not owned by any live worker).

    Cases covered:
      - rq_job_id is None         → phantom row (created but never enqueued)
      - rq_job_id in failed reg   → worker crashed
      - rq_job_id not in queued,  → orphan (RQ lost it)
        started, or live workers

    Call ONLY from the web app at startup, never from a worker.
    """
    try:
        import redis as _r
        from rq import Worker, Queue
        from rq.registry import FailedJobRegistry, StartedJobRegistry
        rconn = _r.Redis()
        queue = Queue("vulnhive_scans", connection=rconn)
        failed_ids = set(FailedJobRegistry(queue=queue).get_job_ids())
        started_ids = set(StartedJobRegistry(queue=queue).get_job_ids())
        queued_ids = set(queue.job_ids)
        live_ids = {w.get_current_job_id() for w in Worker.all(connection=rconn) if w.get_current_job_id()}
    except Exception:
        # If Redis is down on startup, leave scans alone — we don't want to
        # clobber state because we can't see RQ.
        return

    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, rq_job_id, status FROM scans WHERE status IN ('running','queued')"
        ).fetchall()
        for r in rows:
            rqid = r["rq_job_id"]
            is_alive = (
                rqid is not None
                and rqid not in failed_ids
                and (rqid in queued_ids or rqid in started_ids or rqid in live_ids)
            )
            if not is_alive:
                reason = (
                    "Job was never enqueued to RQ" if not rqid
                    else "RQ job failed (worker crashed)" if rqid in failed_ids
                    else "Orphaned — no live worker, not in queue"
                )
                conn.execute(
                    "UPDATE scans SET status='failed', error=? WHERE id=?",
                    (reason, r["id"])
                )


# ─── Scan CRUD ───────────────────────────────────────────────────────────

def create_scan(target, scan_name=None, mode="multi-agent", llm_backend="ollama", config=None) -> int:
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, scan_name, status, mode, llm_backend, started_at, config_json) "
            "VALUES (?, ?, 'queued', ?, ?, ?, ?)",
            (target, scan_name, mode, llm_backend, datetime.now().isoformat(), json.dumps(config or {})),
        )
        return cur.lastrowid


def update_scan(scan_id, **fields):
    if not fields:
        return
    with get_db() as conn:
        keys = ", ".join(f"{k} = ?" for k in fields.keys())
        conn.execute(f"UPDATE scans SET {keys} WHERE id = ?", (*fields.values(), scan_id))


def set_rq_job_id(scan_id, job_id):
    update_scan(scan_id, rq_job_id=job_id)


def get_scan(scan_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def list_scans(limit=200):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def finish_scan(scan_id, status="done"):
    """Compute final counts + duration + mark terminal status."""
    with get_db() as conn:
        # Severity counts from findings table
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        rows = conn.execute(
            "SELECT severity, COUNT(*) as n FROM findings WHERE scan_id = ? GROUP BY severity",
            (scan_id,),
        ).fetchall()
        for r in rows:
            if r["severity"] in counts:
                counts[r["severity"]] = r["n"]

        scan = conn.execute("SELECT started_at FROM scans WHERE id = ?", (scan_id,)).fetchone()
        duration = 0.0
        if scan and scan["started_at"]:
            try:
                duration = (datetime.now() - datetime.fromisoformat(scan["started_at"])).total_seconds()
            except Exception:
                pass

        conn.execute(
            "UPDATE scans SET status=?, finished_at=?, duration_sec=?, progress=100, phase='completed', "
            "total_findings=?, critical_count=?, high_count=?, medium_count=?, low_count=?, info_count=? "
            "WHERE id = ?",
            (
                status, datetime.now().isoformat(), round(duration, 1),
                sum(counts.values()),
                counts["Critical"], counts["High"], counts["Medium"], counts["Low"], counts["Info"],
                scan_id,
            ),
        )


# ─── Findings ────────────────────────────────────────────────────────────

SEVERITY_TO_CVSS = {"Critical": 9.5, "High": 7.5, "Medium": 5.5, "Low": 3.0, "Info": 0.0}


def save_finding(scan_id, finding) -> int:
    """Save a finding, return its id. Used by the live event stream."""
    sev = finding.get("severity", "Info")
    extras = {k: v for k, v in finding.items() if k not in {
        "vuln_type", "severity", "url", "method", "param_name", "payload",
        "evidence", "source", "validated", "cvss", "cwe", "confidence",
    }}
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO findings (scan_id, vuln_type, severity, url, method, param_name, payload, "
            "evidence, source, validated, cvss, cwe, confidence, details_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                finding.get("vuln_type", ""), sev,
                finding.get("url", ""), finding.get("method", "GET"),
                finding.get("param_name", ""), finding.get("payload", ""),
                finding.get("evidence", ""), finding.get("source", ""),
                1 if finding.get("validated") else 0,
                finding.get("cvss", SEVERITY_TO_CVSS.get(sev, 0.0)),
                finding.get("cwe", ""),
                finding.get("confidence", 0.8),
                json.dumps(extras, default=str),
            ),
        )
        return cur.lastrowid


def get_findings(scan_id, severity=None, status=None, search=None):
    sql = ("SELECT * FROM findings WHERE scan_id = ? "
           " ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 "
           " WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, id DESC")
    with get_db() as conn:
        rows = conn.execute(sql, (scan_id,)).fetchall()
    out = [dict(r) for r in rows]
    if severity and severity != "all":
        out = [f for f in out if f["severity"] == severity]
    if status and status != "all":
        out = [f for f in out if f["status"] == status]
    if search:
        s = search.lower()
        out = [f for f in out if any(s in (f.get(k) or "").lower()
               for k in ("vuln_type", "url", "payload", "evidence", "source"))]
    return out


def get_finding(finding_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return dict(row) if row else None


def update_finding_status(finding_id, status):
    with get_db() as conn:
        conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))


# ─── Logs ────────────────────────────────────────────────────────────────

def add_log(scan_id, message, level="info") -> int:
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO scan_logs (scan_id, level, message, timestamp) VALUES (?, ?, ?, ?)",
            (scan_id, level, message, datetime.now().isoformat()),
        )
        return cur.lastrowid


def get_logs(scan_id, after_id=0, limit=500):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_logs WHERE scan_id = ? AND id > ? ORDER BY id LIMIT ?",
            (scan_id, after_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


# ─── Recon ───────────────────────────────────────────────────────────────

def save_recon(scan_id, recon_type, data):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO recon (scan_id, recon_type, data_json) VALUES (?, ?, ?)",
            (scan_id, recon_type, json.dumps(data, default=str)),
        )


def get_recon(scan_id):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM recon WHERE scan_id = ?", (scan_id,)).fetchall()
        return {r["recon_type"]: json.loads(r["data_json"] or "{}") for r in rows}


# ─── Chat ────────────────────────────────────────────────────────────────

def save_chat(scan_id, role, content, backend=None):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO chat_messages (scan_id, role, content, backend) VALUES (?, ?, ?, ?)",
            (scan_id, role, content, backend),
        )


def get_chat(scan_id, limit=50):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM chat_messages WHERE scan_id = ? ORDER BY id DESC LIMIT ?",
            (scan_id, limit),
        ).fetchall()
        return [dict(r) for r in reversed(rows)]


def clear_chat(scan_id):
    with get_db() as conn:
        conn.execute("DELETE FROM chat_messages WHERE scan_id = ?", (scan_id,))


# ─── Aggregates / dashboards ────────────────────────────────────────────

def get_stats():
    with get_db() as conn:
        total_scans = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        running = conn.execute("SELECT COUNT(*) AS n FROM scans WHERE status='running'").fetchone()["n"]
        queued = conn.execute("SELECT COUNT(*) AS n FROM scans WHERE status='queued'").fetchone()["n"]
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings WHERE status='open' GROUP BY severity"
        ).fetchall()
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for r in sev_rows:
        if r["severity"] in sev:
            sev[r["severity"]] = r["n"]
    return {
        "total_scans": total_scans,
        "running": running,
        "queued": queued,
        **{f"{k.lower()}_total": v for k, v in sev.items()},
        "findings_total": sum(sev.values()),
        "risk_score": min(100, sev["Critical"] * 12 + sev["High"] * 5 + sev["Medium"] * 2 + sev["Low"]),
    }


# Initialise on import (recovers stale 'running' scans)
init_db()


# ── Migration trigger ──────────────────────────────────────────────────
# Run pending migrations whenever this module is imported (dashboard boot).
def _apply_pending_migrations() -> None:
    """Apply numbered migrations to DB_PATH. Safe / idempotent on every boot."""
    from pathlib import Path
    from dashboard.migrations.runner import run_migration_001_up
    try:
        run_migration_001_up(Path(DB_PATH))
    except Exception as e:
        import sys
        print(f"[migrations] WARNING: 001 failed: {e}", file=sys.stderr)


_apply_pending_migrations()
