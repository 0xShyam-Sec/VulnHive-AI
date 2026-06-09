"""Apply numbered SQL migrations to the dashboard SQLite DB.

Each migration is two files: NNN_*_up.sql and NNN_*_down.sql.
Idempotent: re-running an up migration is a no-op.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

_HERE = Path(__file__).parent


def _exec_script(db_path: Path, script_path: Path) -> None:
    sql = script_path.read_text(encoding="utf-8")
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(sql)
        conn.commit()
    finally:
        conn.close()


def _has_table(db_path: Path, name: str) -> bool:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)
        )
        return cur.fetchone() is not None
    finally:
        conn.close()


def _copy_legacy_rows(db_path: Path) -> int:
    """Copy rows from `findings` → `findings_v2` + `finding_instances`. Returns count."""
    from engine.finding_model import from_legacy_dict

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM findings").fetchall()
        inserted = 0
        for row in rows:
            d = dict(row)
            finding, instance = from_legacy_dict(d)
            conn.execute(
                """INSERT INTO findings_v2
                   (id, scan_id, rule_id, vuln_type, title, cwe, cvss,
                    severity, confidence, status, verified, false_p,
                    nb_occurrences, primary_evidence, remediation,
                    references_json, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?, ?,?,?,?,?, ?,?,?, ?,?,?)""",
                (
                    finding.id, finding.scan_id, finding.rule_id, finding.vuln_type,
                    finding.title, finding.cwe, finding.cvss,
                    finding.severity.value, finding.confidence.value, finding.status.value,
                    int(finding.verified), int(finding.false_p),
                    finding.nb_occurrences, finding.primary_evidence, finding.remediation,
                    "{}", finding.created_at, finding.updated_at,
                ),
            )
            conn.execute(
                """INSERT INTO finding_instances
                   (id, finding_id, url, method, param_name, payload,
                    evidence_raw, request, response_excerpt, source_tool,
                    source_module, created_at)
                   VALUES (?,?,?,?,?,?, ?,?,?,?, ?,?)""",
                (
                    instance.id, instance.finding_id, instance.url, instance.method,
                    instance.param_name, instance.payload,
                    instance.evidence_raw, instance.request, instance.response_excerpt,
                    instance.source_tool, instance.source_module, instance.created_at,
                ),
            )
            inserted += 1
        conn.commit()
        return inserted
    finally:
        conn.close()


def run_migration_001_up(db_path: Path) -> None:
    """Create new tables, copy legacy rows, rename for transition window."""
    db_path = Path(db_path)
    if _has_table(db_path, "findings_legacy"):
        return
    if not _has_table(db_path, "findings"):
        _exec_script(db_path, _HERE / "001_finding_instance_split_up.sql")
        return

    _exec_script(db_path, _HERE / "001_finding_instance_split_up.sql")
    _copy_legacy_rows(db_path)

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("ALTER TABLE findings RENAME TO findings_legacy")
        conn.execute("ALTER TABLE findings_v2 RENAME TO findings")
        conn.commit()
    finally:
        conn.close()


def run_migration_001_down(db_path: Path) -> None:
    """Restore the legacy shape."""
    db_path = Path(db_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DROP TABLE IF EXISTS finding_instances")
        conn.execute("DROP TABLE IF EXISTS findings")
        conn.execute("DROP TABLE IF EXISTS scan_errors")
        if _has_table(db_path, "findings_legacy"):
            conn.execute("ALTER TABLE findings_legacy RENAME TO findings")
        conn.commit()
    finally:
        conn.close()
