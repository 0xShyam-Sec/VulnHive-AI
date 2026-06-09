"""Read/write access to findings, instances, and scan errors.

Pydantic-typed. Used by the runner (write path) and the dashboard views (read path).
Replaces the dict-shaped helpers that used to live in dashboard/db.py.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

from engine.errors import ScanError
from engine.finding_model import (
    Confidence,
    Finding,
    FindingInstance,
    Severity,
    Status,
)


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _row_to_finding(row: sqlite3.Row) -> Finding:
    return Finding(
        id=row["id"],
        scan_id=row["scan_id"],
        rule_id=row["rule_id"],
        vuln_type=row["vuln_type"],
        title=row["title"],
        cwe=row["cwe"],
        cvss=row["cvss"],
        severity=Severity(row["severity"]),
        confidence=Confidence(row["confidence"]),
        status=Status(row["status"]),
        verified=bool(row["verified"]),
        false_p=bool(row["false_p"]),
        nb_occurrences=row["nb_occurrences"],
        primary_evidence=row["primary_evidence"],
        remediation=row["remediation"],
        references_json=json.loads(row["references_json"] or "{}"),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_instance(row: sqlite3.Row) -> FindingInstance:
    return FindingInstance(
        id=row["id"],
        finding_id=row["finding_id"],
        url=row["url"],
        method=row["method"],
        param_name=row["param_name"],
        payload=row["payload"],
        evidence_raw=row["evidence_raw"],
        request=row["request"],
        response_excerpt=row["response_excerpt"],
        source_tool=row["source_tool"],
        source_module=row["source_module"],
        created_at=row["created_at"],
    )


def _find_existing(conn: sqlite3.Connection, f: Finding) -> Optional[Finding]:
    """Lookup by dedup key. Returns the canonical Finding or None."""
    row = conn.execute(
        """SELECT * FROM findings
           WHERE scan_id=? AND rule_id=? AND vuln_type=?
             AND lower(title)=? AND (cwe IS ? OR cwe=?)
           LIMIT 1""",
        (f.scan_id, f.rule_id, f.vuln_type, f.title.lower().strip(),
         f.cwe, f.cwe),
    ).fetchone()
    return _row_to_finding(row) if row else None


def _instance_exists(conn: sqlite3.Connection, finding_id: str, i: FindingInstance) -> bool:
    row = conn.execute(
        """SELECT 1 FROM finding_instances
           WHERE finding_id=? AND url=? AND method=?
             AND (param_name IS ? OR param_name=?)
           LIMIT 1""",
        (finding_id, i.url, i.method, i.param_name, i.param_name),
    ).fetchone()
    return row is not None


def save_finding(db_path: Path, f: Finding, i: FindingInstance) -> Finding:
    """Persist a Finding+Instance pair with dedup-and-merge semantics."""
    db_path = Path(db_path)
    conn = _connect(db_path)
    try:
        existing = _find_existing(conn, f)
        if existing is None:
            conn.execute(
                """INSERT INTO findings
                   (id, scan_id, rule_id, vuln_type, title, cwe, cvss,
                    severity, confidence, status, verified, false_p,
                    nb_occurrences, primary_evidence, remediation,
                    references_json, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?, ?,?,?,?,?, ?,?,?, ?,?,?)""",
                (
                    f.id, f.scan_id, f.rule_id, f.vuln_type, f.title,
                    f.cwe, f.cvss,
                    f.severity.value, f.confidence.value, f.status.value,
                    int(f.verified), int(f.false_p),
                    f.nb_occurrences, f.primary_evidence, f.remediation,
                    json.dumps(f.references_json), f.created_at, f.updated_at,
                ),
            )
            target_finding_id = f.id
        else:
            target_finding_id = existing.id
            if not _instance_exists(conn, target_finding_id, i):
                conn.execute(
                    "UPDATE findings SET nb_occurrences = nb_occurrences + 1, updated_at=? WHERE id=?",
                    (f.updated_at, target_finding_id),
                )

        if not _instance_exists(conn, target_finding_id, i):
            conn.execute(
                """INSERT INTO finding_instances
                   (id, finding_id, url, method, param_name, payload,
                    evidence_raw, request, response_excerpt, source_tool,
                    source_module, created_at)
                   VALUES (?,?,?,?,?,?, ?,?,?,?, ?,?)""",
                (
                    i.id, target_finding_id, i.url, i.method,
                    i.param_name, i.payload, i.evidence_raw,
                    i.request, i.response_excerpt, i.source_tool,
                    i.source_module, i.created_at,
                ),
            )
        conn.commit()
        out = conn.execute("SELECT * FROM findings WHERE id=?", (target_finding_id,)).fetchone()
        return _row_to_finding(out)
    finally:
        conn.close()


def list_findings_for_scan(db_path: Path, scan_id: int) -> list[Finding]:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY severity, created_at",
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()
    return [_row_to_finding(r) for r in rows]


def list_instances_for_finding(db_path: Path, finding_id: str) -> list[FindingInstance]:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM finding_instances WHERE finding_id=? ORDER BY created_at",
            (finding_id,),
        ).fetchall()
    finally:
        conn.close()
    return [_row_to_instance(r) for r in rows]


def save_scan_error(db_path: Path, err: ScanError) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            """INSERT INTO scan_errors
               (scan_id, producer, phase, kind, error, traceback, affected_target, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (err.scan_id, err.producer, err.phase, err.kind, err.error,
             err.traceback, err.affected_target, err.created_at),
        )
        conn.commit()
    finally:
        conn.close()


def list_scan_errors(db_path: Path, scan_id: int) -> list[dict]:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM scan_errors WHERE scan_id=? ORDER BY created_at",
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]
