import sqlite3
from pathlib import Path

import pytest

from dashboard.migrations import runner


@pytest.fixture
def legacy_db(tmp_path: Path) -> Path:
    """A DB pre-populated with the legacy `findings` shape and one row."""
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT);
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            vuln_type TEXT,
            severity TEXT,
            url TEXT,
            method TEXT,
            param_name TEXT,
            payload TEXT,
            evidence TEXT,
            source TEXT,
            validated INTEGER DEFAULT 0,
            status TEXT DEFAULT 'open',
            cvss REAL,
            cwe TEXT,
            confidence REAL DEFAULT 0.8,
            details_json TEXT,
            created_at TEXT
        );
        INSERT INTO scans (id, target) VALUES (1, 'http://x');
        INSERT INTO findings
            (scan_id, vuln_type, severity, url, method, param_name, payload,
             evidence, source, validated, cvss, cwe, created_at)
        VALUES
            (1, 'sqli', 'high', 'http://x/q', 'GET', 'id', '1''',
             'MySQL error', 'sqli_agent', 1, 9.8, 'CWE-89', '2026-01-01T00:00:00');
    """)
    conn.commit()
    conn.close()
    return db


def test_migration_up_creates_new_tables_and_preserves_rows(legacy_db):
    runner.run_migration_001_up(legacy_db)

    conn = sqlite3.connect(legacy_db)
    cur = conn.cursor()

    legacy_rows = cur.execute("SELECT COUNT(*) FROM findings_legacy").fetchone()[0]
    assert legacy_rows == 1

    new_rows = cur.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    assert new_rows == 1

    inst_rows = cur.execute("SELECT COUNT(*) FROM finding_instances").fetchone()[0]
    assert inst_rows == 1

    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_errors'")
    assert cur.fetchone() is not None

    conf = cur.execute("SELECT confidence FROM findings").fetchone()[0]
    assert conf == "high"

    conn.close()


def test_migration_down_restores_legacy_shape(legacy_db):
    runner.run_migration_001_up(legacy_db)
    runner.run_migration_001_down(legacy_db)

    conn = sqlite3.connect(legacy_db)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
    assert cur.fetchone() is not None
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings_legacy'")
    assert cur.fetchone() is None
    assert cur.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
    conn.close()


def test_migration_up_is_idempotent(legacy_db):
    runner.run_migration_001_up(legacy_db)
    runner.run_migration_001_up(legacy_db)
    conn = sqlite3.connect(legacy_db)
    rows = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    assert rows == 1
    conn.close()
