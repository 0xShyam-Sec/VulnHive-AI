import sqlite3
from pathlib import Path

import pytest

from dashboard import repository
from dashboard.migrations import runner
from engine.finding_model import (
    Confidence,
    Finding,
    FindingInstance,
    Severity,
)


@pytest.fixture
def db(tmp_path: Path) -> Path:
    db = tmp_path / "test.db"
    sqlite3.connect(db).executescript(
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT);"
        "INSERT INTO scans (id, target) VALUES (1, 'http://x');"
    )
    runner.run_migration_001_up(db)
    return db


def _make_finding(scan_id=1, rule_id="sqli-error", url="http://x/q") -> tuple:
    f = Finding(
        scan_id=scan_id, rule_id=rule_id, vuln_type="sqli",
        title="SQL Injection", severity=Severity.high,
        confidence=Confidence.confirmed, cwe=89, cvss=9.8,
    )
    i = FindingInstance(
        finding_id=f.id, url=url, method="GET", param_name="id",
        payload="1'", evidence_raw="MySQL error", source_tool="sqli_agent",
    )
    return f, i


def test_save_and_list(db):
    f, i = _make_finding()
    repository.save_finding(db, f, i)

    rows = repository.list_findings_for_scan(db, scan_id=1)
    assert len(rows) == 1
    assert rows[0].id == f.id
    assert rows[0].cwe == 89


def test_new_url_creates_new_instance_same_finding(db):
    f, i1 = _make_finding(url="http://x/a")
    repository.save_finding(db, f, i1)

    f2, i2 = _make_finding(url="http://x/b")
    f2.rule_id = f.rule_id
    f2.vuln_type = f.vuln_type
    f2.title = f.title
    f2.cwe = f.cwe
    repository.save_finding(db, f2, i2)

    findings = repository.list_findings_for_scan(db, scan_id=1)
    assert len(findings) == 1                          # collapsed
    assert findings[0].nb_occurrences == 2

    instances = repository.list_instances_for_finding(db, findings[0].id)
    assert len(instances) == 2
    assert {x.url for x in instances} == {"http://x/a", "http://x/b"}


def test_save_scan_error(db):
    from engine.errors import ScanError
    err = ScanError(
        scan_id=1, producer="nuclei", phase="discovery",
        kind="producer_fatal", error="binary missing",
    )
    repository.save_scan_error(db, err)
    errors = repository.list_scan_errors(db, scan_id=1)
    assert len(errors) == 1
    assert errors[0]["producer"] == "nuclei"
