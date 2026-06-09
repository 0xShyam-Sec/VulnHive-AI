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
def db_with_mixed_findings(tmp_path: Path) -> Path:
    db = tmp_path / "filter.db"
    sqlite3.connect(db).executescript(
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT);"
        "INSERT INTO scans (id, target) VALUES (1, 'http://x');"
    )
    runner.run_migration_001_up(db)

    rows = [
        ("sqli", Severity.critical, Confidence.confirmed),
        ("xss", Severity.high, Confidence.high),
        ("csrf", Severity.medium, Confidence.medium),
        ("headers", Severity.low, Confidence.low),
        ("info", Severity.info, Confidence.false_positive),
    ]
    for vt, sev, conf in rows:
        f = Finding(
            scan_id=1,
            rule_id=f"r-{vt}",
            vuln_type=vt,
            title=vt.upper(),
            severity=sev,
            confidence=conf,
        )
        i = FindingInstance(
            finding_id=f.id,
            url=f"http://x/{vt}",
            method="GET",
            source_tool=f"{vt}_agent",
        )
        repository.save_finding(db, f, i)
    return db


def test_default_filter_hides_low_and_false_positive(db_with_mixed_findings):
    db = db_with_mixed_findings
    visible = repository.list_findings_filtered(
        db,
        scan_id=1,
        severities=None,
        confidences=["confirmed", "high", "medium"],
        statuses=["active"],
    )
    confs = {f.confidence.value for f in visible}
    assert confs == {"confirmed", "high", "medium"}


def test_show_low_confidence(db_with_mixed_findings):
    db = db_with_mixed_findings
    visible = repository.list_findings_filtered(
        db,
        scan_id=1,
        confidences=["confirmed", "high", "medium", "low"],
        statuses=["active"],
    )
    confs = {f.confidence.value for f in visible}
    assert "low" in confs


def test_severity_filter(db_with_mixed_findings):
    db = db_with_mixed_findings
    visible = repository.list_findings_filtered(
        db,
        scan_id=1,
        severities=["critical", "high"],
        confidences=None,
        statuses=None,
    )
    sevs = {f.severity.value for f in visible}
    assert sevs.issubset({"critical", "high"})
    assert len(visible) == 2


def test_include_false_positives(db_with_mixed_findings):
    db = db_with_mixed_findings
    visible = repository.list_findings_filtered(
        db,
        scan_id=1,
        confidences=["false_positive"],
        statuses=["active"],
        include_false_p=True,
    )
    confs = {f.confidence.value for f in visible}
    assert "false_positive" in confs
