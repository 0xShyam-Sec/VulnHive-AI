-- Migration 001: split flat findings into Finding + FindingInstance
-- Idempotent. Safe to run multiple times.

BEGIN;

CREATE TABLE IF NOT EXISTS findings_v2 (
    id TEXT PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    title TEXT NOT NULL,
    cwe INTEGER,
    cvss REAL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    verified INTEGER NOT NULL DEFAULT 0,
    false_p INTEGER NOT NULL DEFAULT 0,
    nb_occurrences INTEGER NOT NULL DEFAULT 1,
    primary_evidence TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    references_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_v2_scan       ON findings_v2(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_v2_confidence ON findings_v2(confidence);
CREATE INDEX IF NOT EXISTS idx_findings_v2_severity   ON findings_v2(severity);

CREATE TABLE IF NOT EXISTS finding_instances (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    param_name TEXT,
    payload TEXT,
    evidence_raw TEXT NOT NULL DEFAULT '',
    request TEXT,
    response_excerpt TEXT,
    source_tool TEXT NOT NULL DEFAULT 'unknown',
    source_module TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings_v2(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_instances_finding ON finding_instances(finding_id);

CREATE TABLE IF NOT EXISTS scan_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    producer TEXT NOT NULL,
    phase TEXT NOT NULL,
    kind TEXT NOT NULL,
    error TEXT NOT NULL,
    traceback TEXT,
    affected_target TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_errors_scan ON scan_errors(scan_id);

COMMIT;
