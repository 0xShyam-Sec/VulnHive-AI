-- Reverse migration 001: restore legacy findings table.

BEGIN;
DROP TABLE IF EXISTS finding_instances;
DROP TABLE IF EXISTS findings_v2;
DROP TABLE IF EXISTS scan_errors;

-- If a swap was performed, rename back. Otherwise nothing to do.
COMMIT;
