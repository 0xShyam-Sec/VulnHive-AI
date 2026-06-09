# Changelog

## 2.0.0 — 2026-06-09 — Engine Reliability & Presentation Uplift

### Breaking changes

- **Findings shape (DB + in-memory).** Flat `findings` rows are now split into
  `Finding` + `FindingInstance`. Multi-endpoint vulnerabilities preserve all
  affected URLs instead of collapsing into one row. Legacy table preserved as
  `findings_legacy` for one release. Schema migration `001_finding_instance_split`
  runs automatically on first dashboard boot; reversible via
  `python -m dashboard.migrations.runner` (call `run_migration_001_down`).
- **Validator semantics.** The `drop_false_positives=True` deletion is removed.
  The new `engine.confidence_labeler` assigns one of five confidence labels:
  `confirmed / high / medium / low / false_positive`. Nothing is deleted; the
  dashboard filter decides what is visible.
- **`pipeline.run_multi_agent()` return shape.** Still returns a list of dicts
  for backward compatibility, but each dict gains `confidence` and
  `nb_occurrences` fields.
- **Python version.** Project now runs on Python 3.14 (was 3.9). All new
  dependencies (instructor, pydantic 2.x) require 3.10+.

### Added

- `Finding` + `FindingInstance` Pydantic models (`engine/finding_model.py`).
- `FindingProducer` abstraction (`engine/producer.py`).
- `engine/modes.py` — single source of truth for mode → producer set.
  `multi-agent` now includes Nuclei + Playwright by default.
- `engine/safe_run.py` — one boundary for producer error policy.
- `engine/runner.py` — async runner with real `asyncio.gather` parallelism
  (3 producers × 1s sleep → 1.13s elapsed, verified).
- `agents/llm_client.py` — Instructor + Ollama OpenAI-compatible API
  (qwen3:14b default; deepseek-r1:14b for `business_logic`, `auth_bypass`,
  `oauth`, `race_condition`, `ato`). Strips `<think>...</think>` blocks from
  deepseek-r1 output.
- `engine/confidence_labeler.py` — replaces FP deletion with relabeling.
- Producer wrappers for `passive_recon`, `playwright_crawler`, `nuclei`,
  `nmap`, `shodan`, and all 25 vuln agents (`agents/vuln/*.py`).
- `scan_errors` table + Scan Health pill (Healthy / Partial / Degraded) in
  dashboard.
- Detailed finding cards (CWE/CVSS/payload/confidence dots) + 5-tab detail
  modal (Overview / Evidence / Affected / Remediation / References).
- Findings page filter UI (severity × confidence × status × hidden toggle).
- Per-agent SSE sub-progress + 5-second heartbeat. Channel mapping in
  `dashboard/sse.py` (`scan:<id>:findings`, `:progress`, `:heartbeat`,
  `:errors`, `:logs`, `:done`).
- Cross-platform PDF (WeasyPrint default, Playwright fallback). Set
  `VULNHIVE_PDF_ENGINE=playwright` to switch globally, or pass per-call.
- `tests/` test tree with unit/integration/e2e/migration suites
  (68 tests passing, ruff clean).
- `.github/workflows/test.yml` GitHub Actions CI workflow.

### Fixed

- **Tier 1 #1**: Dashboard worker now honors `config[mode]`. Was hardcoded to
  always call `run_multi_agent` regardless of user selection. `_execute_scan`
  in `dashboard/worker.py` dispatches via `engine/modes.MODE_PRODUCERS`.
- **Tier 1 #2**: Confidence labeler replaces silent FP deletion. Validator now
  labels with `confirmed/high/medium/low/false_positive`. Dashboard default
  filter hides `low` and `false_positive` behind a toggle.
- **Tier 1 #3**: Dedup preserves multi-endpoint issues via `FindingInstance`.
  50 CORS misconfigs on different hosts → 1 Finding + 50 Instances with
  `nb_occurrences = 50`.
- **Tier 1 #4**: Nuclei included in `multi-agent` by default; Nmap/Shodan in
  `full`. Both run as `FindingProducer`s emitting the same Finding shape.
- **Tier 1 #5**: Playwright now emits `idor_target` findings for endpoints
  tagged `auth_required` (uses the existing `Endpoint.auth_required` flag).
- **Tier 1 #6**: 8 silent-skip bare-excepts in `agents/base.py`,
  `agents/orchestrator.py`, and `pipeline.py` replaced with structured
  `log.warning/error` calls. Ruff `S110/S112` ban enforced in CI; legacy
  modules grandfathered via per-file-ignores.
- **Tier 2 #7**: Instructor + Ollama `format=json` ends regex-based JSON
  parsing. Pydantic validation + auto-retry on malformed output.
- **Tier 2 #9**: Producers run truly in parallel via `asyncio.gather`. No more
  `asyncio.run()` blocking inside `agent.run()`.
- **Tier 3 #10**: Finding cards surface CWE/CVSS/payload/evidence/confidence;
  click opens 5-tab detail modal. CWE/CVSS populated at write-time from
  `engine/classification.py`.
- **Tier 3 #12**: Per-agent sub-progress bars + 5s heartbeat in the dashboard.
  Kill the "stuck at 40%" feeling in long Phase 3 (attack) phases.
- **Tier 3 #13**: WeasyPrint by default. Works on Linux/Windows/macOS
  without a browser dependency. Playwright fallback retained for JS-rendered
  chart libraries.
- Stop button responsive within ~1s: producers check `ctx.cancelled` between
  work units; worker polls Redis `vulnhive:stop:<scan_id>` flag every 0.5s
  and propagates to `ctx.cancel()`.

### Observability

- `structlog` with three sinks: rich console (human-readable), JSONL file
  (`logs/scan_<id>.jsonl`), Redis pubsub (`scan:<id>:logs`).
- `ScanError` record persisted to `scan_errors` table; dashboard shows
  health pill (Healthy / Partial / Degraded) with click-to-expand error list.

### Out of scope (future)

- Bugcrowd VRT taxonomy column (deferred; `references_json` reserves space).
- 7-Question Triage Gate (PASS / DOWNGRADE / KILL).
- URL-shape prioritizer (only run agents matching URL patterns).
- Anthropic backend with native tool-use (current `.env` key is wrong).

### Migration notes

First dashboard boot on 2.0.0 triggers schema migration 001 automatically. Old
data is preserved in `findings_legacy` for one release. To roll back:
```python
from pathlib import Path
from dashboard.migrations.runner import run_migration_001_down
run_migration_001_down(Path("dashboard/vulnhive.db"))
```
External scripts reading `dashboard.db.list_findings()` as `list[dict]` should
upgrade to the Pydantic model API (`dashboard.repository.list_findings_for_scan`)
or convert via `[f.model_dump() for f in ...]`.

The venv was rebuilt on Python 3.14 (was 3.9). The old venv is preserved at
`./venv.bak-py39-mixed/` for reference; safe to delete after verifying 2.0.0
works.

---

## 1.x — pre-2026-06

Earlier releases. See git history (`git log --before=2026-06-09`).
