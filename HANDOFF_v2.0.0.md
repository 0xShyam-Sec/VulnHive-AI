# VulnHive AI — v2.0.0 Complete Session Handoff

> **For a new Claude Code session picking up after a laptop transfer.**
> Read this top-to-bottom. It is the canonical record of all work done in
> the session that produced VulnHive AI v2.0.0.
> Author: Claude Opus 4.7 (1M context) · Document date: 2026-06-11

---

## 0. TL;DR — Where things stand right now

- **Released v2.0.0** on 2026-06-09. Tag `v2.0.0` on `main`, pushed to GitHub.
- **All Tier 1 + Tier 2 + selected Tier 3 fixes** from the v2.0.0 spec landed
  across 41 commits (38 on the feature branch + 3 post-merge cleanups).
- **68 automated tests passing** (`pytest tests/unit tests/integration tests/migration`).
  Ruff clean project-wide.
- **GitHub Actions CI** runs on every push; `lint-and-test` job is the gate
  and currently goes green in ~1 minute.
- **33-page project report PDF** generated for non-technical readers, at
  `/Users/shyamk/Downloads/VulnHive_AI_Report_v2.pdf` (also committed at
  `presentation/VulnHive_AI_Report_v2.pdf`).
- **Python upgraded 3.9 → 3.14.** Old venv preserved at `./venv.bak-py39-mixed/`.
- **The branch `spec/engine-reliability-uplift` has been merged into `main`
  and deleted locally.** GitHub also has the merged commits.

**If you only read three files in the repo:**
1. `CHANGELOG.md` — comprehensive list of v2.0.0 changes
2. `docs/superpowers/specs/2026-06-09-engine-reliability-and-presentation-uplift-design.md` — the design
3. `docs/superpowers/plans/2026-06-09-engine-reliability-and-presentation-uplift.md` — the 36-task implementation plan

---

## 1. Critical pointers (where to find things)

| Resource | Path |
|---|---|
| **This handoff** | `HANDOFF_v2.0.0.md` (you are reading it) |
| Pre-v2.0.0 handoff | `HANDOFF.md` (kept for historical context; my v2.0.0 pointer at the top) |
| v2.0.0 design spec | `docs/superpowers/specs/2026-06-09-engine-reliability-and-presentation-uplift-design.md` |
| v2.0.0 implementation plan | `docs/superpowers/plans/2026-06-09-engine-reliability-and-presentation-uplift.md` |
| CHANGELOG | `CHANGELOG.md` |
| Project report PDF (v2.0.0) | `presentation/VulnHive_AI_Report_v2.pdf` |
| Project report source HTML | `presentation/vulnhive_report_v2.html` |
| Earlier project report PDF (v1.x, historical) | `presentation/VulnHive_AI_Report.pdf` |
| GitHub repo | https://github.com/0xShyam-Sec/VulnHive-AI |
| CI workflow | `.github/workflows/test.yml` |

---

## 2. The 14-issue audit that started v2.0.0

The previous session began with a forensic audit: the user said "the tool has
solid functionality but is not working as expected." Four parallel auditor
subagents inspected pipeline / orchestration, vuln agents / LLM / skills,
discovery / validators, and dashboard / reporting. They surfaced 14 issues
across three tiers.

### Tier 1 — Findings silently lost (all 6 fixed in v2.0.0)
| # | Issue | File | Status |
|---|---|---|---|
| 1 | Dashboard worker ignores user's mode selection | `dashboard/worker.py:254` (pre-v2.0.0) | ✅ Fixed (Task 19) |
| 2 | `drop_false_positives=True` hardcoded — silent FP delete | `agents/orchestrator.py:209` | ✅ Fixed (Task 18 + post-merge fix) |
| 3 | Over-aggressive dedup collapses multi-endpoint issues | `agents/orchestrator.py:187` | ✅ Fixed (Task 6 — Finding+Instance) |
| 4 | Nmap / Nuclei / Shodan only in `--mode full` | `pipeline.py:185-260` | ✅ Fixed (Task 8 — modes table) |
| 5 | Playwright crawler discovers endpoints but never emits findings | `discovery/playwright_crawler.py:265` | ✅ Fixed (Task 15) |
| 6 | 8+ bare-excepts swallow skill/validator/LLM errors | `agents/base.py:79, 137, 192, 217, 539; pipeline.py:149, 248; agents/orchestrator.py:230` | ✅ Fixed (Task 20) |

### Tier 2 — Reliability / speed (#7 and #9 fixed; #8 skipped)
| # | Issue | Status |
|---|---|---|
| 7 | Ollama JSON parsing fragile (3 regex fallbacks; malformed → silent drop) | ✅ Fixed via Instructor + Ollama `format=json` (Task 11) |
| 8 | Anthropic key in `.env` is actually an OpenAI key | ⏭ **Skipped — out of scope.** User chose to stay on Ollama. Still broken in `.env`. |
| 9 | "Parallel" agents not actually parallel — `asyncio.run()` blocks | ✅ Fixed (Task 10) — verified 3 producers × 1s sleep → 1.13s elapsed |

### Tier 3 — Presentation (#10, #12, #13 fixed; #11 and #14 skipped)
| # | Issue | Status |
|---|---|---|
| 10 | Dashboard cards hide CWE/CVSS/payload/evidence | ✅ Fixed (Task 22 — detailed cards + Task 23 — 5-tab modal + Task 24 — filter UI) |
| 11 | No VRT column; CWE unpopulated | ⏭ **Skipped.** CWE/CVSS *minimum* population landed via `engine/classification.py`. Full VRT taxonomy deferred. |
| 12 | Phase 3 (attack) shows 40% for 4+ min with no sub-progress | ✅ Fixed (Tasks 25 + 26 — per-agent SSE progress + heartbeat + sub-progress UI) |
| 13 | PDF gen hardcoded to macOS Chrome path | ✅ Fixed (Task 28 — WeasyPrint default, Playwright fallback) |
| 14 | "Chat with findings" is dead code | ⏭ **Skipped.** Schema exists in `dashboard/db.py:108-116`, no routes wired. Future cycle. |

**Also addressed (not numbered):** Scan Health pill + structured logging (Tasks 1, 2, 27).

---

## 3. v2.0.0 architecture in one diagram

```
┌───────────────────────────────────────────────────────────────────┐
│  MODE TABLE  (engine/modes.py — one source of truth)              │
│  multi-agent → [passive_recon, playwright, nuclei, waf_detector,  │
│                 …all 25 vuln agents]                              │
│  full        → [nmap, shodan, …everything from multi-agent…]      │
└───────────────────────────────┬───────────────────────────────────┘
                                ▼
┌──────────────── PRODUCERS (engine/producers/*) ────────────────┐
│  Each yields Finding objects asynchronously. ~30 producers     │
│  total: 25 vuln agents + 5 importers/crawlers + null stubs.    │
└───────────────────────────────┬────────────────────────────────┘
                                ▼  (asyncio.gather, true parallel)
┌──────────────── SAFE-RUN BOUNDARY (engine/safe_run.py) ────────┐
│  Catches exceptions. Other producers continue.                 │
│  Records ScanError(kind=producer_fatal) for the failed one.    │
└───────────────────────────────┬────────────────────────────────┘
                                ▼
┌──────────────── DEDUP + CONFIDENCE LABELER ────────────────────┐
│  Same (rule_id, cwe, title) → one Finding, many Instances.     │
│  Confidence labeler relabels — never deletes.                  │
└───────────────────────────────┬────────────────────────────────┘
                                ▼
┌──────────────── PERSISTENCE (SQLite) ──────────────────────────┐
│  findings + finding_instances + scan_errors tables.            │
│  Reversible schema migration runs on first boot.               │
└───────────────────────────────┬────────────────────────────────┘
                                ▼
┌──────────────── REDIS PUBSUB ──────────────────────────────────┐
│  scan:<id>:findings  scan:<id>:progress                        │
│  scan:<id>:heartbeat scan:<id>:errors  scan:<id>:logs          │
└───────────────────────────────┬────────────────────────────────┘
                                ▼  (Server-Sent Events)
┌──────────────── HTMX DASHBOARD ────────────────────────────────┐
│  Cards swap in, modal opens on click, progress bars update,    │
│  heartbeat pulses, errors stream live. No JS framework.        │
└────────────────────────────────────────────────────────────────┘
```

---

## 4. The 41-commit changelog (chronological, with rationale)

### Pre-flight (Tasks 0a–0d, commits 1–4)

| SHA | Commit | What and why |
|---|---|---|
| `f75b0b2` | `build: add pydantic, structlog, instructor, weasyprint, pytest deps` | 8 new dependencies. Triggered the Python version reckoning (see §6 — venv issue). |
| (no commit) | venv rebuild | Old `./venv/` was a Python 3.14 venv with a Python 3.9 binary spliced in. Rebuilt cleanly with `python3.14 -m venv venv`. Old venv preserved as `./venv.bak-py39-mixed/`. |
| `f472ad2` | `build: configure ruff with S110/S112 bare-except ban + pytest-asyncio` | `pyproject.toml` with ruff S110/S112 (bare-except ban) + pytest asyncio mode + target-version py310. |
| `fae294e` | `test: scaffold tests/{unit,integration,e2e,migration,legacy} with conftest` | Test tree created. The 3 root-level `test_*.py` files moved into `tests/legacy/`. |

### Phase 1 — Engine reliability (Tasks 1–20, commits 5–24)

| SHA | Commit | What it does |
|---|---|---|
| `818ad4f` | `feat(engine): add error taxonomy (Fatal, ProducerFatal, ScanError)` | `engine/errors.py` — three error classes. |
| `e988fb9` | `feat(engine): structlog with rich console + file + Redis sinks` | `engine/logging_setup.py` — observable everywhere. |
| `f6c2578` | `feat(engine): Finding + FindingInstance Pydantic models + legacy adapters` | The new data model. |
| `a6e31d4` | `feat(engine): CWE + CVSS defaults keyed by vuln_type` | `engine/classification.py` — populates the new fields. |
| `0cb0119` | `feat(db): migration 001 — split flat findings into Finding+Instance` | Reversible + idempotent SQL migration. |
| `bb1bfa7` | `feat(db): repository.save_finding with dedup + instance merging` | Dedup by `(scan_id, rule_id, vuln_type, normalized_title, cwe)`; new URL → new Instance + `nb_occurrences++`. **Also fixed a Task 5 bug** (fresh-DB path never renamed findings_v2 → findings). |
| `7662442` | `chore: remove unused datetime import in test_errors` | Code-quality review cleanup. |
| `71a4325` | `feat(engine): FindingProducer ABC + ScanContext (progress, cancel, errors)` | The producer base class. |
| `ddd0e06` | `feat(engine): MODE_PRODUCERS table — nuclei now in multi-agent default` | One source of truth for mode → producer set. |
| `777b988` | `feat(engine): safe_produce — one boundary for producer error policy` | Single decorator that catches exceptions and records `ScanError`. |
| `7f44c46` | `feat(engine): async runner with real parallelism + persistence pipeline` | `engine/runner.py` — `asyncio.gather`. **3 × 1s producers → 1.13s elapsed** (verified test). |
| `4158374` | `feat(agents): Instructor + Ollama structured output (qwen3 / deepseek-r1)` | `agents/llm_client.py` — replaces regex parsing with Pydantic-validated, auto-retry LLM calls. Deepseek `<think>` block stripper. |
| `2683619` | `feat(producers): PassiveReconProducer + mock target fixture for integration tests` | First producer. Mock target Flask app at `tests/fixtures/mock_target/app.py`. **Adapted**: legacy passive_recon emits `missing_security_header_<name>` not `missing_security_header`. Added `_normalise_vuln_type()`. |
| `9601f5b` | `feat(producers): NucleiProducer importer — parses JSONL, populates CWE/CVE` | Nuclei output as findings. Live mode shells out to nuclei binary. |
| `66de1e2` | `feat(producers): NmapProducer + ShodanProducer importers` | Nmap XML → one finding per open port. Shodan via free InternetDB endpoint (no key needed). |
| `6a9e4b8` | `feat(producers): Playwright crawler now emits Findings for auth_required endpoints` | **Closes Tier 1 #5.** Uses existing `Endpoint.auth_required: bool` (no new dataclass needed). |
| `6c19cf8` | `feat(producers): generic VulnAgentProducer adapter for legacy agents` | Wraps any `agents/vuln/*.py` class. Maps `validated=1` + payload + evidence → `Confidence.confirmed`. |
| `88d982f` | `feat(producers): registry mapping every producer name to its factory` | `engine/producers/registry.py` — all 25 vuln agents + 5 importers/crawlers + 3 null-stub producers. **Class names corrected**: `SQLiAgent` not `SqliAgent`, `CMDIAgent` not `CmdiAgent`, etc. (See §5 for the full table.) Also adds `security_headers` to `classification.py`. |
| `d6b4572` | `feat(engine): confidence_labeler replaces drop_false_positives deletion` | **Closes Tier 1 #2.** Relabels evidence → 5-tier confidence. Wired into `engine/runner.py`'s persistence loop. |
| `c017ad0` | `feat(pipeline): worker honors config[mode]; pipeline.py shims call runner` | **Closes Tier 1 #1 + #4.** `dashboard/worker.py:_resolve_producers_for_mode` + `_execute_scan`. `pipeline.run_multi_agent` becomes a thin runner shim. Test mocks `redis` module since it's not installed for unit tests. |
| `b3d40bb` | `fix: replace 8+ bare-excepts with structured log + recover` | **Closes Tier 1 #6.** 7 in `agents/base.py`, 1 in `agents/orchestrator.py`. `pipeline.py`'s only `except Exception:` had a real body, not `pass` — already clean. |

### Phase 1 → Phase 2 transition (commit 25)

| SHA | Commit | What it does |
|---|---|---|
| `873f028` | `chore: tighten ruff config + cleanup unused imports` | Expanded `pyproject.toml` per-file-ignores to cover all legacy modules (agents/recon.py, auth.py, etc. — about 30 files). Removed an unused `Optional` import in `pipeline.py` left over from the Task 19 shim rewrite. Also removed unused `os`/`tempfile` from `tests/conftest.py`. |
| Tag: `v2.0.0-phase1-engine` | (annotated tag) | Phase 1 milestone. |

### Phase 2 — Presentation (Tasks 22–31, commits 26–35)

| SHA | Commit | What it does |
|---|---|---|
| `6c07e4d` | `feat(dashboard): finding card shows CWE, CVSS, payload, confidence dots` | **Closes Tier 3 #10.** New `dashboard/templates/partials/finding_card.html` + `dashboard/static/css/findings.css` + linked from `base.html`. Cards now show severity badge, confidence dots (●●●●○ etc.), CWE link to MITRE, CVSS, payload preview, instance counter. Click → modal. |
| `5f814f5` | `feat(dashboard): finding detail modal with 5 tabs (overview/evidence/instances/remediation/refs)` | HTMX-loaded modal at `/findings/<string:finding_id>/modal`. **Note**: uses `<string:>` converter (Finding.id is a UUID), distinct from legacy `/findings/<int:finding_id>/status` route. |
| `cbd26d4` | `feat(dashboard): filter findings by severity x confidence x status` | `dashboard/repository.list_findings_filtered` + new `findings.html` template + revised `/findings` route. HTMX `change delay:200ms` for live updates. Default hides Low + False-positive (with toggle). |
| `ff4cf68` | `feat(sse): per-producer progress + 5s heartbeat events` | `engine/runner._emit_heartbeat`. `dashboard/sse.py` event-name constants + suffix→event map. Subscribes to `vulnhive:scan:*` (legacy) AND `scan:*` (direct runner format). |
| `79a812b` | `feat(dashboard): per-agent sub-progress bars + heartbeat live UI` | Producers call `ctx.progress(producer, current, total, last, finished)`. New `scan_live_progress.html` partial (three-tier: overall / phase / per-agent rows). `scan_detail.html` updated. Route passes `producer_names`. |
| `fe372f7` | `feat(dashboard): Scan Health pill (ok/partial/degraded) + live error stream` | `record_error()` publishes to Redis `scan:<id>:errors`. `scan_health.html` partial with health pill + collapsible error table. CSS appended. |
| `a89dc5d` | `feat(dashboard): cross-platform PDF (WeasyPrint default, Playwright fallback)` | **Closes Tier 3 #13.** `dashboard/pdf.py:render_pdf(html, out_path, engine)`. Default engine via `VULNHIVE_PDF_ENGINE` env var. `dashboard/app.py` PDF route rewired. |
| `9763f72` | `feat: stop button cancels within ~1s by checking ctx.cancelled per work unit` | `engine/runner.run_scan` gains `on_ctx` callback. `dashboard/worker._execute_scan` polls Redis `vulnhive:stop:<scan_id>` every 0.5s. |
| `26ef0dc` | `test(e2e): DVWA multi-agent smoke — floor 30 findings, CWE populated, mixed confidence` | `tests/e2e/test_dvwa_smoke.py`. Skipped unless `DVWA_AVAILABLE=1`. |
| `294d947` | `ci: GitHub Actions workflow — ruff + unit/integration/migration + DVWA e2e` | `.github/workflows/test.yml`. |

### Release commits (36–38)

| SHA | Commit | What it does |
|---|---|---|
| `0949afa` | `chore(release): 2.0.0 — engine reliability + presentation uplift` | Added `__version__ = "2.0.0"` to `main.py`; comprehensive `CHANGELOG.md`. |
| `531e474` | `docs(handoff): add v2.0.0 release notes pointer at top of HANDOFF.md` | Added a v2.0.0 section to the top of the existing `HANDOFF.md`. |
| `dffdd62` | `fix(orchestrator): drop_false_positives=False to match v2.0.0 contract` | **Post-final-review fix.** The legacy `agents/orchestrator.run_multi_agent_scan` path still passed `drop_false_positives=True`. Flipped to False to honor the CHANGELOG promise. |
| Tag: `v2.0.0-phase2-presentation` | (annotated tag) | Phase 2 milestone. |
| Tag: `v2.0.0` | (annotated tag) | Full release. |

### Merge to main + push (commits 39–41)

| SHA | Commit | What it does |
|---|---|---|
| `af8f2c9` | `Merge v2.0.0: engine reliability + presentation uplift` (merge commit, `--no-ff`) | Merged `spec/engine-reliability-uplift` → `main`. Feature branch deleted. |
| Pushed to origin/main + all tags. |
| `147309f` | `ci: drop e2e-dvwa job; fix sys.executable + Ollama-availability gate` | **First CI run after push failed** on the e2e job because (1) `./venv/bin/python` doesn't exist in GHA runners, and (2) default GHA runners (~7GB RAM) can't host qwen3:14b (~9GB model). Fix: use `sys.executable`; require BOTH `DVWA_AVAILABLE=1` and `OLLAMA_AVAILABLE=1`; remove the e2e-dvwa job from CI entirely (documented how to run locally). |
| `f5af1ee` | `docs(presentation): v2.0.0 project report — 33-page PDF + HTML source` | 33-page user/project report PDF generated via WeasyPrint at `presentation/VulnHive_AI_Report_v2.pdf` + source HTML at `presentation/vulnhive_report_v2.html`. |

**Total: 41 commits on `main` (38 on feature branch + 3 post-merge).**

---

## 5. The 25 vuln agents — name correction table

The audit's plan-doc used incorrect class names. The **actual** class names use uppercase acronyms (SQLiAgent, not SqliAgent; XSSAgent not XssAgent; etc.). This table is correct as of v2.0.0 and is what's in `engine/producers/registry.py`:

| Module | Class | `vuln_type` | Notes |
|--------|-------|---|---|
| `agents.vuln.api_version` | `APIVersionAgent` | `api_version` | |
| `agents.vuln.auth_bypass` | `AuthBypassAgent` | `auth_bypass` | Uses deepseek-r1 (reasoning) |
| `agents.vuln.business_logic` | `BusinessLogicAgent` | `business_logic` | Uses deepseek-r1 (reasoning) |
| `agents.vuln.cache_poison` | `CachePoisonAgent` | `cache_poison` | |
| `agents.vuln.cmdi` | `CMDIAgent` | `command_injection` | ⚠ vuln_type ≠ module name |
| `agents.vuln.csrf` | `CSRFAgent` | `csrf` | |
| `agents.vuln.file_upload` | `FileUploadAgent` | `file_upload` | |
| `agents.vuln.graphql` | `GraphQLAgent` | `graphql` | |
| `agents.vuln.headers` | `HeadersAgent` | `security_headers` | ⚠ vuln_type ≠ module name; added to `classification.py` |
| `agents.vuln.http_smuggling` | `HTTPSmugglingAgent` | `http_smuggling` | |
| `agents.vuln.idor` | `IDORAgent` | `idor` | |
| `agents.vuln.idor_advanced` | `IDORAdvancedAgent` | `idor` | Maps to same vuln_type as basic IDOR |
| `agents.vuln.jwt` | `JWTAgent` | `jwt` | |
| `agents.vuln.mass_assignment` | `MassAssignmentAgent` | `mass_assignment` | |
| `agents.vuln.open_redirect` | `OpenRedirectAgent` | `open_redirect` | |
| `agents.vuln.path_traversal` | `PathTraversalAgent` | `path_traversal` | |
| `agents.vuln.rate_limit` | `RateLimitAgent` | `rate_limit` | |
| `agents.vuln.sensitive_data` | `SensitiveDataAgent` | `sensitive_data` | |
| `agents.vuln.sqli` | `SQLiAgent` | `sqli` | |
| `agents.vuln.ssrf` | `SSRFAgent` | `ssrf` | |
| `agents.vuln.ssti` | `SSTIAgent` | `ssti` | |
| `agents.vuln.subdomain` | `SubdomainAgent` | `subdomain` | |
| `agents.vuln.websocket` | `WebSocketAgent` | `websocket` | |
| `agents.vuln.xss` | `XSSAgent` | `xss` | |
| `agents.vuln.xxe` | `XXEAgent` | `xxe` | |

**Model assignment**: `agents/llm_client.MODEL_PER_AGENT` routes `business_logic`, `auth_bypass`, `oauth`, `race_condition`, `ato` to **deepseek-r1:14b**. Everything else uses **qwen3:14b** (the default).

---

## 6. Environment setup

### Python version

**Project Python is 3.14.** The previous version's HANDOFF.md said 3.9, but v2.0.0 required 3.10+ (instructor, pydantic 2.x use `X | Y` union syntax).

Venv layout:
- `./venv/` — current. Python 3.14. Created with `python3.14 -m venv venv`.
- `./venv.bak-py39-mixed/` — backup of the broken pre-v2.0.0 venv. **Safe to delete** when you're confident things work.

Confirm: `./venv/bin/python --version` → `Python 3.14.3`

### System dependencies (macOS via brew)

WeasyPrint needs native libs:
```bash
brew install pango cairo
```

These were installed during the v2.0.0 work. Other tools the project uses (some optional):
- `nmap` (for the NmapProducer)
- `nuclei` (for the NucleiProducer; both binary and template set)
- `redis` (`brew services start redis` to start; required for dashboard)
- Docker + `docker-compose` (for the DVWA test target)

### Python dependencies (`requirements.txt`)

Pre-v2.0.0 had 11 entries; v2.0.0 added 8:
```
# Pre-existing
anthropic>=0.40.0
openpyxl>=3.1.0
httpx>=0.27.0
beautifulsoup4>=4.12.0
playwright>=1.48.0
python-dotenv>=1.0.0
rich>=13.9.0
aiodns>=3.1.0
groq>=1.0.0
google-genai>=1.0.0
flask>=3.0.0

# Added in v2.0.0
pydantic>=2.5.0
structlog>=24.1.0
instructor>=1.3.0
openai>=1.30.0
weasyprint>=62.0
pytest>=8.0.0
pytest-asyncio>=0.23.0
ruff>=0.5.0
```

Also installed at runtime but not in requirements.txt: `pypdf` (used once to extract text from the v1.x report; not needed for runtime).

### Environment variables

| Var | Used by | Default | What it does |
|---|---|---|---|
| `VULNHIVE_PDF_ENGINE` | `dashboard/pdf.py` | `weasyprint` | Set to `playwright` to use Chromium for JS-rendered chart libraries |
| `VULNHIVE_LOG_DIR` | (reserved) | `logs/` | Where structlog file sink writes |
| `OBJC_DISABLE_INITIALIZE_FORK_SAFETY` | macOS worker | (unset) | **MUST be set to `YES` for the dashboard worker on macOS.** Without it, the worker fork crashes. |
| `DVWA_AVAILABLE` | e2e tests | `0` | Set to `1` when DVWA is running on `:8080` to enable e2e tests |
| `OLLAMA_AVAILABLE` | e2e tests | `0` | Set to `1` when Ollama with qwen3:14b is running |
| `GROQ_API_KEY` | optional LLM backend | (unset) | Free cloud AI alternative |
| `GEMINI_API_KEY` | optional LLM backend | (unset) | Free cloud AI (region-restricted) |
| `ANTHROPIC_API_KEY` | optional LLM backend | (wrong key) | **STILL BROKEN** — `.env` has an OpenAI key labelled as Anthropic. See §10. |

---

## 7. Common commands (cheat sheet)

### Activate environment
```bash
cd /Users/shyamk/Documents/pentest-agent
source venv/bin/activate
```

### Run tests
```bash
./venv/bin/pytest tests/unit tests/integration tests/migration -v   # 68 passing
./venv/bin/ruff check .                                              # must be clean
```

### Run a CLI scan
```bash
./venv/bin/python main.py --target http://localhost:8080 --mode multi-agent --llm ollama
```

### Run the dashboard (TWO terminals)
```bash
# Terminal 1
brew services start redis
./venv/bin/python main.py --dashboard --port 5001

# Terminal 2 (MUST set the fork-safety var on macOS)
OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ./venv/bin/python -m dashboard.worker
```

Then open http://localhost:5001 in a browser.

### Bring up DVWA target
```bash
docker compose up -d   # DVWA at http://localhost:8080  (admin/password)
```

### Run the e2e DVWA smoke locally
```bash
DVWA_AVAILABLE=1 OLLAMA_AVAILABLE=1 ./venv/bin/pytest tests/e2e -v -m e2e
```

### Re-render the project report PDF
```bash
./venv/bin/python -c "
from dashboard.pdf import render_pdf
from pathlib import Path
html = Path('presentation/vulnhive_report_v2.html').read_text()
render_pdf(html, Path('/Users/shyamk/Downloads/VulnHive_AI_Report_v2.pdf'))
print('OK')
"
```

### Rollback the DB schema migration
```bash
./venv/bin/python -c "
from pathlib import Path
from dashboard.migrations.runner import run_migration_001_down
run_migration_001_down(Path('dashboard/vulnhive.db'))
"
```

### Inspect git state
```bash
git log --oneline -20             # recent commits
git tag -l 'v2.*'                  # list v2.x tags
git log v2.0.0-phase1-engine..v2.0.0   # what landed in Phase 2
```

---

## 8. New file map (what was added in v2.0.0)

### New `engine/` modules
```
engine/
├── errors.py                    # FatalError, ProducerFatalError, ScanError dataclass
├── logging_setup.py             # structlog with rich/file/Redis sinks
├── finding_model.py             # Pydantic Finding + FindingInstance + adapters
├── classification.py            # CWE/CVSS lookup keyed by vuln_type
├── producer.py                  # FindingProducer ABC + ScanContext
├── modes.py                     # MODE_PRODUCERS + ALL_VULN_AGENTS
├── safe_run.py                  # safe_produce error boundary
├── runner.py                    # Async runner with parallelism + heartbeat
├── confidence_labeler.py        # 5-tier confidence relabeler
└── producers/
    ├── __init__.py
    ├── passive_recon.py         # Wraps discovery/passive_recon.py
    ├── playwright_crawler.py    # NEW: emits IDOR-candidate findings
    ├── nuclei.py                # JSONL parser + live shell-out
    ├── nmap.py                  # XML parser + live shell-out
    ├── shodan.py                # Free InternetDB endpoint
    ├── vuln_agent.py            # Generic VulnAgentProducer adapter
    └── registry.py              # PRODUCER_FACTORIES dict
```

### New `agents/` module
```
agents/
└── llm_client.py                # Instructor wrapper for Ollama + model picker
```

### Dashboard new files
```
dashboard/
├── repository.py                # Pydantic-typed find/save/list functions
├── pdf.py                       # WeasyPrint default, Playwright fallback
├── migrations/
│   ├── __init__.py
│   ├── 001_finding_instance_split_up.sql
│   ├── 001_finding_instance_split_down.sql
│   └── runner.py                # Idempotent + reversible migrator
├── static/css/
│   └── findings.css             # Severity, confidence-dots, health-pill styles
└── templates/
    ├── partials/
    │   ├── finding_card.html    # REWRITTEN — shows CWE/CVSS/payload/dots
    │   ├── finding_detail_modal.html  # NEW — 5-tab modal
    │   ├── scan_live_progress.html    # NEW — three-tier progress UI
    │   └── scan_health.html     # NEW — health pill
    └── (base.html, findings.html, scan_detail.html — modified)
```

### Tests tree (NEW)
```
tests/
├── conftest.py                  # tmp_db, in_memory_db, event_loop fixtures
├── unit/                        # ~10 unit test files (30 tests)
│   ├── test_errors.py
│   ├── test_logging_setup.py
│   ├── test_finding_model.py
│   ├── test_classification.py
│   ├── test_producer.py
│   ├── test_modes.py
│   ├── test_safe_run.py
│   ├── test_llm_client.py
│   └── test_producer_registry.py
├── integration/                 # ~14 integration test files (35 tests)
│   ├── test_repository.py
│   ├── test_runner_parallel.py            # Proves 3×1s → 1.13s elapsed
│   ├── test_passive_recon_producer.py
│   ├── test_nuclei_producer.py
│   ├── test_importers_nmap_shodan.py
│   ├── test_playwright_producer.py
│   ├── test_vuln_agent_producer.py
│   ├── test_confidence_labeler.py
│   ├── test_worker_mode_dispatch.py
│   ├── test_finding_card_render.py
│   ├── test_finding_modal_render.py
│   ├── test_findings_filter.py
│   ├── test_progress_events.py
│   ├── test_producer_progress.py
│   ├── test_scan_health.py
│   ├── test_pdf_export.py
│   └── test_stop_button.py
├── migration/
│   └── test_migration_001.py    # 3 tests: up, down, idempotent
├── e2e/
│   └── test_dvwa_smoke.py       # SKIPPED unless DVWA+Ollama up
├── legacy/                      # 3 files moved from repo root
│   ├── test_api_schema_inference.py
│   ├── test_cmdi_verify.py
│   └── test_rate_limit_import.py
└── fixtures/
    ├── mock_target/app.py       # Tiny Flask app w/ planted issues
    └── recordings/
        ├── nuclei_sample.jsonl  # 2 sample Nuclei findings
        └── nmap_sample.xml      # 3-port sample
```

### Top-level new files
```
pyproject.toml                   # ruff + pytest config
CHANGELOG.md                     # v2.0.0 release notes
HANDOFF_v2.0.0.md                # (this file)
.github/workflows/test.yml       # CI workflow (lint-and-test only)
presentation/vulnhive_report_v2.html
presentation/VulnHive_AI_Report_v2.pdf
docs/superpowers/specs/2026-06-09-engine-reliability-and-presentation-uplift-design.md
docs/superpowers/plans/2026-06-09-engine-reliability-and-presentation-uplift.md
```

---

## 9. Known issues, gotchas, and decisions

### 9.1 Anthropic API key in `.env` is wrong (KNOWN, NOT FIXED)
The `.env` file has `ANTHROPIC_API_KEY=sk-...` but the value is actually an OpenAI key. This was Tier 2 #8 in the audit; the user chose to skip it. Result: `--llm anthropic` does not work. Stay on `--llm ollama` (default) or `--llm groq`.

To fix later: get a real `sk-ant-...` key from Anthropic and update `.env`.

### 9.2 The dashboard `chat.py` is dead code (KNOWN, NOT FIXED)
The schema for `chat_messages` exists in `dashboard/db.py` lines 108-116, but `dashboard/chat.py` was not migrated from v1. No routes consume the schema. Tier 3 #14 was explicitly out of scope for v2.0.0.

### 9.3 Legacy `agents/orchestrator.run_multi_agent_scan` still exists
The new pipeline goes via `engine/runner.run_scan`. The legacy orchestrator is **still importable and callable** (any code calling `agents.orchestrator.run_multi_agent_scan` directly will work) but:
- It no longer calls `drop_false_positives=True` (post-merge fix `dffdd62`)
- It's not called by anything in the v2.0.0 hot paths
- It can be removed in a future cycle once we're sure nothing depends on it

### 9.4 Python 3.14 `datetime.utcnow()` deprecation
`engine/errors.py` uses `_dt.datetime.now(_dt.timezone.utc).isoformat()` (the modern form). The verbatim plan-doc said `_dt.datetime.utcnow()` but that emits a DeprecationWarning on Python 3.14. **This pattern is the standard going forward.**

### 9.5 ruff per-file-ignores grandfather legacy code
Pre-v2.0.0 legacy modules have many S110/S112 (bare-except) violations, F401 (unused imports), F541 (f-strings without placeholders), etc. We chose NOT to fix them in this release (out of scope). Instead, `pyproject.toml` per-file-ignores grants exemptions:
- The 25 vuln agents under `agents/vuln/*.py`
- All `discovery/*.py`, `exploit/*.py`, `chain/*.py`
- Individual top-level legacy files (api_scanner.py, oauth_handler.py, etc.)
- `agents/base.py`, `agents/orchestrator.py`, `pipeline.py` keep S110/S112 strict (we fixed the audited spots) but get F841/E exemptions for other style issues.

**Rule for future work**: new files MUST pass ruff with all rules on. Legacy files can stay as-is until refactored.

### 9.6 The e2e DVWA test is intentionally not in CI
Default GitHub Actions runners (~7GB RAM) cannot host Ollama with qwen3:14b (~9GB model). The test is gated on `DVWA_AVAILABLE=1 AND OLLAMA_AVAILABLE=1` and must run locally before demos. To re-enable in CI later, a self-hosted runner with Ollama pre-installed would work.

### 9.7 The venv mixup history
The original `./venv/` had been created with Python 3.14 (per `pyvenv.cfg`) but had a Python 3.9 binary symlinked in, so `./venv/bin/python` was 3.9 while `./venv/bin/python3.14` was 3.14, with separate site-packages. The Task 0b implementer used pip from python3.14 to install but verified with python3.9 — hence the import errors. The fix was a clean venv rebuild on python3.14.

If you ever see weird module-not-found errors after installing dependencies: check `./venv/bin/python --version` and `./venv/bin/python -m pip --version` are talking about the same Python.

### 9.8 Dashboard worker requires `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` on macOS
Without this env var, the worker forks the work-horse process and crashes on macOS. Documented in HANDOFF.md §4 and in CHANGELOG.md.

### 9.9 The migration auto-runs on first dashboard boot
When you start the dashboard for the first time on v2.0.0, the SQLite migration `001_finding_instance_split` runs automatically (triggered by `dashboard/db.py:_apply_pending_migrations()`). This:
1. Creates `findings_v2`, `finding_instances`, `scan_errors` tables
2. Copies every existing `findings` row → `findings_v2` + `finding_instances`
3. Renames `findings` → `findings_legacy`
4. Renames `findings_v2` → `findings`

To roll back: see §7 "Rollback the DB schema migration".

### 9.10 `dashboard/templates/base.html` and `finding_card.html` had to be re-created
These were marked as new files in the commit history because the dashboard was previously untracked. They existed on disk but not in git. The v2.0.0 work formalised them into git history.

---

## 10. Roadmap — what's NOT in v2.0.0

Listed in priority order. The CHANGELOG §"Out of scope" mentions some of these:

1. **VRT (Vulnerability Rating Taxonomy) column** on every Finding. Bugcrowd's standard for classifying findings for bounty payouts. The `references_json` field on `Finding` is already designed to hold this. Estimated work: ~half a day.

2. **7-Question Triage Gate** — replaces the binary validator with a structured PASS / DOWNGRADE / KILL gate based on 7 yes/no questions. Pattern in `skills/triage-validation.md`. Estimated work: 1 day.

3. **URL-shape prioritiser** — only run agents matching URL patterns (e.g. `/search?q=` → SQLi first; `/api/users/{id}` → IDOR first). Cuts scan time significantly. Estimated work: 1 day.

4. **Anthropic backend fix** — replace the wrong `.env` key with a real `sk-ant-...` key. 5 minutes once the user gets a key.

5. **Reactivate "chat with findings"** — schema exists, AI assistant logic was in v1's `dashboard/chat.py` (deleted in v2 rebuild). Estimated work: half a day.

6. **Scheduled scans** — daily / weekly recurring scans via cron. Estimated work: 1 day.

7. **GitHub PR integration** — auto-scan code on every pull request. Estimated work: 2-3 days.

8. **SAST mode** — scan source code, not just live sites. Significant work (~1-2 weeks).

9. **Slack / Discord notifications** for critical findings. Estimated work: half a day.

10. **Cloud-security scanning** — AWS / Azure / GCP misconfigurations. Major effort (~2-4 weeks).

For each item, the **right way to start** is brainstorming → spec → plan → subagent-driven execution, the same workflow we used for v2.0.0.

---

## 11. The test suite — what's covered

68 passing tests + 1 e2e (skipped without env vars):

### `tests/unit/` — 10 files, ~30 tests
- `test_errors.py` — Fatal / ProducerFatal / ScanError types
- `test_logging_setup.py` — structlog 3-sink config + JSONL file output
- `test_finding_model.py` — Finding / Instance creation + legacy dict roundtrip
- `test_classification.py` — CWE/CVSS lookup
- `test_producer.py` — FindingProducer ABC + ScanContext (cancel, progress, errors)
- `test_modes.py` — mode→producers table assertions
- `test_safe_run.py` — error-boundary catches all but FatalError
- `test_llm_client.py` — model picker + deepseek `<think>` strip
- `test_producer_registry.py` — every vuln agent + importer is registered
- (`test_errors.py` was amended to remove the deprecation warning)

### `tests/integration/` — 17 files, ~35 tests
- `test_repository.py` — save + list + multi-URL collapse + scan errors
- `test_runner_parallel.py` — **3 × 1s producers → < 2s elapsed** (proves parallelism)
- `test_passive_recon_producer.py` — against the mock target Flask app
- `test_nuclei_producer.py` — JSONL parse → 2 findings, CWE/severity correct
- `test_importers_nmap_shodan.py` — Nmap XML → 3 findings; Shodan handles missing key
- `test_playwright_producer.py` — auth_required → idor_target findings
- `test_vuln_agent_producer.py` — stub agent → confidence=confirmed flow
- `test_confidence_labeler.py` — confirmed stays / strong-evidence promotes / no-evidence demotes / FP not deleted
- `test_worker_mode_dispatch.py` — full mode includes nmap; multi-agent doesn't; unknown→multi-agent
- `test_finding_card_render.py` — Jinja render snapshot has CWE/CVSS/payload/dots
- `test_finding_modal_render.py` — modal renders with/without instances
- `test_findings_filter.py` — severity × confidence × status filters + include_false_p
- `test_progress_events.py` — ctx.progress publishes; heartbeat fires N times
- `test_producer_progress.py` — Nuclei + VulnAgent emit progress per item
- `test_scan_health.py` — record_error publishes to Redis errors channel
- `test_pdf_export.py` — WeasyPrint renders minimal HTML; unknown engine raises
- `test_stop_button.py` — on_ctx callback captures ctx; cancel stops producer within 1s

### `tests/migration/` — 1 file, 3 tests
- `test_migration_001.py` — up creates tables + preserves rows; down restores; idempotent

### `tests/e2e/` — 1 file, 1 test (skipped by default)
- `test_dvwa_smoke.py` — Requires `DVWA_AVAILABLE=1 AND OLLAMA_AVAILABLE=1`. Asserts ≥30 findings, CWE populated, mixed confidence.

### `tests/legacy/` — 3 files relocated from repo root
- `test_api_schema_inference.py`
- `test_cmdi_verify.py`
- `test_rate_limit_import.py`

---

## 12. Original HANDOFF (pre-v2.0.0) — historical reference

The pre-v2.0.0 `HANDOFF.md` is preserved with a v2.0.0 pointer added at the top. It documents Phases A-D of the project (the work before this session):

- **Phase A** — Original CLI tool (pre-dashboard). 24 vuln agents, WAF detection, WHOIS/DNS, subdomain enum, Nmap/Nuclei integration.
- **Phase B** — Dashboard v1 (May 2026). Various issues piled up; backed up to `dashboard_v1_backup/`.
- **Phase C** — Dashboard v2 rebuild (June 1-2 2026). Flask + RQ + Redis + SQLite + SSE + HTMX. Most templates and JS came from this work.
- **Phase D** — Skills knowledge layer (June 3 2026). 33 markdown skill files cloned from Claude-BugHunter (MIT licensed) at `skills/`. `skill_loader.py` injects 8K+ chars of curated patterns into every agent's LLM prompt at init time. **All 25 vuln agents have curated knowledge in their system prompts.**

The skills/ knowledge layer is **still active** in v2.0.0. When `VulnAgentProducer` instantiates a legacy agent, the agent's `__init__` runs `BaseAgent._resolve_skill_addendum()` which loads the matching skill and appends it to the system prompt. So the LLM still gets the 681-pattern knowledge base.

---

## 13. Glossary (all technical terms in one place)

**Agent** — a specialised piece of code hunting one type of vulnerability. 25 in v2.0.0.

**asyncio.gather** — the Python primitive for running multiple coroutines concurrently. Used by `engine/runner.py` to achieve true parallelism.

**Confidence** — a 5-level label on every Finding: Confirmed / High / Medium / Low / False-positive. Replaces the v1.x binary "validated/not".

**CVE / CVSS / CWE** — standard catalogue numbers. CVE = specific vulnerability (e.g. CVE-2024-1234). CVSS = severity score 0-10. CWE = type of weakness (e.g. CWE-89 = SQL Injection).

**Finding** — in v2.0.0, a logical vulnerability. Holds title, CWE, CVSS, severity, confidence, remediation. Has many Instances.

**FindingInstance** — a specific occurrence of a Finding on a specific URL. Many Instances can share one Finding.

**HTMX** — JavaScript-light library for swapping HTML fragments. The dashboard uses it for nearly all interactivity.

**Instructor** — the library wrapping Ollama's OpenAI-compatible API for structured Pydantic-validated output with retry-on-validation-error.

**Ollama** — local LLM runner. The project uses `qwen3:14b` by default and `deepseek-r1:14b` for reasoning-heavy agents.

**Producer** — anything that emits Findings. Vuln agents, importers (Nmap/Nuclei/Shodan), and crawlers (Playwright/PassiveRecon) all conform to one `FindingProducer` ABC.

**Pydantic** — type-safe data validation. Finding + FindingInstance use it.

**Redis** — in-memory pubsub + job queue backend. The dashboard's worker queue (RQ) and SSE channels both use Redis.

**RQ** — Redis Queue. Job queueing library.

**Scan Health pill** — the badge in the dashboard showing whether the scan ran healthily end-to-end.

**SSE** — Server-Sent Events. One-way push from server to browser. Used for live progress / findings / heartbeats / errors.

**structlog** — structured logging library. Three sinks configured: rich console, JSONL file, Redis pubsub.

**WeasyPrint** — pure-Python HTML→PDF renderer. v2.0.0 default. No browser dependency.

For a comprehensive 50+ term glossary aimed at non-technical readers, see `presentation/VulnHive_AI_Report_v2.pdf` §22.

---

## 14. For a new Claude session — how to pick up

If you are a new Claude Code session reading this file because the user just transferred laptops:

### Step 1: Read the canonical references in order
1. This file (`HANDOFF_v2.0.0.md`) — done if you're reading this
2. `CHANGELOG.md` — quick scan of what changed in v2.0.0
3. (Optional) `docs/superpowers/specs/2026-06-09-...-design.md` — the design rationale
4. (Optional) `docs/superpowers/plans/2026-06-09-...-uplift.md` — every task in detail
5. (Optional) `presentation/VulnHive_AI_Report_v2.pdf` — the 33-page user-facing explanation

### Step 2: Sanity-check the working tree
```bash
cd /Users/shyamk/Documents/pentest-agent
git branch                # should be 'main'
git tag -l 'v2.*'          # v2.0.0, v2.0.0-phase1-engine, v2.0.0-phase2-presentation
git log --oneline -5       # recent commits should match the 41-commit log in §4
./venv/bin/python --version   # should be Python 3.14.3
```

### Step 3: Run the test suite
```bash
./venv/bin/pytest tests/unit tests/integration tests/migration -q
# Expected: 68 passed
./venv/bin/ruff check .
# Expected: All checks passed!
```

If either fails, something has drifted since v2.0.0 was tagged. Check `git status` for accidentally modified files.

### Step 4: Confirm services
- Redis: `brew services list | grep redis`
- Ollama: `ollama list` (look for `qwen3:14b` and `deepseek-r1:14b`)
- DVWA: `docker ps | grep dvwa` (only if you plan to scan)

### Step 5: Ask the user what to work on next
Likely candidates from the roadmap (§10):
- VRT taxonomy column (~half day)
- 7-Question Triage Gate (~1 day)
- URL-shape prioritiser (~1 day)
- Anthropic key fix (5 min once they have a real key)
- Chat-with-findings reactivation (~half day)

### Step 6: Follow the same workflow
Use the superpowers skills for any non-trivial work:
1. `superpowers:brainstorming` to refine the idea into a design
2. `superpowers:writing-plans` to turn the design into a task plan
3. `superpowers:subagent-driven-development` to execute the plan

This workflow produced v2.0.0 cleanly across 41 commits with 68 passing tests; it should work for the next cycle too.

---

## 15. The user (for context)

- **Name**: Shyam Kakkad
- **GitHub**: 0xShyam-Sec
- **Email**: shyamk@locus.sh
- **Repo**: github.com/0xShyam-Sec/VulnHive-AI
- **Project intent**: Academic + portfolio project. Originally built March-June 2026. The user wants this to be the "best version" of the tool and uses subagent-driven execution for complex work.
- **Workflow preference**: Approves design sections one at a time during brainstorming; chooses subagent-driven execution; expects continuous execution without check-ins between tasks.

---

## 16. Final state checksum

If everything is in place, these commands should all succeed cleanly:

```bash
# 1. Working tree state
test -f HANDOFF_v2.0.0.md && echo "✓ handoff present"
test -f CHANGELOG.md && echo "✓ changelog present"
test -f docs/superpowers/specs/2026-06-09-engine-reliability-and-presentation-uplift-design.md && echo "✓ spec present"
test -f docs/superpowers/plans/2026-06-09-engine-reliability-and-presentation-uplift.md && echo "✓ plan present"
test -f presentation/VulnHive_AI_Report_v2.pdf && echo "✓ report PDF present"
test -d engine/producers && echo "✓ producers tree present"
test -f engine/runner.py && echo "✓ runner present"
test -f engine/confidence_labeler.py && echo "✓ confidence labeler present"
test -f dashboard/repository.py && echo "✓ repository present"
test -f dashboard/pdf.py && echo "✓ PDF module present"
test -f dashboard/migrations/runner.py && echo "✓ migration runner present"
test -f tests/conftest.py && echo "✓ conftest present"
test -f .github/workflows/test.yml && echo "✓ CI workflow present"

# 2. Git state
git rev-parse v2.0.0 > /dev/null 2>&1 && echo "✓ v2.0.0 tag present"
git log --oneline | grep -q "Merge v2.0.0" && echo "✓ merge commit present"

# 3. Python state
./venv/bin/python -c "
from engine.finding_model import Finding, FindingInstance, Confidence
from engine.producer import FindingProducer, ScanContext
from engine.runner import run_scan
from engine.modes import MODE_PRODUCERS
from engine.producers.registry import build_producers
from dashboard.repository import save_finding
from dashboard.pdf import render_pdf
assert 'nuclei' in MODE_PRODUCERS['multi-agent']
print('✓ all v2.0.0 modules importable; nuclei in multi-agent default')
"

# 4. Tests + lint
./venv/bin/pytest tests/unit tests/integration tests/migration -q | tail -1
./venv/bin/ruff check . | tail -1
```

All `✓` marks present + `68 passed` + `All checks passed!` = the v2.0.0 release is healthy and you're ready to start the next cycle.

---

*This handoff was generated by Claude Opus 4.7 (1M context) on 2026-06-11
after completing the v2.0.0 release. Hand it to your next session.*
