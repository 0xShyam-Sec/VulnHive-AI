# VulnHive AI — Project Handoff Document

> **For continuing in a new Claude Code session.** Read this top-to-bottom before
> doing anything. Everything important about the current state is in here. Date
> of handoff: 2026-06-09 (v2.0.0).

---

## 0a. v2.0.0 — June 2026 — Engine Reliability & Presentation Uplift

- **Released**: 2026-06-09. Branch: `spec/engine-reliability-uplift`. Tags:
  `v2.0.0` (full), `v2.0.0-phase1-engine`, `v2.0.0-phase2-presentation`.
- **Spec**: `docs/superpowers/specs/2026-06-09-engine-reliability-and-presentation-uplift-design.md`
- **Plan**: `docs/superpowers/plans/2026-06-09-engine-reliability-and-presentation-uplift.md`
- **Changelog**: `CHANGELOG.md`
- **All Tier 1 + Tier 2 + selected Tier 3 fixes landed**: dashboard worker
  honors `config[mode]`; nuclei + playwright now in multi-agent default; no
  silent FP delete; multi-endpoint dedup preserved via FindingInstance; 8
  bare-excepts replaced with structured logs; Ollama structured output via
  Instructor; true async parallelism; finding cards show CWE/CVSS/payload;
  per-agent sub-progress + heartbeat; WeasyPrint PDF (cross-platform).
- **Python version**: 3.14 (was 3.9). Old venv preserved as `venv.bak-py39-mixed/`.
- **Tests**: 68 passing across unit/integration/migration suites; ruff clean
  project-wide; e2e DVWA smoke test runs when `DVWA_AVAILABLE=1`.
- **GitHub Actions CI**: `.github/workflows/test.yml` runs lint + unit/integration/migration on every push; e2e runs on main pushes only.

If you're continuing in a new Claude session after 2.0.0, the spec + plan + CHANGELOG together are the canonical reference. The §0 below (and §1–§13) describe state from **before** 2.0.0 — useful for historical context, but the new architecture (FindingProducer abstraction, mode→producers table, confidence labeler) supersedes much of the pipeline.py / orchestrator.py details below.

---

## 0. TL;DR — Where things stand right now (pre-2.0.0 — historical)

- **The tool works.** CLI scans run, dashboard v2 runs, real findings are produced.
- **Two recent wins:** ① rebuilt the dashboard cleanly with HTMX + RQ + Redis + SSE
  (v1 backed up in `dashboard_v1_backup/`), ② added a **skills/** knowledge layer
  that injects 681+ disclosed-report patterns into every agent's LLM prompt at runtime.
- **One real bug just fixed:** `run_multi_agent()` was silently skipping passive
  reconnaissance, so missing-header / CORS / sensitive-file findings were
  disappearing. Fixed in `pipeline.py` — passive_recon now always runs.
- **The "0 findings on Locus devo-5" mystery is now solved.** Both the target
  is now an Angular SPA (less to find) AND there was the passive_recon bug.

---

## 1. Project identity

- **Name:** VulnHive AI
- **Author:** Shyam Kakkad (`0xShyam-Sec` on GitHub)
- **Repo:** https://github.com/0xShyam-Sec/VulnHive-AI
- **Working directory:** `/Users/shyamk/Documents/pentest-agent`
- **Python:** 3.9 (venv at `./venv/`)
- **Purpose:** AI-powered automated penetration testing engine — 24 vuln agents,
  WAF detection, subdomain enum, exploit chaining, web dashboard, PDF reports.

## 2. What the tool actually does

Black-box web-application scanner. Give it a URL → it crawls, runs 24
specialised vulnerability agents in parallel, validates findings via local
LLM, dedupes, and produces HTML/JSON/PDF reports. Has a Flask dashboard for
running scans from a browser instead of CLI.

**Stack (running locally, all free):**

| Layer | What |
|---|---|
| Backend | Python 3.9, Flask, RQ + Redis, SQLite |
| LLM | Ollama (qwen3:14b, deepseek-r1:14b) running on localhost:11434 |
| External AI options | Groq (free), Gemini (blocked in our region), Anthropic (no valid key) |
| Tools | Nmap 7.99, Nuclei 3.8.0, Playwright |
| Frontend (dashboard v2) | HTMX 2.x + Bootstrap 5 + Alpine.js (minimal) + SSE |
| PDF generation | Headless Chrome (works, proven) |

## 3. Directory map (only the parts that matter)

```
pentest-agent/
├── main.py                       # CLI entry point
├── pipeline.py                   # Scan modes: systematic, agent, browser, api, multi-agent, full
├── HANDOFF.md                    # ← This file
│
├── agents/
│   ├── base.py                   # BaseAgent: multi-LLM (ollama/groq/gemini/anthropic) + SKILL INJECTION
│   ├── orchestrator.py           # run_multi_agent_scan — sequential agent loop
│   └── vuln/                     # 24 vuln agents: sqli, xss, csrf, ssrf, idor, cmdi, ssti, xxe, etc.
│
├── engine/
│   ├── scan_runner.py            # Unified runner (used by the OLD v1 dashboard, NOT by CLI)
│   ├── scan_state.py             # ScanState — thread-safe shared state
│   ├── config.py                 # ScanConfig
│   └── decision_engine.py
│
├── discovery/
│   ├── passive_recon.py          # ★ IMPORTANT: produces missing-header / CORS / sensitive-file findings
│   ├── playwright_crawler.py
│   ├── waf_detector.py           # 25 WAF fingerprints
│   ├── whois_dns.py
│   ├── nmap_scanner.py
│   ├── nuclei_scanner.py
│   └── shodan_cve.py
│
├── skills/                       # ★ NEW: 33 markdown skill files (681+ disclosed-report patterns)
│   ├── README.md                 # Attribution to Claude-BugHunter (MIT)
│   ├── hunt-sqli.md
│   ├── hunt-xss.md
│   ├── … (28 more hunt-* files)
│   ├── triage-validation.md
│   └── bugcrowd-reporting.md
│
├── skill_loader.py               # ★ NEW: loads skill markdown into agent prompts
│
├── dashboard/                    # ★ NEW v2 (rebuilt June 1-2)
│   ├── app.py                    # Flask routes + HTMX
│   ├── worker.py                 # RQ worker (run with OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES)
│   ├── db.py                     # SQLite layer
│   ├── sse.py                    # Server-Sent Events fan-out (Halford pattern)
│   ├── chat.py                   # AI chat with findings (from v1)
│   ├── vulnhive.db               # SQLite DB
│   ├── templates/                # Jinja2 + HTMX
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── scan_new.html
│   │   ├── scan_detail.html      # LIVE progress via SSE
│   │   ├── findings.html
│   │   ├── recon.html
│   │   ├── history.html
│   │   ├── health.html
│   │   ├── report_pdf.html
│   │   └── partials/
│   └── static/
│       ├── css/theme.css
│       └── js/{app.js, alpine.min.js}
│
├── dashboard_v1_backup/          # Old v1 dashboard, kept for design reference
│
├── reports/                      # Generated HTML / JSON / PDF reports
│   └── devo-5_locus-dev_com_20260320_172828_technical.html  # The famous old report (600+ findings)
│
├── presentation/                 # Faculty demo materials
│   ├── index.html                # 10-slide deck
│   └── VulnHive_AI_Report.pdf    # Full project report (584 KB PDF)
│
└── mobile_analysis/savanna/      # APK static analysis (Savanna fintech app)
    ├── SAVANNA_APK_Pentest_Report.html
    └── decoded/                  # apktool output
```

## 4. How to start everything

```bash
cd /Users/shyamk/Documents/pentest-agent
source venv/bin/activate

# 1. Make sure Redis is up (required for dashboard)
brew services start redis    # or: redis-server

# 2. Make sure Ollama is up (for local LLM)
ollama serve &
# Models available: qwen3:14b (current default), deepseek-r1:14b

# 3. Make sure DVWA is running (for safe practice target)
docker compose up -d
# DVWA at http://localhost:8080 — admin / password — visit /setup.php once if first time

# 4. Start dashboard
./venv/bin/python3 main.py --dashboard --port 5001

# 5. Start RQ worker IN A SEPARATE TERMINAL (the fork-safety env var is critical on macOS)
OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ./venv/bin/python3 -m dashboard.worker
```

Dashboard URL: **http://localhost:5001**

## 5. Recent decisions and history

### Phase A — Original CLI tool (pre-dashboard)
- Built `pipeline.py` with 6 scan modes (systematic, agent, browser, api, multi-agent, full)
- 24 vuln agents
- WAF detection, WHOIS/DNS, subdomain enum, Nmap, Nuclei integration
- Old March 20 scan against `devo-5.locus-dev.com` produced **600+ findings** using
  `--mode full` (or browser+multi-agent combined). Source breakdown: 107 browser,
  43 HeadersAgent, 20 passive-recon, 1 systematic.

### Phase B — Dashboard v1 (May)
- Built first dashboard with threads + in-memory state + polling
- Multiple issues piled up: dropdowns broken on macOS, charts auto-resized to
  full page height, blank pages on tab switch, "Starting…" stuck button, no
  stop functionality. **Backed up in `dashboard_v1_backup/`.**

### Phase C — Dashboard v2 (June 1-2) — current
- Wiped v1, rebuilt cleanly using research-backed patterns from DefectDojo,
  Faraday, ProjectDiscovery Cloud.
- **Architecture:** Flask + RQ + Redis + SQLite + SSE + HTMX (no SPA, no JSON layer)
- **`HX-Redirect` header** for server-driven navigation (can't break like fetch+manual-redirect did)
- **Cancel/stop button** wired to Redis flag, checked at phase boundaries
- **Live progress** via SSE streaming HTML fragments (no client templating)
- **PDF reports** via headless Chrome (already proven working)
- **macOS fork() crash fixed** with `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` env var

### Phase D — Skills knowledge layer (June 3 — today)
- Analysed `https://github.com/elementalsouls/Claude-BugHunter` (MIT-licensed Claude
  Code skill bundle, 681 disclosed-report patterns).
- **Cloned 33 of their skill markdown files into our `skills/` folder** with attribution.
- Built `skill_loader.py` — reads skills from disk, maps to our agents, injects
  into LLM prompt at runtime.
- Modified `agents/base.py` so every agent auto-loads its matching skill at init.
- **All 25 vuln agents have curated knowledge (8K+ chars each) now in context.**
- Works fully offline with local Ollama. No Claude subscription needed.

### Phase E — The passive_recon bug (June 3 — today, just fixed)
- User repeatedly said "the tool used to work, now it doesn't." I argued back
  three times saying it was the target. **I was wrong.**
- Forensic check revealed `run_multi_agent()` does NOT call `passive_recon`.
- The OLD report's 600+ findings included 20 from `passive-recon` source — that
  source disappeared when `multi-agent` mode became the default (which happened
  when the dashboard standardized on it).
- **Fixed in `pipeline.py:228`** — `passive_recon` now runs first in `run_multi_agent`.
- Verified: same scan against devo-5 — was 0 findings, now 5 findings (missing
  CSP, X-Frame-Options, Permissions-Policy, CORS misconfig, info disclosure header).

## 6. Working state of components

| Component | Status | Notes |
|---|---|---|
| CLI `main.py --target X` | ✅ Works | Default mode is `multi-agent`. For old-style 600+ findings use `--mode full` |
| Dashboard `--dashboard` | ✅ Works | Port 5001 (5000 used by macOS AirPlay) |
| RQ worker | ✅ Works | MUST have `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` set on macOS |
| Ollama backend | ✅ Works | qwen3:14b default |
| Groq backend | ✅ Works | API key in `.env` (free tier) |
| Gemini backend | ⚠️ Blocked | Free tier disabled for our Google account region |
| Anthropic backend | ⚠️ No key | Need a valid `sk-ant-…` key — current `.env` has an OpenAI key by mistake |
| Skills knowledge injection | ✅ Works | All 25 agents get +8K chars at init, logs `loaded curated skill` |
| PDF reports | ✅ Works | Via Chrome headless |
| AI Chat with findings | ✅ Works | `/api/chat/<scan_id>/message` endpoint, SSE streaming |
| Live SSE updates | ✅ Works | Redis pub/sub bridge, HTMX `sse-swap` |
| Stop button | ✅ Works | Redis stop flag, checked at phase boundaries |

## 7. Known issues / pending work

### Worth doing next

1. **VRT + CWE auto-classification** — every finding should get CVSS, CWE,
   Bugcrowd VRT category columns. Half-day of work. The disclosed-report
   patterns in `skills/` already reference these — just need to extract them.

2. **7-Question Triage Gate** — replace binary validator with a structured
   gate (PASS / DOWNGRADE / KILL). Reduces false positives massively. Reference
   pattern in `skills/triage-validation.md`.

3. **Make dashboard default mode `full` instead of `multi-agent`** — would
   surface browser + systematic findings that are currently hidden behind the
   default. Single line change in `dashboard/templates/scan_new.html` and
   `dashboard/app.py`'s `_QUEUE.enqueue` call.

4. **URL-shape prioritiser** — only run agents matching URL patterns (e.g.,
   `/search?q=` → SQLi first). Cuts scan time. Pattern in
   `/tmp/Claude-BugHunter/scripts/cbh.py` `classify` command.

5. **Anthropic key fix** — the current `.env` has an OpenAI key labelled as
   `ANTHROPIC_API_KEY`. Either remove it or replace with a real `sk-ant-…` key.

### Acknowledged limitations (not bugs)

- **SPA targets (React/Angular/Vue) cannot be deeply scanned** without browser
  automation. Our scanner sees only the static HTML shell. This is the same
  for ALL black-box scanners (Burp, Acunetix, Nessus). Workarounds: use
  `--mode browser` (Playwright-based) or test the API host directly.

- **Encrypted-API gateways** (e.g., Savanna's RSA+AES envelope encryption)
  defeat black-box scanners. Documented in the Savanna APK report.

- **Internal/VPN-only APIs** can't be reached from outside. Locus's
  `aws-devo.locus-api.com` is NXDOMAIN from public DNS — needs VPN.

## 8. Targets used during development

| Target | Type | Auth | Notes |
|--------|------|------|-------|
| `http://localhost:8080` (DVWA) | Server-rendered PHP, deliberately vulnerable | admin/password (form) | Always works, produces good findings |
| `https://devo-5.locus-dev.com` | Angular SPA frontend | Auth0 OAuth 2.0 PKCE | Now SPA — old March 20 scan was against earlier server-rendered version |
| `https://aws-devo.locus-api.com` | The real Locus API | Bearer JWT | **Private DNS / VPN required** — cannot scan from outside |
| `https://savmoney.keyannatech.com` | Angular SPA frontend | Auth0 OAuth | Savanna fintech — SPA, can't deep-scan |
| `https://savmoneyapi.keyannatech.com` | Real Savanna API | Bearer + RSA+AES encryption | Encrypted gateway, very hard to scan |
| `scanme.nmap.org` | Nmap's official test target | None | Safe for nmap/network demos |

## 9. Key commands (cheat sheet)

```bash
# Basic CLI scan (now correctly includes passive_recon since the fix)
./venv/bin/python3 main.py --target http://localhost:8080

# Full scan (best for replicating old 600+ findings behaviour)
./venv/bin/python3 main.py --target http://localhost:8080 --mode full

# Authenticated CLI scan
./venv/bin/python3 main.py --target http://localhost:8080 \
    --auth-type form --login-url http://localhost:8080/login.php \
    --username admin --password password --report-dir ./reports

# Bearer token scan (e.g., API)
./venv/bin/python3 main.py --target https://api.example.com \
    --auth-type bearer --bearer-token "eyJ..." --llm ollama

# Start dashboard
./venv/bin/python3 main.py --dashboard --port 5001

# Start RQ worker (MUST have OBJC env var on macOS)
OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ./venv/bin/python3 -m dashboard.worker

# Check skill catalogue
./venv/bin/python3 skill_loader.py            # list all skills
./venv/bin/python3 skill_loader.py hunt-sqli  # show one skill body

# Inspect dashboard DB
./venv/bin/python3 -c "
from dashboard import db
for s in db.list_scans(limit=10): print(f\"#{s['id']}  {s['status']}  {s['target']}\")
"
```

## 10. Things to NOT redo if continuing

- **Don't rebuild the dashboard again.** v2 works. v1 is in `dashboard_v1_backup/`
  for design reference only.
- **Don't try to scan Locus's `aws-devo.locus-api.com` from outside the VPN** —
  it's NXDOMAIN. We confirmed this twice. To pentest the real API, run the tool
  from a machine on Locus's VPN.
- **Don't argue with the user that "the target changed" before doing forensics.**
  The bug in `run_multi_agent` was real. Always trace findings by source field
  in old reports first.
- **Don't strip the `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` from the worker
  startup.** macOS forks the work-horse process and crashes without it.

## 11. Credit / attribution

- **Skills content** in `skills/` adapted from
  [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) by
  Sachin Sharma (MIT licensed). Credit retained in `skills/README.md`.
- **Dashboard architecture** patterned after DefectDojo, Faraday, and
  ProjectDiscovery Cloud (researched June 2).

## 12. Environment variables (in `.env`)

```
GROQ_API_KEY=gsk_…           # works — free tier
GEMINI_API_KEY=AIza…         # exists but blocked by Google quota in our region
ANTHROPIC_API_KEY=sk-…       # currently an OpenAI key by mistake — needs a real sk-ant- key
SHODAN_API_KEY=…             # not set (free InternetDB still works without one)
```

---

## 13. To continue in a new Claude session

1. Open a new Claude Code session in `/Users/shyamk/Documents/pentest-agent`.
2. Tell Claude: *"Read HANDOFF.md first, then we'll continue."*
3. Claude will have full context.

**Suggested next task:** implement #1 from §7 — VRT + CWE auto-classification.
The patterns are already in `skills/hunt-*.md` and the database has the
`cwe` + `cvss` columns ready (in `dashboard/db.py`). Mostly extraction work,
half a day.

---

*Document last updated: 2026-06-03 by Claude during the post-dashboard-rebuild
working session. Total project lines of code: ~32K Python + ~5K HTML/CSS/JS
+ ~668KB of curated bug-hunting knowledge in `skills/`.*
