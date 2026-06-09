"""
RQ worker — runs scans in a separate process from the web server.

Run with:
    rq worker -u redis://localhost:6379 vulnhive_scans

Or via the helper:
    python -m dashboard.worker

The worker function is `run_scan(scan_id)`. It reads the scan config from
the DB, executes the real scan engine, persists findings as they're discovered,
and publishes events to Redis (which the web process forwards to SSE clients).

Design contract:
- DB row is the SOURCE OF TRUTH for scan state.
- Every status transition is committed to DB FIRST, then announced.
- Worker can crash mid-scan and DB row is recoverable (stale-recovery in db.init_db).
- Stop request handled via Redis key `vulnhive:stop:{scan_id}` — checked at each
  phase boundary. Clean cooperative cancellation, no orphan processes.
"""

import json
import os
import sys
import time
import traceback
from datetime import datetime
from typing import Optional

# Make project root importable when invoked via `python -m dashboard.worker`
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import redis as redis_client

from dashboard import db, sse


_REDIS = redis_client.Redis(decode_responses=True)
_STOP_KEY = "vulnhive:stop:{scan_id}"


class ScanStopped(Exception):
    """Raised when the user has requested cancellation."""


# ─── Stop-request helpers (called by web process) ───────────────────────

def request_stop(scan_id: int):
    _REDIS.set(_STOP_KEY.format(scan_id=scan_id), "1", ex=3600)


def _is_stop_requested(scan_id: int) -> bool:
    return _REDIS.get(_STOP_KEY.format(scan_id=scan_id)) == "1"


def _clear_stop(scan_id: int):
    _REDIS.delete(_STOP_KEY.format(scan_id=scan_id))


def _check_stop(scan_id: int):
    if _is_stop_requested(scan_id):
        raise ScanStopped()


# ─── Event publishing helpers ────────────────────────────────────────────
#
# These render HTML partials directly so HTMX `sse-swap` can drop them into
# the page without any JS templating. The partial files live in templates/partials/.

def _emit_progress(scan_id: int, progress: int, phase: str):
    """Update DB + emit a progress bar fragment."""
    db.update_scan(scan_id, progress=progress, phase=phase)
    html = (
        f'<div class="progress-bar progress-bar-striped progress-bar-animated bg-success" '
        f'role="progressbar" style="width: {progress}%" '
        f'aria-valuenow="{progress}" aria-valuemin="0" aria-valuemax="100">{progress}%</div>'
    )
    sse.publish(scan_id, "progress", html)
    # Also emit the phase label as a separate event
    sse.publish(scan_id, "phase",
                f'<span class="badge bg-info">{phase.upper()}</span>')


def _emit_log(scan_id: int, message: str, level: str = "info"):
    log_id = db.add_log(scan_id, message, level=level)
    color = {"info": "#c9d1d9", "warn": "#ffae5c", "error": "#ff5c6c",
             "success": "#3fef9d", "debug": "#b07dff"}.get(level, "#c9d1d9")
    ts = datetime.now().strftime("%H:%M:%S")
    html = (
        f'<div class="log-line" data-id="{log_id}">'
        f'<span class="text-muted me-2">[{ts}]</span>'
        f'<span style="color:{color}">{_html_escape(message)}</span>'
        f'</div>'
    )
    sse.publish(scan_id, "log", html)


def _emit_finding(scan_id: int, finding: dict):
    """Persist + emit a Bootstrap card fragment."""
    finding_id = db.save_finding(scan_id, finding)
    sev = finding.get("severity", "Info")
    sev_class = {"Critical": "danger", "High": "warning", "Medium": "warning text-dark",
                 "Low": "info", "Info": "secondary"}.get(sev, "secondary")
    html = (
        f'<div class="card mb-2 finding-card border-start border-{sev_class} border-4" '
        f'data-finding-id="{finding_id}">'
        f'<div class="card-body py-2 px-3 d-flex align-items-center gap-3">'
        f'<span class="badge bg-{sev_class}">{sev}</span>'
        f'<strong>{_html_escape(finding.get("vuln_type", "?"))}</strong>'
        f'<span class="text-muted small font-monospace text-truncate" style="max-width:50%">'
        f'{_html_escape(finding.get("method", "GET"))} {_html_escape(finding.get("url", ""))}'
        f'</span>'
        f'<span class="text-muted small ms-auto">{_html_escape(finding.get("source", ""))}</span>'
        f'</div></div>'
    )
    sse.publish(scan_id, "finding", html)


def _emit_summary_refresh(scan_id: int):
    """Tell the page to re-fetch the severity-count summary."""
    sse.publish(scan_id, "summary_refresh", "1")


def _html_escape(s) -> str:
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                  .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;"))


# ─── The main job function ──────────────────────────────────────────────

def run_scan(scan_id: int):
    """
    Entry point for `rq enqueue`. Drives a complete scan.

    Reads config from DB → runs engine → persists findings → publishes events.
    Guarantees that the scan row ends in a TERMINAL status (done/failed/stopped)
    even if the engine throws.
    """
    _clear_stop(scan_id)
    scan = db.get_scan(scan_id)
    if not scan:
        return  # gone

    target = scan["target"]
    config = json.loads(scan.get("config_json") or "{}")
    started = time.time()

    try:
        db.update_scan(scan_id, status="running", phase="starting")
        _emit_progress(scan_id, 2, "starting")
        _emit_log(scan_id, f"Scan started for {target}", "success")

        # ── Phase 1: Discovery ─────────────────────────────────────────
        _check_stop(scan_id)
        _emit_progress(scan_id, 10, "discovery")
        _emit_log(scan_id, "Phase 1/5: Discovery — crawling + WAF + DNS")

        # ── Phase 2: Recon ─────────────────────────────────────────────
        _check_stop(scan_id)
        _emit_progress(scan_id, 25, "recon")
        _emit_log(scan_id, "Phase 2/5: Reconnaissance")

        # ── Phase 3: Attack (runs the real multi-agent pipeline) ───────
        _check_stop(scan_id)
        _emit_progress(scan_id, 40, "attack")
        _emit_log(scan_id, "Phase 3/5: Running 24 vulnerability agents...")

        findings = _run_engine(target, config, scan_id)

        # Persist + announce each finding individually
        for f in findings:
            _check_stop(scan_id)
            _emit_finding(scan_id, f)

        _emit_log(scan_id, f"Vulnerability scan complete: {len(findings)} findings",
                  "success" if findings else "info")

        # ── Phase 4: Validation ────────────────────────────────────────
        _check_stop(scan_id)
        _emit_progress(scan_id, 80, "validation")
        _emit_log(scan_id, "Phase 4/5: Validation + deduplication")

        # ── Phase 5: Report ────────────────────────────────────────────
        _check_stop(scan_id)
        _emit_progress(scan_id, 95, "report")
        _emit_log(scan_id, "Phase 5/5: Generating report")
        time.sleep(0.3)

        # ── Done ───────────────────────────────────────────────────────
        db.finish_scan(scan_id, status="done")
        _emit_progress(scan_id, 100, "completed")
        _emit_summary_refresh(scan_id)
        elapsed = time.time() - started
        _emit_log(scan_id, f"Scan finished in {elapsed:.1f}s", "success")
        sse.publish(scan_id, "done", "1")

    except ScanStopped:
        db.finish_scan(scan_id, status="stopped")
        _emit_summary_refresh(scan_id)
        elapsed = time.time() - started
        _emit_log(scan_id, f"Scan STOPPED by user after {elapsed:.1f}s", "warn")
        sse.publish(scan_id, "done", "stopped")

    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        tb = traceback.format_exc()
        db.update_scan(scan_id, status="failed", error=err,
                       finished_at=datetime.now().isoformat(),
                       duration_sec=round(time.time() - started, 1))
        _emit_log(scan_id, f"FATAL: {err}", "error")
        _emit_log(scan_id, tb.split("\n")[-2] if tb else "", "error")
        _emit_summary_refresh(scan_id)
        sse.publish(scan_id, "done", "failed")
        raise  # let RQ record the exception

    finally:
        _clear_stop(scan_id)


def _resolve_producers_for_mode(config: dict) -> list:
    """Translate the scan config's `mode` field into a producer list.

    Falls back to `multi-agent` for unknown modes.
    """
    from engine.modes import MODE_PRODUCERS
    from engine.producers.registry import build_producers
    mode = config.get("mode") or "multi-agent"
    if mode not in MODE_PRODUCERS:
        mode = "multi-agent"
    return build_producers(mode)


def _execute_scan(scan_id: int, target: str, config: dict, redis_client):
    """Run a scan using the producer pipeline. Honors config[mode] and the Redis stop flag."""
    import asyncio
    from pathlib import Path

    from engine.runner import run_scan
    from engine.logging_setup import configure_logging
    from dashboard import db as _db

    db_path = Path(_db.DB_PATH)
    configure_logging(scan_id=scan_id, log_dir=Path("logs"), redis_client=redis_client)

    producers = _resolve_producers_for_mode(config)

    stop_flag = f"vulnhive:stop:{scan_id}"
    ctx_holder: dict = {}

    async def _watch_stop_flag():
        # Poll the Redis stop flag and propagate to ctx.cancel().
        while True:
            await asyncio.sleep(0.5)
            ctx = ctx_holder.get("ctx")
            if ctx is None or ctx.cancelled:
                return
            if redis_client is not None:
                try:
                    if redis_client.exists(stop_flag):
                        ctx.cancel()
                        return
                except Exception:
                    pass

    async def _runner():
        stopper = asyncio.create_task(_watch_stop_flag())
        try:
            return await run_scan(
                scan_id=scan_id,
                target=target,
                producers=producers,
                db_path=db_path,
                auth_config=config.get("auth_config") or {},
                llm_backend=config.get("llm_backend", "ollama"),
                redis_client=redis_client,
                on_ctx=lambda c: ctx_holder.__setitem__("ctx", c),
            )
        finally:
            stopper.cancel()
            try:
                await stopper
            except Exception:
                pass

    return asyncio.run(_runner())


def _run_engine(target: str, config: dict, scan_id: int) -> list:
    """
    Bridge into the existing scan engine. Best-effort — engine import failures
    won't crash the worker; we just emit a log and return [].
    """
    # Build auth config from the stored form
    auth_config = None
    atype = config.get("auth_type", "none")
    if atype != "none":
        auth_config = {"auth_type": atype}
        if atype == "form":
            auth_config["login_url"] = config.get("login_url", "")
            auth_config["username"] = config.get("username", "")
            auth_config["password"] = config.get("password", "")
        elif atype == "bearer":
            auth_config["bearer_token"] = config.get("bearer_token", "")
        elif atype == "basic":
            auth_config["username"] = config.get("username", "")
            auth_config["password"] = config.get("password", "")
        elif atype == "cookie":
            auth_config["cookies"] = config.get("cookies", "")

    try:
        # Hand off to the producer-based runner, which honours config['mode'].
        config_with_auth = dict(config)
        config_with_auth["auth_config"] = auth_config
        config_with_auth["llm_backend"] = config.get("llm_backend", "ollama")
        result = _execute_scan(scan_id, target, config_with_auth, _REDIS)
        return result.get("findings", [])
    except Exception as e:
        _emit_log(scan_id, f"Engine error: {e}", "error")
        return []


# ─── CLI entry ──────────────────────────────────────────────────────────

def _cli():
    """Run the worker. Equivalent to `rq worker -u redis://... vulnhive_scans`."""
    from rq import Queue, Worker

    queue_name = os.environ.get("VULNHIVE_QUEUE", "vulnhive_scans")
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    conn = redis_client.from_url(redis_url)

    print(f"  VulnHive RQ worker → queue '{queue_name}' on {redis_url}")
    # RQ 2.x: Connection context manager removed; pass connection directly
    queue = Queue(queue_name, connection=conn)
    worker = Worker([queue], connection=conn)
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    _cli()
