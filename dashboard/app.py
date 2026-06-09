"""
VulnHive AI — Flask web dashboard (v2).

Architecture:
- HTMX-driven server-rendered templates (NO SPA, NO JSON layer)
- RQ + Redis for background scan execution
- SSE for live progress/logs/findings updates
- SQLite for persistent scan + finding state
"""

import csv
import io
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime

import httpx
from flask import (
    Flask, render_template, request, jsonify, redirect,
    Response, stream_with_context, url_for, abort, send_file,
)
from rq import Queue
from redis import Redis

# Make project root importable
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from dashboard import db, sse, worker as worker_mod


# ─── App setup ───────────────────────────────────────────────────────────

app = Flask(
    __name__,
    template_folder=os.path.join(_HERE, "templates"),
    static_folder=os.path.join(_HERE, "static"),
)
app.config["SECRET_KEY"] = os.environ.get("VULNHIVE_SECRET", "dev-secret-change-me")
app.config["JSON_SORT_KEYS"] = False

_REDIS = Redis()
_QUEUE = Queue("vulnhive_scans", connection=_REDIS)

# Start the SSE Redis-pubsub bridge once on import
sse.start_bridge()


# ─── Helpers ─────────────────────────────────────────────────────────────

def _is_htmx() -> bool:
    return request.headers.get("HX-Request") == "true"


def _ollama_online() -> bool:
    try:
        return httpx.get("http://localhost:11434/api/tags", timeout=1.0).status_code == 200
    except Exception:
        return False


def _redis_online() -> bool:
    try:
        return _REDIS.ping()
    except Exception:
        return False


def _worker_count() -> int:
    try:
        from rq import Worker
        return len([w for w in Worker.all(connection=_REDIS) if "vulnhive_scans" in [q.name for q in w.queues]])
    except Exception:
        return 0


# ─── Top-level pages ─────────────────────────────────────────────────────

@app.route("/")
def index():
    scans = db.list_scans(limit=20)
    stats = db.get_stats()
    return render_template("index.html", scans=scans, stats=stats)


@app.route("/scans/new")
def scan_new_page():
    return render_template("scan_new.html")


@app.route("/scans/<int:scan_id>")
def scan_detail(scan_id):
    from pathlib import Path
    from engine.modes import MODE_PRODUCERS, build_producer_names
    from dashboard import repository, db as _db
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    findings = db.get_findings(scan_id)[:50]
    mode = (scan.get("mode") if isinstance(scan, dict) else getattr(scan, "mode", None)) or "multi-agent"
    if mode not in MODE_PRODUCERS:
        mode = "multi-agent"
    producer_names = build_producer_names(mode)
    errors = repository.list_scan_errors(Path(_db.DB_PATH), scan_id=scan_id)
    return render_template("scan_detail.html", scan=scan, findings=findings,
                           producer_names=producer_names, errors=errors)


def _render_findings_page(scan_id):
    from pathlib import Path
    from dashboard import repository, db as _db

    DEFAULT_SEV = ["critical", "high", "medium"]
    DEFAULT_CONF = ["confirmed", "high", "medium"]

    severities = request.args.getlist("severity") or DEFAULT_SEV
    confidences = request.args.getlist("confidence") or DEFAULT_CONF
    statuses = request.args.getlist("status") or ["active"]

    db_path = Path(_db.DB_PATH)
    visible = repository.list_findings_filtered(
        db_path,
        scan_id=scan_id,
        severities=severities,
        confidences=confidences,
        statuses=statuses,
    )

    # Count items hidden by current filters
    all_active = repository.list_findings_filtered(
        db_path,
        scan_id=scan_id,
        severities=None,
        confidences=None,
        statuses=None,
        include_false_p=True,
    )
    hidden_count = len(all_active) - len(visible)

    # Primary instance per finding (for the card preview)
    primaries = {}
    for f in visible:
        ins = repository.list_instances_for_finding(db_path, f.id)
        primaries[f.id] = ins[0].model_dump() if ins else {}

    scan = _db.get_scan(scan_id) if scan_id is not None else None
    return render_template(
        "findings.html",
        scan=scan,
        findings=visible,
        primaries=primaries,
        selected_severities=severities,
        selected_confidences=confidences,
        hidden_count=hidden_count,
    )


@app.route("/scans/<int:scan_id>/findings")
def scan_findings_page(scan_id):
    if not db.get_scan(scan_id):
        abort(404)
    return _render_findings_page(scan_id)


@app.route("/scans/<int:scan_id>/recon")
def scan_recon_page(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    recon = db.get_recon(scan_id)
    return render_template("recon.html", scan=scan, recon=recon)


@app.route("/health")
def health_page():
    return render_template("health.html", health=_health_check())


@app.route("/history")
def history_page():
    return render_template("history.html", scans=db.list_scans(limit=500))


# ─── HTMX partials (server-rendered fragments) ──────────────────────────

@app.route("/partials/scan_summary/<int:scan_id>")
def partial_scan_summary(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return ""
    return render_template("partials/scan_summary.html", scan=scan)


@app.route("/partials/recent_scans")
def partial_recent_scans():
    return render_template("partials/scan_table.html", scans=db.list_scans(limit=20))


@app.route("/partials/findings_list/<int:scan_id>")
def partial_findings_list(scan_id):
    findings = db.get_findings(
        scan_id,
        severity=request.args.get("severity"),
        status=request.args.get("status"),
        search=request.args.get("q"),
    )
    return render_template("partials/findings_list.html", findings=findings)


# ─── Actions ─────────────────────────────────────────────────────────────

@app.route("/scans/start", methods=["POST"])
def scan_start():
    """
    Triggered by HTMX form submit. Persists the scan, enqueues to RQ,
    returns HX-Redirect to the detail page (server-driven navigation).
    """
    f = request.form
    target = (f.get("target") or "").strip()
    if not target:
        return _form_error("Target URL required")
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    config = {
        "auth_type": f.get("auth_type", "none"),
        "login_url": f.get("login_url", ""),
        "username": f.get("username", ""),
        "password": f.get("password", ""),
        "bearer_token": f.get("bearer_token", ""),
        "api_key_name": f.get("api_key_name", ""),
        "api_key_value": f.get("api_key_value", ""),
        "api_key_loc": f.get("api_key_loc", "header"),
        "cookies": f.get("cookies", ""),
        "llm_backend": f.get("llm", "ollama"),
        "mode": f.get("mode", "multi-agent"),
        "depth": f.get("depth", "standard"),
        "scan_type": f.get("scan_type", "full"),
        "nmap": f.get("nmap", "default"),
        "nuclei": f.get("nuclei", "default"),
        "rate_limit": float(f.get("rate_limit", 0) or 0),
        "max_pages": int(f.get("max_pages", 100) or 100),
        "exploit_chains": bool(f.get("exploit_chains")),
        "adaptive": bool(f.get("adaptive")),
        "scan_all": bool(f.get("scan_all")),
    }

    scan_id = db.create_scan(
        target=target,
        scan_name=f.get("scan_name"),
        mode=config["mode"],
        llm_backend=config["llm_backend"],
        config=config,
    )

    job = _QUEUE.enqueue(
        "dashboard.worker.run_scan", scan_id,
        job_id=f"scan-{scan_id}",
        job_timeout=3600,
        result_ttl=86400,
    )
    db.set_rq_job_id(scan_id, job.id)

    # HTMX-friendly redirect
    if _is_htmx():
        return ("", 200, {"HX-Redirect": url_for("scan_detail", scan_id=scan_id)})
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/scans/<int:scan_id>/stop", methods=["POST"])
def scan_stop(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    if scan["status"] in ("running", "queued"):
        worker_mod.request_stop(scan_id)
    if _is_htmx():
        # Re-render the summary fragment showing 'stopping' state
        return partial_scan_summary(scan_id)
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/findings/<int:finding_id>/status", methods=["POST"])
def finding_set_status(finding_id):
    new_status = request.form.get("status", "open")
    db.update_finding_status(finding_id, new_status)
    if _is_htmx():
        f = db.get_finding(finding_id)
        return render_template("partials/finding_status.html", finding=f)
    return ("", 204)


@app.route("/findings/<string:finding_id>/modal")
def finding_modal(finding_id):
    """Render the finding detail modal body. HTMX target."""
    from pathlib import Path
    from dashboard import repository, db as _db

    db_path = Path(_db.DB_PATH)
    # Use the repository's internal helpers to fetch a single finding by UUID id.
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return "<div class='text-danger'>Finding not found.</div>", 404

    finding = repository._row_to_finding(row)
    instances = repository.list_instances_for_finding(db_path, finding_id)
    return render_template("partials/finding_detail_modal.html",
                           f=finding, instances=instances)


# ─── Live SSE stream ─────────────────────────────────────────────────────

@app.route("/scans/<int:scan_id>/stream")
def scan_stream(scan_id):
    @stream_with_context
    def gen():
        for msg in sse.subscribe(scan_id):
            yield msg
    return Response(
        gen(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ─── Export endpoints ────────────────────────────────────────────────────

@app.route("/scans/<int:scan_id>/export/json")
def export_json(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    payload = {
        "scan": scan,
        "findings": db.get_findings(scan_id),
        "recon": db.get_recon(scan_id),
        "logs": db.get_logs(scan_id),
    }
    return Response(
        json.dumps(payload, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.json"'},
    )


@app.route("/scans/<int:scan_id>/export/csv")
def export_csv(scan_id):
    findings = db.get_findings(scan_id)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "severity", "vuln_type", "url", "method", "param", "payload",
                "evidence", "source", "status", "cvss", "cwe"])
    for f in findings:
        w.writerow([f.get("id"), f.get("severity"), f.get("vuln_type"), f.get("url"),
                    f.get("method"), f.get("param_name"), f.get("payload"),
                    (f.get("evidence") or "")[:1000], f.get("source"),
                    f.get("status"), f.get("cvss"), f.get("cwe")])
    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.csv"'},
    )


@app.route("/scans/<int:scan_id>/export/pdf")
def export_pdf(scan_id):
    """Generate a printable HTML, render to PDF with headless Chrome."""
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)
    findings = db.get_findings(scan_id)
    html = render_template("report_pdf.html", scan=scan, findings=findings,
                            recon=db.get_recon(scan_id),
                            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    out_dir = os.path.join(_ROOT, "reports", "pdf")
    os.makedirs(out_dir, exist_ok=True)
    html_path = os.path.join(out_dir, f"scan_{scan_id}.html")
    pdf_path = os.path.join(out_dir, f"scan_{scan_id}.pdf")
    with open(html_path, "w") as fp:
        fp.write(html)

    chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if not os.path.exists(chrome):
        return jsonify({"error": "Chrome required for PDF generation"}), 500
    subprocess.run(
        [chrome, "--headless", "--disable-gpu", "--no-pdf-header-footer",
         f"--print-to-pdf={pdf_path}", f"file://{html_path}"],
        capture_output=True, timeout=60,
    )
    if not os.path.exists(pdf_path):
        return jsonify({"error": "PDF generation failed"}), 500
    return send_file(pdf_path, as_attachment=True,
                     download_name=f"vulnhive_scan_{scan_id}.pdf",
                     mimetype="application/pdf")


# ─── Health check ────────────────────────────────────────────────────────

def _health_check():
    return {
        "redis": _redis_online(),
        "rq_worker_count": _worker_count(),
        "queued_jobs": len(_QUEUE),
        "ollama": _ollama_online(),
        "nmap": bool(shutil.which("nmap")),
        "nuclei": bool(shutil.which("nuclei")),
        "groq_key": bool(os.environ.get("GROQ_API_KEY")),
        "gemini_key": bool(os.environ.get("GEMINI_API_KEY")),
        "anthropic_key": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "scans_total": db.get_stats()["total_scans"],
        "scans_running": db.get_stats()["running"],
    }


@app.route("/api/health")
def api_health():
    return jsonify(_health_check())


# ─── Helpers ─────────────────────────────────────────────────────────────

def _form_error(msg: str):
    if _is_htmx():
        return f'<div class="alert alert-danger" role="alert">{msg}</div>', 400
    return msg, 400


# ─── Entry point ─────────────────────────────────────────────────────────

def start_dashboard(host="0.0.0.0", port=5001, debug=False):
    db.init_db()
    db.recover_stale_running_scans()
    print(f"\n  ┌─ VulnHive AI Dashboard v2 ──────────────────────────────")
    print(f"  │  URL:    http://localhost:{port}")
    print(f"  │  Redis:  {'connected' if _redis_online() else 'OFFLINE — start with `brew services start redis`'}")
    print(f"  │  Worker: {_worker_count()} running")
    if _worker_count() == 0:
        print(f"  │  ⚠ NO worker running. Start one with:")
        print(f"  │     python -m dashboard.worker")
    print(f"  └─────────────────────────────────────────────────────────\n")
    app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)


if __name__ == "__main__":
    start_dashboard(debug=False)
