"""Async runner: gathers producers, merges their async streams,
dedupes through the repository layer, persists, broadcasts.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from engine.finding_model import Finding, FindingInstance
from engine.logging_setup import get_logger
from engine.producer import FindingProducer, ScanContext
from engine.safe_run import safe_produce

_log = get_logger()


async def _drain_into_queue(
    producer: FindingProducer,
    ctx: ScanContext,
    q: "asyncio.Queue[Optional[Finding]]",
) -> None:
    """Pull findings from one producer and push into the merge queue."""
    try:
        async for f in safe_produce(producer, ctx):
            await q.put(f)
    finally:
        await q.put(None)


async def run_scan(
    scan_id: int,
    target: str,
    producers: list[FindingProducer],
    db_path: Optional[Path] = None,
    auth_config: Optional[dict] = None,
    llm_backend: str = "ollama",
    redis_client=None,
    on_ctx=None,
) -> dict:
    """Run all producers concurrently; persist and broadcast as findings arrive."""
    ctx = ScanContext(
        scan_id=scan_id,
        target=target,
        db_path=db_path,
        auth_config=auth_config or {},
        llm_backend=llm_backend,
        redis_client=redis_client,
    )
    if on_ctx is not None:
        try:
            on_ctx(ctx)
        except Exception as e:
            _log.warning("on_ctx_callback_failed", scan_id=scan_id, error=str(e))
    q: asyncio.Queue[Optional[Finding]] = asyncio.Queue(maxsize=256)

    tasks = [
        asyncio.create_task(_drain_into_queue(p, ctx, q)) for p in producers
    ]
    hb_task = None
    if redis_client is not None:
        hb_task = asyncio.create_task(_emit_heartbeat(scan_id, redis_client))
    pending_producers = len(tasks)

    out_findings: list[Finding] = []

    while pending_producers > 0:
        item = await q.get()
        if item is None:
            pending_producers -= 1
            continue

        # Build a primary FindingInstance from the producer-attached payload.
        instance_payload = item.references_json.pop("_primary_instance", None)
        if instance_payload is None:
            source = (
                item.rule_id.split(":")[0] if ":" in item.rule_id else item.rule_id
            )
            instance = FindingInstance(
                finding_id=item.id,
                url=ctx.target,
                source_tool=source,
            )
        else:
            instance = FindingInstance(
                finding_id=item.id,
                **instance_payload,
            )

        # Confidence labeling (never drops; only relabels)
        try:
            from engine.confidence_labeler import label_confidence
            item = await label_confidence(item)
        except Exception as e:
            _log.warning("confidence_labeler_failed", scan_id=scan_id, error=str(e))

        if db_path is not None:
            try:
                from dashboard.repository import save_finding

                persisted = save_finding(db_path, item, instance)
            except Exception as e:
                _log.error("persist_failed", scan_id=scan_id, error=str(e))
                persisted = item
        else:
            persisted = item

        out_findings.append(persisted)

        if redis_client is not None:
            try:
                import json

                redis_client.publish(
                    f"scan:{scan_id}:findings",
                    json.dumps(persisted.model_dump(mode="json")),
                )
            except Exception as e:
                _log.warning(
                    "finding_broadcast_failed", scan_id=scan_id, error=str(e)
                )

    await asyncio.gather(*tasks, return_exceptions=True)

    if hb_task is not None:
        hb_task.cancel()
        try:
            await hb_task
        except (asyncio.CancelledError, Exception) as e:
            _log.debug("heartbeat_task_stopped", error=str(e))

    return {"findings": out_findings, "errors": list(ctx.errors)}


async def _emit_heartbeat(
    scan_id: int,
    redis_client,
    every: float = 5.0,
    total_ticks: int = None,
) -> None:
    """Publish a heartbeat event every `every` seconds while the scan runs.

    Pass total_ticks for testing (finite ticks). Pass None in production for an
    indefinite heartbeat that the caller cancels when the scan completes.
    """
    import json
    n = 0
    while True:
        try:
            redis_client.publish(
                f"scan:{scan_id}:heartbeat",
                json.dumps({"ts": str(asyncio.get_event_loop().time())}),
            )
        except Exception as e:
            _log.warning("heartbeat_publish_failed", scan_id=scan_id, error=str(e))
        n += 1
        if total_ticks is not None and n >= total_ticks:
            return
        await asyncio.sleep(every)


def attach_instance(
    finding: Finding,
    *,
    url: str,
    method: str = "GET",
    param_name: Optional[str] = None,
    payload: Optional[str] = None,
    evidence_raw: str = "",
    source_tool: str = "unknown",
    request: Optional[str] = None,
    response_excerpt: Optional[str] = None,
) -> Finding:
    """Helper for producers — attach an instance description before yield."""
    finding.references_json["_primary_instance"] = {
        "url": url,
        "method": method,
        "param_name": param_name,
        "payload": payload,
        "evidence_raw": evidence_raw,
        "request": request,
        "response_excerpt": response_excerpt,
        "source_tool": source_tool,
    }
    return finding
