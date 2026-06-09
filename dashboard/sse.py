"""
Server-Sent Events fan-out.

Pattern: a MessageAnnouncer with bounded per-listener queues. A slow client
that fills its queue is dropped — never blocks the producer. Multi-scan safe
via per-scan channels (separate listener lists per scan_id).

Producers (the RQ worker) push events to Redis pub/sub. The web process
subscribes to Redis and fans events out to all SSE listeners for that scan_id.
That way the worker runs in a separate process from the web server and events
still flow.
"""

import json
import queue
import threading
from typing import Optional, Dict, List

import redis as redis_client

# Event names used in SSE responses (event: <name>\ndata: ...\n\n)
EVENT_FINDING    = "finding"
EVENT_PROGRESS   = "agent_progress"
EVENT_HEARTBEAT  = "heartbeat"
EVENT_SCAN_ERROR = "scan_error"
EVENT_LOG        = "log"
EVENT_DONE       = "done"

# Map Redis channel suffix → SSE event name
SUFFIX_TO_EVENT = {
    "findings":  EVENT_FINDING,
    "progress":  EVENT_PROGRESS,
    "heartbeat": EVENT_HEARTBEAT,
    "logs":      EVENT_LOG,
    "errors":    EVENT_SCAN_ERROR,
    "done":      EVENT_DONE,
}


# ─── Per-process listener registry ───────────────────────────────────────

_listeners_lock = threading.Lock()
_listeners: Dict[int, List[queue.Queue]] = {}   # scan_id → [Queue, ...]


def _add_listener(scan_id: int) -> queue.Queue:
    q = queue.Queue(maxsize=200)
    with _listeners_lock:
        _listeners.setdefault(scan_id, []).append(q)
    return q


def _remove_listener(scan_id: int, q: queue.Queue):
    with _listeners_lock:
        if scan_id in _listeners and q in _listeners[scan_id]:
            _listeners[scan_id].remove(q)
            if not _listeners[scan_id]:
                del _listeners[scan_id]


def _broadcast_local(scan_id: int, message: str):
    """Push to all in-process SSE listeners for this scan."""
    with _listeners_lock:
        targets = list(_listeners.get(scan_id, []))
    for q in targets:
        try:
            q.put_nowait(message)
        except queue.Full:
            # Slow client — drop it. Garbage-collected on next listen().
            pass


# ─── SSE message formatting ─────────────────────────────────────────────

def format_sse(data: str, event: Optional[str] = None) -> str:
    """
    Format a single SSE message. `data` may contain newlines (handled per-line).
    """
    lines = data.split("\n")
    out = ""
    if event:
        out += f"event: {event}\n"
    for line in lines:
        out += f"data: {line}\n"
    out += "\n"
    return out


# ─── Redis pub/sub bridge (worker process ↔ web process) ────────────────

_REDIS = redis_client.Redis(decode_responses=True)
_CHANNEL_PREFIX = "vulnhive:scan:"
# Runner publishes directly to scan:{scan_id}:{suffix} — a different prefix
_DIRECT_PREFIX = "scan:"


def publish(scan_id: int, event: str, data: str):
    """
    Called by the RQ worker. Publishes to Redis; the web process
    subscribers receive it and fan it out to SSE listeners.
    """
    payload = json.dumps({"event": event, "data": data})
    _REDIS.publish(f"{_CHANNEL_PREFIX}{scan_id}", payload)


def _redis_subscriber():
    """
    Single background thread per web process that listens to ALL scan channels
    via pattern subscription and broadcasts locally.

    Two patterns are subscribed:
    * ``vulnhive:scan:*`` — wrapped JSON payload ``{"event": ..., "data": ...}``
      published by :func:`publish` (used by dashboard routes / legacy path).
    * ``scan:*`` — raw JSON payload published directly by the runner (findings,
      progress, heartbeat).  The SSE event name is derived from the channel
      suffix using :data:`SUFFIX_TO_EVENT`.
    """
    pubsub = _REDIS.pubsub()
    pubsub.psubscribe(f"{_CHANNEL_PREFIX}*", f"{_DIRECT_PREFIX}*")
    for msg in pubsub.listen():
        if msg.get("type") != "pmessage":
            continue
        try:
            channel = msg["channel"]
            if channel.startswith(_CHANNEL_PREFIX):
                # Legacy wrapped format: {"event": "...", "data": "..."}
                scan_id = int(channel[len(_CHANNEL_PREFIX):])
                payload = json.loads(msg["data"])
                sse_msg = format_sse(payload["data"], event=payload.get("event"))
            else:
                # Direct format: scan:{scan_id}:{suffix}  →  raw JSON data
                parts = channel.split(":")
                # channel is "scan:{scan_id}:{suffix}" → parts = ["scan", id, suffix]
                scan_id = int(parts[1])
                suffix = parts[2] if len(parts) > 2 else "message"
                event_name = SUFFIX_TO_EVENT.get(suffix, "message")
                sse_msg = format_sse(msg["data"], event=event_name)
            _broadcast_local(scan_id, sse_msg)
        except Exception as e:
            print(f"[SSE bridge] error processing message: {e}")


# Start the subscriber once at module import (web process).
_subscriber_thread: Optional[threading.Thread] = None


def start_bridge():
    """Idempotent — call at app startup."""
    global _subscriber_thread
    if _subscriber_thread is None or not _subscriber_thread.is_alive():
        _subscriber_thread = threading.Thread(
            target=_redis_subscriber, daemon=True, name="sse-redis-bridge"
        )
        _subscriber_thread.start()


# ─── Public API used by the SSE route ───────────────────────────────────

def subscribe(scan_id: int):
    """
    Generator-friendly. Yields SSE-formatted strings.
    The route wraps it in `stream_with_context`.
    """
    q = _add_listener(scan_id)
    try:
        # Initial comment to flush headers immediately
        yield ": connected\n\n"
        # Heartbeat every 15s so corp proxies don't kill the connection
        last_heartbeat = 0.0
        import time as _time
        while True:
            try:
                msg = q.get(timeout=15)
                if msg is None:    # sentinel for clean shutdown
                    break
                yield msg
            except queue.Empty:
                yield ": heartbeat\n\n"
                last_heartbeat = _time.time()
    finally:
        _remove_listener(scan_id, q)


# ─── Direct local push (used by routes that emit without going through Redis) ──

def announce(scan_id: int, event: str, data: str):
    """In-process broadcast — used by routes that don't go through a worker."""
    _broadcast_local(scan_id, format_sse(data, event=event))
