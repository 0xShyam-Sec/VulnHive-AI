"""
Core ReAct agent loop — supports two LLM backends:

  1. Ollama (default) — free, local, no API key, uses qwen2.5:14b
  2. Anthropic API    — Claude Sonnet/Opus, native tool use (no text parsing)

Usage:
    run_agent(target, task)                          # Ollama (default)
    run_agent(target, task, llm_backend="anthropic") # Anthropic API
"""

import json
import os
import re
import httpx
from rich.console import Console
from rich.panel import Panel
from tools import TOOL_SCHEMAS, TOOL_DISPATCH, authenticate, get_session_cookies

console = Console()

# ── Ollama settings ───────────────────────────────────────────────────────
OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "qwen2.5:14b"

# ── Anthropic settings ────────────────────────────────────────────────────
ANTHROPIC_MODEL = "claude-sonnet-4-6"   # change to claude-opus-4-6 for best results
MAX_ITERATIONS = 25


# ── System prompts ────────────────────────────────────────────────────────

SYSTEM_PROMPT_OLLAMA = """\
You are an expert penetration tester AI agent. You test web applications \
in a LOCAL LAB ENVIRONMENT with explicit authorization. Educational purposes only.

## How to use tools
Respond with EXACTLY ONE tool call in this format — nothing else after it:
```tool
{"tool": "tool_name", "args": {"param1": "value1"}}
```
STOP after the ``` closing. Do NOT guess or imagine the result. \
The system will execute the tool and give you the real result.

## Available Tools

### authenticate
Login to the target. Supports: form login (auto-detects CSRF tokens), cookie, basic auth, bearer token. \
Args: auth_type (required: "form"/"cookie"/"basic"/"bearer"), login_url, username, password, \
username_field, password_field, cookies, bearer_token, success_indicator. \
Session cookies are auto-stored for all subsequent requests.

### send_http_request
Send HTTP request. Args: url (required), method (GET/POST), headers, body, cookies. \
Session cookies and auth headers are auto-attached.

### extract_forms
Extract HTML forms from a page. Args: url (required)

### check_response_contains
Check if response has a string. Args: url (required), search_string (required), method, body

### crawl_links
Get all links from a single page. Args: url (required)

### scan_target
RECOMMENDED FIRST STEP: Deep-crawl the entire target website and return a complete \
attack surface map — all pages, forms, parameters, and technologies detected. \
Args: base_url (required), max_depth (default 3), max_pages (default 100).

### validate_finding
CRITICAL: Use this to CONFIRM any suspected vulnerability. It runs deterministic \
code-based checks (canary strings, regex patterns). A vulnerability is only real \
if this returns "validated": true.
Args: vuln_type (required), url (required), param_name (required), method (GET/POST), \
extra_params (optional: extra form fields like {"Submit": "Submit"}).
Supported vuln_type values: sqli, xss, command_injection, path_traversal, \
csrf, idor, open_redirect, ssrf, security_headers, sensitive_data

## Workflow
1. If the target requires login, use authenticate first
2. Use scan_target to deep-crawl and get the full attack surface map
3. For each endpoint with parameters, test for all 10 vulnerability types
4. ALWAYS call validate_finding to confirm any suspected vulnerability
5. When done, write SCAN COMPLETE with a summary of VALIDATED findings only

## Tips
- Include extra_params like {"Submit": "Submit"} for apps that require submit buttons
- For CSRF, test POST forms that change state
- For IDOR, test parameters that look like IDs (id, user_id, order_id)
"""

SYSTEM_PROMPT_ANTHROPIC = """\
You are an expert penetration tester AI agent working in an authorized lab environment.
Your job is to find and confirm real vulnerabilities in web applications.

## Workflow
1. If the target requires login, call authenticate first
2. Call scan_target to get the full attack surface (all pages, forms, parameters)
3. For each endpoint with parameters, test all 10 vulnerability types
4. ALWAYS call validate_finding to confirm any suspected vulnerability — never report unconfirmed findings
5. When done, respond with SCAN COMPLETE and a summary of confirmed vulnerabilities only

## Tips
- Always include extra_params like {"Submit": "Submit"} for DVWA-style apps
- For CSRF, test POST forms that change state (password change, data modification)
- For IDOR, test ID-like parameters (id, user_id, order_id, doc)
- validate_finding runs deterministic checks — trust its result
"""


# ── Anthropic tool schema conversion ─────────────────────────────────────

def _convert_tool_schemas_for_anthropic():
    """Convert our tool schemas to Anthropic's tool format."""
    anthropic_tools = []
    for schema in TOOL_SCHEMAS:
        # Our schemas use OpenAI-style format, convert to Anthropic format
        anthropic_tools.append({
            "name": schema["name"],
            "description": schema.get("description", ""),
            "input_schema": schema.get("parameters", schema.get("input_schema", {
                "type": "object", "properties": {}, "required": []
            })),
        })
    return anthropic_tools


# ── Ollama backend ────────────────────────────────────────────────────────

def _parse_tool_call(text):
    """Extract tool call from Ollama's text response."""
    pattern = r'```tool\s*\n?(.*?)\n?```'
    matches = re.findall(pattern, text, re.DOTALL)
    if matches:
        try:
            data = json.loads(matches[0].strip())
            return data.get("tool"), data.get("args", {})
        except json.JSONDecodeError:
            pass

    pattern2 = r'```(?:json)?\s*\n?(\{[^`]*"tool"[^`]*\})\s*\n?```'
    matches2 = re.findall(pattern2, text, re.DOTALL)
    if matches2:
        try:
            data = json.loads(matches2[0].strip())
            return data.get("tool"), data.get("args", {})
        except json.JSONDecodeError:
            pass

    pattern3 = r'\{[^{}]*"tool"\s*:\s*"[^"]+?"[^{}]*\}'
    matches3 = re.findall(pattern3, text, re.DOTALL)
    if matches3:
        try:
            data = json.loads(matches3[0])
            return data.get("tool"), data.get("args", {})
        except json.JSONDecodeError:
            pass

    return None, None


def _call_ollama(messages):
    """Send messages to Ollama and get a response."""
    client = httpx.Client(timeout=180)
    try:
        resp = client.post(OLLAMA_URL, json={
            "model": MODEL,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "num_predict": 1024,
                "stop": ["**Tool Result:**", "Tool result:", "Result:"],
            }
        })
        resp.raise_for_status()
        return resp.json()["message"]["content"]
    except Exception as e:
        return f"Error calling Ollama: {e}"


def _run_ollama_agent(target_url, task, auth_status):
    """Run the agent loop using Ollama backend."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT_OLLAMA},
        {
            "role": "user",
            "content": (
                f"Target: {target_url}\n\nTask: {task}\n\n{auth_status}\n"
                "Start with scan_target, test all vulnerability types, "
                "always validate with validate_finding. Write SCAN COMPLETE when done."
            ),
        }
    ]

    validated_findings = []

    for iteration in range(1, MAX_ITERATIONS + 1):
        console.rule(f"[bold blue]Iteration {iteration}/{MAX_ITERATIONS}")
        response_text = _call_ollama(messages)

        display_text = response_text[:800] + ("\n..." if len(response_text) > 800 else "")
        console.print(Panel(display_text, title="[bold green]Agent Thinking", border_style="green"))

        if "SCAN COMPLETE" in response_text.upper():
            console.print("[bold green]Agent finished.[/]")
            break

        tool_name, tool_args = _parse_tool_call(response_text)

        if tool_name and tool_name in TOOL_DISPATCH:
            console.print(f"  [bold yellow]→ {tool_name}[/]({json.dumps(tool_args)[:300]})")
            try:
                result = TOOL_DISPATCH[tool_name](**tool_args)
            except TypeError as e:
                result = {"error": f"Bad arguments: {e}"}

            result_str = json.dumps(result, indent=2, default=str)
            console.print(f"  [dim]← {result_str[:600]}{'...' if len(result_str) > 600 else ''}[/dim]")

            if tool_name == "validate_finding" and result.get("validated"):
                validated_findings.append(result)
                console.print(f"  [bold red]CONFIRMED: {result['type']}[/]")

            messages.append({"role": "assistant", "content": response_text})
            messages.append({
                "role": "user",
                "content": (
                    f"Tool result for {tool_name}:\n{result_str[:3000]}\n\n"
                    "Analyze this. If you found a potential vulnerability, "
                    "use validate_finding to confirm. Otherwise, continue testing."
                )
            })
        elif tool_name:
            messages.append({"role": "assistant", "content": response_text})
            messages.append({"role": "user",
                             "content": f"Unknown tool: {tool_name}. Available: {', '.join(TOOL_DISPATCH.keys())}"})
        else:
            messages.append({"role": "assistant", "content": response_text})
            messages.append({"role": "user",
                             "content": "Use a tool to continue. Write SCAN COMPLETE when done."})

    return validated_findings


# ── Anthropic backend ─────────────────────────────────────────────────────

def _run_anthropic_agent(target_url, task, auth_status):
    """Run the agent loop using Anthropic API with native tool use."""
    try:
        import anthropic
    except ImportError:
        console.print("[bold red]Error:[/] anthropic package not installed. Run: pip install anthropic")
        return []

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[bold red]Error:[/] ANTHROPIC_API_KEY environment variable not set.")
        console.print("[dim]Set it with: export ANTHROPIC_API_KEY=sk-ant-...[/]")
        return []

    client = anthropic.Anthropic(api_key=api_key)
    tools = _convert_tool_schemas_for_anthropic()

    messages = [
        {
            "role": "user",
            "content": (
                f"Target: {target_url}\n\nTask: {task}\n\n{auth_status}\n\n"
                "Start with scan_target to map the attack surface, then test all "
                "10 vulnerability types. Always call validate_finding to confirm. "
                "Write SCAN COMPLETE when done."
            ),
        }
    ]

    validated_findings = []

    for iteration in range(1, MAX_ITERATIONS + 1):
        console.rule(f"[bold blue]Iteration {iteration}/{MAX_ITERATIONS}")

        try:
            response = client.messages.create(
                model=ANTHROPIC_MODEL,
                max_tokens=4096,
                system=SYSTEM_PROMPT_ANTHROPIC,
                tools=tools,
                messages=messages,
            )
        except anthropic.APIError as e:
            console.print(f"[red]Anthropic API error: {e}[/]")
            break

        # Show text thinking
        for block in response.content:
            if hasattr(block, 'text') and block.text:
                display = block.text[:800] + ("\n..." if len(block.text) > 800 else "")
                console.print(Panel(display, title="[bold green]Agent Thinking", border_style="green"))

        # Check stop condition
        if response.stop_reason == "end_turn":
            full_text = " ".join(
                block.text for block in response.content if hasattr(block, 'text')
            )
            if "SCAN COMPLETE" in full_text.upper() or not any(
                hasattr(b, 'name') for b in response.content
            ):
                console.print("[bold green]Agent finished.[/]")
                break

        # Process tool use blocks (native — no parsing needed)
        tool_calls_made = False
        tool_results = []

        for block in response.content:
            if block.type == "tool_use":
                tool_name = block.name
                tool_args = block.input
                tool_use_id = block.id

                console.print(f"  [bold yellow]→ {tool_name}[/]({json.dumps(tool_args)[:300]})")

                if tool_name in TOOL_DISPATCH:
                    try:
                        result = TOOL_DISPATCH[tool_name](**tool_args)
                    except TypeError as e:
                        result = {"error": f"Bad arguments: {e}"}
                else:
                    result = {"error": f"Unknown tool: {tool_name}"}

                result_str = json.dumps(result, indent=2, default=str)
                console.print(f"  [dim]← {result_str[:600]}{'...' if len(result_str) > 600 else ''}[/dim]")

                if tool_name == "validate_finding" and result.get("validated"):
                    validated_findings.append(result)
                    console.print(f"  [bold red]CONFIRMED: {result['type']}[/]")

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": result_str[:4000],
                })
                tool_calls_made = True

        if not tool_calls_made:
            break

        # Append assistant turn and tool results
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

    return validated_findings


# ── Public entry point ────────────────────────────────────────────────────

def run_agent(target_url, task, auth_config=None, llm_backend="ollama"):
    """
    Run the pentest agent against a target.

    Args:
        target_url:   The target application URL
        task:         What to test for
        auth_config:  Optional auth settings dict
        llm_backend:  "ollama" (default, free/local) or "anthropic" (Claude API)
    """
    # Authenticate if config provided
    if auth_config:
        auth_type = auth_config.get("auth_type", "form")
        console.print(f"[bold cyan]Authenticating ({auth_type})...[/]")
        login_result = authenticate(**auth_config)
        if login_result.get("success"):
            console.print(f"[bold green]OK[/] {login_result['message']}")
        else:
            console.print(f"[bold red]Auth failed:[/] {login_result.get('error', 'Unknown')}")
            console.print("[yellow]Continuing without authentication...[/]")
    else:
        console.print("[dim]No auth config — agent will authenticate if needed.[/]")

    auth_status = (
        "You are already authenticated. Session cookies are auto-attached."
        if auth_config and get_session_cookies()
        else (
            "You are NOT authenticated. If the target has a login page, "
            "use authenticate first (auth_type='form', provide login_url, username, password)."
        )
    )

    backend_label = f"[bold]LLM:[/] {llm_backend.upper()}"
    if llm_backend == "anthropic":
        backend_label += f" ({ANTHROPIC_MODEL})"
    else:
        backend_label += f" ({MODEL})"
    console.print(backend_label)

    # Run the appropriate backend
    if llm_backend == "anthropic":
        validated_findings = _run_anthropic_agent(target_url, task, auth_status)
    else:
        validated_findings = _run_ollama_agent(target_url, task, auth_status)

    # Print summary
    console.print()
    console.rule("[bold red]Validated Findings")
    if validated_findings:
        from pipeline import print_findings_detailed
        # Convert to standard finding dict format
        findings = [
            {
                "source": f"agent-{llm_backend}",
                "vuln_type": f.get("type", "Unknown"),
                "url": f.get("url", ""),
                "param_name": f.get("param_name", ""),
                "method": f.get("method", "GET"),
                "payload": str(f.get("payload", "")),
                "evidence": str(f.get("evidence", "")),
                "severity": f.get("severity", ""),
            }
            for f in validated_findings
        ]
        print_findings_detailed(findings)
    else:
        console.print("[yellow]No vulnerabilities confirmed by validator.[/]")

    return validated_findings
