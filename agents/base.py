"""
BaseAgent — shared agent loop supporting both Anthropic API and Ollama backends.

- Anthropic: native tool_use blocks, parallel-safe
- Ollama: text-based tool calling with regex parser, sequential only
"""

import json
import os
import re
import sys
import asyncio
from rich.console import Console

console = Console()

OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "deepseek-r1:14b"
ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"


class BaseAgent:
    model = ANTHROPIC_MODEL
    ollama_model = OLLAMA_MODEL
    max_iterations = 15
    system_prompt = ""
    allowed_tools = []
    agent_name = "BaseAgent"

    def __init__(self, llm_backend="ollama"):
        self.llm_backend = llm_backend

        if llm_backend == "anthropic":
            try:
                import anthropic
            except ImportError:
                console.print("[bold red]anthropic not installed. Run: pip install anthropic[/]")
                sys.exit(1)
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                console.print("[bold red]ANTHROPIC_API_KEY not set.[/]")
                sys.exit(1)
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key)

        self._tools = self._build_tool_schemas()

    def _build_tool_schemas(self):
        from tools import TOOL_SCHEMAS
        schemas = []
        for s in TOOL_SCHEMAS:
            if self.allowed_tools and s["name"] not in self.allowed_tools:
                continue
            schemas.append({
                "name": s["name"],
                "description": s.get("description", ""),
                "input_schema": s.get("parameters", s.get("input_schema", {
                    "type": "object", "properties": {}, "required": []
                })),
            })
        return schemas

    async def run(self, user_message: str) -> list:
        """Async wrapper — runs sync loop in thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync, user_message)

    def _run_sync(self, user_message: str) -> list:
        if self.llm_backend == "anthropic":
            return self._run_anthropic(user_message)
        else:
            return self._run_ollama_direct(user_message)

    def _run_ollama_direct(self, user_message: str) -> list:
        """
        Ollama mode — skip LLM text parsing entirely.
        Directly call validate_finding for every test target using the vuln_type
        defined on the agent class. Fast, reliable, zero text parsing issues.
        """
        vuln_type = getattr(self, "vuln_type", None)
        if not vuln_type:
            return self._run_ollama(user_message)  # fallback to LLM if no vuln_type set

        from tools import TOOL_DISPATCH
        findings = []

        # Parse test targets from the message
        targets = self._parse_targets_from_message(user_message)
        if not targets:
            return []

        console.print(f"  [dim]{self.agent_name}: testing {len(targets)} parameter(s)...[/]")

        for t in targets:
            try:
                from validator import _reset_client
                _reset_client()
            except Exception:
                pass

            extra_params = {}
            # Common submit buttons needed for form-based endpoints
            url = t.get("url", "")
            if any(x in url for x in ["/sqli", "/xss", "/exec", "/csrf", "/fi", "/upload"]):
                extra_params = {"Submit": "Submit"}

            try:
                result = TOOL_DISPATCH["validate_finding"](
                    vuln_type=vuln_type,
                    url=t["url"],
                    param_name=t["param"],
                    method=t.get("method", "GET"),
                    extra_params=extra_params if extra_params else None,
                )
                if result.get("validated"):
                    findings.append(result)
                    console.print(
                        f"  [bold red][{self.agent_name}] CONFIRMED: {result.get('type')} "
                        f"@ {t['param']}[/]"
                    )
            except Exception as e:
                pass  # silently skip failed checks

        return findings

    @staticmethod
    def _parse_targets_from_message(msg: str) -> list:
        """Extract test targets from the orchestrator message."""
        import re
        targets = []
        for line in msg.split("\n"):
            m = re.search(r'URL:\s*(\S+)\s*\|\s*param:\s*(\S+)\s*\|\s*method:\s*(\S+)', line)
            if m:
                targets.append({"url": m.group(1), "param": m.group(2), "method": m.group(3)})
        return targets

    # ── Anthropic backend ─────────────────────────────────────────

    def _run_anthropic(self, user_message: str) -> list:
        import anthropic
        messages = [{"role": "user", "content": user_message}]
        findings = []

        for _ in range(self.max_iterations):
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=2048,
                    system=self.system_prompt,
                    tools=self._tools,
                    messages=messages,
                )
            except anthropic.APIError as e:
                console.print(f"  [red]{self.agent_name} API error: {e}[/]")
                break

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = self._execute_tool(block.name, block.input)
                    if block.name == "validate_finding" and result.get("validated"):
                        findings.append(result)
                        console.print(
                            f"  [bold red][{self.agent_name}] CONFIRMED: {result.get('type')}[/]"
                        )
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result, default=str)[:4000],
                    })

            if not tool_results:
                break

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        return findings

    # ── Ollama backend ────────────────────────────────────────────

    def _run_ollama(self, user_message: str) -> list:
        import httpx

        # Build tool description for system prompt
        tool_desc = self._build_ollama_tool_desc()
        system = self.system_prompt + f"\n\n## Tools Available\n{tool_desc}\n\n" + OLLAMA_TOOL_FORMAT

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ]
        findings = []

        client = httpx.Client(timeout=180)
        max_iter = min(self.max_iterations, 10)  # cap for Ollama — prevent hangs

        for _ in range(max_iter):
            try:
                resp = client.post(OLLAMA_URL, json={
                    "model": self.ollama_model,
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "num_predict": 512,
                        "stop": ["Tool result:", "**Tool Result:**"],
                    },
                })
                resp.raise_for_status()
                response_text = resp.json()["message"]["content"]
            except Exception as e:
                console.print(f"  [red]{self.agent_name} Ollama error: {e}[/]")
                break

            if "DONE" in response_text.upper() or "NO MORE" in response_text.upper():
                break

            tool_name, tool_args = self._parse_tool_call(response_text)

            if not tool_name:
                # No tool call — agent is done
                break

            result = self._execute_tool(tool_name, tool_args)

            if tool_name == "validate_finding" and result.get("validated"):
                findings.append(result)
                console.print(
                    f"  [bold red][{self.agent_name}] CONFIRMED: {result.get('type')}[/]"
                )

            result_str = json.dumps(result, default=str)[:2000]
            messages.append({"role": "assistant", "content": response_text})
            messages.append({
                "role": "user",
                "content": f"Tool result for {tool_name}:\n{result_str}\n\nContinue testing. Write DONE when finished.",
            })

        return findings

    def _build_ollama_tool_desc(self) -> str:
        lines = []
        for t in self._tools:
            lines.append(f"### {t['name']}\n{t['description']}")
        return "\n\n".join(lines)

    @staticmethod
    def _parse_tool_call(text):
        """Extract tool call JSON from Ollama text response."""
        for pattern in [
            r'```tool\s*\n?(.*?)\n?```',
            r'```(?:json)?\s*\n?(\{[^`]*"tool"[^`]*\})\s*\n?```',
            r'\{[^{}]*"tool"\s*:\s*"[^"]+?"[^{}]*\}',
        ]:
            matches = re.findall(pattern, text, re.DOTALL)
            if matches:
                try:
                    data = json.loads(matches[0].strip())
                    return data.get("tool"), data.get("args", {})
                except json.JSONDecodeError:
                    continue
        return None, None

    # ── Shared ────────────────────────────────────────────────────

    def _execute_tool(self, name: str, args: dict) -> dict:
        from tools import TOOL_DISPATCH
        if name in TOOL_DISPATCH:
            try:
                return TOOL_DISPATCH[name](**args)
            except TypeError as e:
                return {"error": f"Bad arguments for {name}: {e}"}
        return {"error": f"Unknown tool: {name}"}

    # ── New deterministic-first interface for DecisionEngine ──

    def test_endpoint(self, endpoint, config, state) -> list:
        """
        DecisionEngine entry point. Runs deterministic test, optionally enhances with LLM.
        Returns list of finding dicts.
        """
        findings = []
        try:
            findings = self._deterministic_test(endpoint, config, state)
        except Exception:
            pass
        if config.llm_available and hasattr(self, '_llm_enhance_findings'):
            try:
                findings = self._llm_enhance_findings(findings, endpoint, config)
            except Exception:
                pass
        return findings

    def _deterministic_test(self, endpoint, config, state) -> list:
        """
        Override in subclass for custom logic. Default: calls validate_finding
        for each param in the endpoint via TOOL_DISPATCH.
        """
        from tools import TOOL_DISPATCH

        vuln_type = getattr(self, "vuln_type", None)
        if not vuln_type:
            return []

        findings = []
        params_to_test = endpoint.params if endpoint.params else [""]

        for param in params_to_test:
            try:
                from validator import _reset_client
                _reset_client()
            except Exception:
                pass
            try:
                result = TOOL_DISPATCH["validate_finding"](
                    vuln_type=vuln_type,
                    url=endpoint.url,
                    param_name=param,
                    method=endpoint.method,
                    cookies=config.cookies if config.cookies else None,
                    extra_params=None,
                )
                if result.get("validated"):
                    result["severity"] = self._get_default_severity()
                    result["source"] = self.agent_name
                    result["vuln_type"] = result.get("type", vuln_type)
                    result["param_name"] = param
                    findings.append(result)
            except Exception:
                pass
        return findings

    def _get_default_severity(self) -> str:
        """Default severity by vuln type."""
        severity_map = {
            "sqli": "High", "xss": "Medium", "command_injection": "Critical",
            "path_traversal": "High", "csrf": "Medium", "idor": "High",
            "ssrf": "High", "open_redirect": "Low", "security_headers": "Low",
            "sensitive_data": "Medium",
        }
        vt = getattr(self, "vuln_type", "")
        return severity_map.get(vt, "Medium")


OLLAMA_TOOL_FORMAT = """\
## How to call a tool
Respond with EXACTLY this format — nothing else after the closing ```:
```tool
{"tool": "tool_name", "args": {"param1": "value1"}}
```
STOP after ```. Do NOT guess results. Write DONE when you have finished testing.\
"""
