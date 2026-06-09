"""
BaseAgent — shared agent loop supporting multiple LLM backends.

Supported backends:
- ollama: Local LLM via Ollama (free, default)
- groq: Groq API — ultra-fast inference (free tier)
- gemini: Google Gemini API (free tier)
- anthropic: Anthropic Claude API (paid)
"""

import json
import os
import re
import sys
import asyncio
from rich.console import Console

console = Console()

OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "qwen3:14b"
OLLAMA_MODEL_FALLBACK = "deepseek-r1:14b"
ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"
GROQ_MODEL = "llama-3.1-8b-instant"
GEMINI_MODEL = "gemini-2.0-flash"


def _load_env():
    """Load .env file into os.environ if python-dotenv is available."""
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        # Manual fallback
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
        if os.path.isfile(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        os.environ.setdefault(key.strip(), val.strip())


class BaseAgent:
    model = ANTHROPIC_MODEL
    ollama_model = OLLAMA_MODEL
    groq_model = GROQ_MODEL
    gemini_model = GEMINI_MODEL
    max_iterations = 15
    system_prompt = ""
    allowed_tools = []
    agent_name = "BaseAgent"

    # If True, look up curated bug-bounty knowledge from skills/ and inject
    # it into the system prompt. Each subclass should set `vuln_type` to enable.
    inject_skill = True
    skill_name = None   # explicit override; if None, looked up by vuln_type

    def _resolve_skill_addendum(self) -> str:
        """Resolve the curated knowledge addendum for this agent (cached)."""
        if not self.inject_skill:
            return ""
        try:
            import sys, os
            # Make project root importable
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if root not in sys.path:
                sys.path.insert(0, root)
            from skill_loader import skill_for_agent, load_skill, build_prompt_addendum
            # Explicit skill_name takes priority; else use vuln_type
            body = None
            if self.skill_name:
                body = load_skill(self.skill_name)
            if not body:
                vt = getattr(self, "vuln_type", None) or self.agent_name
                body = skill_for_agent(vt)
            return build_prompt_addendum(body) if body else ""
        except Exception as e:
            from engine.logging_setup import get_logger
            get_logger().warning("skill_load_failed", agent=getattr(self, "agent_name", "?"), error=str(e))
            return ""

    def __init__(self, llm_backend="ollama"):
        self.llm_backend = llm_backend
        _load_env()

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
            self.client = anthropic.Anthropic(api_key=api_key)

        elif llm_backend == "groq":
            try:
                from groq import Groq
            except ImportError:
                console.print("[bold red]groq not installed. Run: pip install groq[/]")
                sys.exit(1)
            api_key = os.environ.get("GROQ_API_KEY")
            if not api_key:
                console.print("[bold red]GROQ_API_KEY not set in .env[/]")
                sys.exit(1)
            self.groq_client = Groq(api_key=api_key)

        elif llm_backend == "gemini":
            try:
                from google import genai
            except ImportError:
                console.print("[bold red]google-genai not installed. Run: pip install google-genai[/]")
                sys.exit(1)
            api_key = os.environ.get("GEMINI_API_KEY")
            if not api_key:
                console.print("[bold red]GEMINI_API_KEY not set in .env[/]")
                sys.exit(1)
            self.gemini_client = genai.Client(api_key=api_key)

        self._tools = self._build_tool_schemas()

        # Inject curated bug-bounty knowledge (from skills/) into the system prompt.
        # One-shot: happens at agent init so all backends (anthropic/groq/gemini/
        # ollama) pick it up automatically.
        addendum = self._resolve_skill_addendum()
        if addendum:
            # Append once — the system_prompt is a class attribute, so we shadow
            # it on the instance to avoid polluting other agent instances.
            self.system_prompt = (self.system_prompt or "") + addendum
            try:
                console.print(
                    f"  [dim]{self.agent_name}: loaded curated skill "
                    f"(+{len(addendum)} chars of disclosed-report knowledge)[/]"
                )
            except Exception as e:
                from engine.logging_setup import get_logger
                get_logger().warning("agent_console_print_failed", agent=getattr(self, "agent_name", "?"), error=str(e))

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
        elif self.llm_backend == "groq":
            return self._run_groq(user_message)
        elif self.llm_backend == "gemini":
            return self._run_gemini(user_message)
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
            except Exception as e:
                from engine.logging_setup import get_logger
                get_logger().warning("agent_client_reset_failed", agent=getattr(self, "agent_name", "?"), error=str(e))

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
                from engine.logging_setup import get_logger
                get_logger().warning("agent_validation_failed", agent=getattr(self, "agent_name", "?"), error=str(e))

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

    # ── Groq backend ───────────────────────────────────────────────

    def _run_groq(self, user_message: str) -> list:
        """
        Groq mode — uses OpenAI-compatible chat API with tool calling.
        Ultra-fast inference (840 tokens/sec on Llama 3.1 8B).
        """
        vuln_type = getattr(self, "vuln_type", None)
        if vuln_type:
            return self._run_ollama_direct(user_message)  # deterministic path

        tool_desc = self._build_ollama_tool_desc()
        system = self.system_prompt + f"\n\n## Tools Available\n{tool_desc}\n\n" + OLLAMA_TOOL_FORMAT

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_message},
        ]
        findings = []
        max_iter = min(self.max_iterations, 10)

        for _ in range(max_iter):
            try:
                resp = self.groq_client.chat.completions.create(
                    model=self.groq_model,
                    messages=messages,
                    max_tokens=2048,
                    temperature=0.1,
                )
                response_text = resp.choices[0].message.content or ""
            except Exception as e:
                console.print(f"  [red]{self.agent_name} Groq error: {e}[/]")
                break

            if "DONE" in response_text.upper() or "NO MORE" in response_text.upper():
                break

            tool_name, tool_args = self._parse_tool_call(response_text)
            if not tool_name:
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

    # ── Gemini backend ───────────────────────────────────────────

    def _run_gemini(self, user_message: str) -> list:
        """
        Gemini mode — uses Google Gemini API.
        Free tier: 15 requests/min.
        """
        vuln_type = getattr(self, "vuln_type", None)
        if vuln_type:
            return self._run_ollama_direct(user_message)  # deterministic path

        tool_desc = self._build_ollama_tool_desc()
        system = self.system_prompt + f"\n\n## Tools Available\n{tool_desc}\n\n" + OLLAMA_TOOL_FORMAT

        full_prompt = f"{system}\n\nUser: {user_message}"
        findings = []
        max_iter = min(self.max_iterations, 10)

        messages_context = full_prompt

        for _ in range(max_iter):
            try:
                resp = self.gemini_client.models.generate_content(
                    model=self.gemini_model,
                    contents=messages_context,
                )
                response_text = resp.text or ""
            except Exception as e:
                console.print(f"  [red]{self.agent_name} Gemini error: {e}[/]")
                break

            if "DONE" in response_text.upper() or "NO MORE" in response_text.upper():
                break

            tool_name, tool_args = self._parse_tool_call(response_text)
            if not tool_name:
                break

            result = self._execute_tool(tool_name, tool_args)

            if tool_name == "validate_finding" and result.get("validated"):
                findings.append(result)
                console.print(
                    f"  [bold red][{self.agent_name}] CONFIRMED: {result.get('type')}[/]"
                )

            result_str = json.dumps(result, default=str)[:2000]
            messages_context += (
                f"\n\nAssistant: {response_text}\n\n"
                f"User: Tool result for {tool_name}:\n{result_str}\n\n"
                f"Continue testing. Write DONE when finished."
            )

        return findings

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
        except Exception as e:
            from engine.logging_setup import get_logger
            get_logger().warning("agent_deterministic_test_failed", agent=getattr(self, "agent_name", "?"), error=str(e))
        if config.llm_available and hasattr(self, '_llm_enhance_findings'):
            try:
                findings = self._llm_enhance_findings(findings, endpoint, config)
            except Exception as e:
                from engine.logging_setup import get_logger
                get_logger().warning("agent_llm_enhance_failed", agent=getattr(self, "agent_name", "?"), error=str(e))
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
            except Exception as e:
                from engine.logging_setup import get_logger
                get_logger().warning("agent_client_reset_failed", agent=getattr(self, "agent_name", "?"), error=str(e))
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
            except Exception as e:
                from engine.logging_setup import get_logger
                get_logger().warning("agent_validation_failed", agent=getattr(self, "agent_name", "?"), error=str(e))
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
