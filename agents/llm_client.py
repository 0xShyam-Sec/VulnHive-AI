"""LLM client with structured output via Instructor over Ollama's OpenAI-compatible API.

Replaces the regex-based _parse_tool_call() chain in agents/base.py.

Two models:
- qwen3:14b (default) — fast, consistent JSON output
- deepseek-r1:14b      — used by reasoning-heavy agents; emits <think>…</think>
                         block that needs stripping before parsing
"""

from __future__ import annotations

import re
from typing import Any, Optional

from pydantic import BaseModel, Field


OLLAMA_DEFAULT = "qwen3:14b"
OLLAMA_REASONING = "deepseek-r1:14b"


# Agents whose work benefits from deepseek-r1's stronger chain-of-thought.
MODEL_PER_AGENT: dict[str, str] = {
    "business_logic": OLLAMA_REASONING,
    "auth_bypass": OLLAMA_REASONING,
    "oauth": OLLAMA_REASONING,
    "race_condition": OLLAMA_REASONING,
    "ato": OLLAMA_REASONING,
}


_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def strip_reasoning_block(raw: str) -> str:
    """Remove deepseek-r1's <think>...</think> chain-of-thought block(s)."""
    return _THINK_RE.sub("", raw).strip()


def pick_model(agent_name: str) -> str:
    """Return the Ollama model name for an agent. Defaults to qwen3:14b."""
    return MODEL_PER_AGENT.get(agent_name, OLLAMA_DEFAULT)


class ToolCall(BaseModel):
    """Structured LLM tool call. Validated by Instructor via Ollama format=schema."""

    tool: str = Field(description="The tool to invoke (e.g. validate_finding)")
    args: dict[str, Any] = Field(default_factory=dict)


class FindingOutput(BaseModel):
    """Structured finding directly emitted by LLM-opinion agents (HeadersAgent etc.)."""

    vuln_type: str
    url: str
    method: str = "GET"
    param_name: Optional[str] = None
    payload: Optional[str] = None
    evidence: str = ""
    severity: str = "medium"
    confidence: str = "medium"


_client = None


def get_client():
    """Lazy: build the Instructor-wrapped OpenAI-compatible client once."""
    global _client
    if _client is not None:
        return _client

    import instructor
    from openai import OpenAI

    _client = instructor.from_openai(
        OpenAI(base_url="http://localhost:11434/v1", api_key="ollama"),
        mode=instructor.Mode.JSON,
    )
    return _client


def call_tool(model: str, system: str, user: str, max_retries: int = 2) -> ToolCall:
    """Ask the LLM for a structured ToolCall. On malformed output, Instructor retries."""
    client = get_client()
    return client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system + "\n\nIMPORTANT: Reply with ONE JSON object only."},
            {"role": "user", "content": user},
        ],
        response_model=ToolCall,
        max_retries=max_retries,
    )


def call_finding(model: str, system: str, user: str, max_retries: int = 2) -> FindingOutput:
    """Ask the LLM directly for a Finding (LLM-opinion agents)."""
    client = get_client()
    return client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system + "\n\nReply with one JSON Finding object."},
            {"role": "user", "content": user},
        ],
        response_model=FindingOutput,
        max_retries=max_retries,
    )
