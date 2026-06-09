from agents.llm_client import (
    MODEL_PER_AGENT,
    OLLAMA_DEFAULT,
    OLLAMA_REASONING,
    pick_model,
    strip_reasoning_block,
)


def test_strip_deepseek_think_block():
    raw = "<think>internal monologue here</think>\n{\"tool\":\"x\",\"args\":{}}"
    assert strip_reasoning_block(raw) == '{"tool":"x","args":{}}'


def test_strip_handles_text_without_think():
    raw = '{"tool":"x","args":{}}'
    assert strip_reasoning_block(raw) == raw


def test_pick_model_defaults_to_qwen():
    assert pick_model("sqli") == OLLAMA_DEFAULT


def test_pick_model_uses_deepseek_for_reasoning_heavy_agents():
    assert pick_model("business_logic") == OLLAMA_REASONING
    assert pick_model("auth_bypass") == OLLAMA_REASONING
    assert pick_model("oauth") == OLLAMA_REASONING


def test_model_per_agent_table_exists():
    assert isinstance(MODEL_PER_AGENT, dict)
