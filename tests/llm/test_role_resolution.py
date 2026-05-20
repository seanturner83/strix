"""Tests for per-role LLM resolution (STRIX_LLM_ORCHESTRATOR / _SUBAGENT / _COMPRESSOR).

Fallback chain (Option B — compressor does NOT inherit from subagent):
- orchestrator: STRIX_LLM_ORCHESTRATOR -> STRIX_LLM
- subagent:     STRIX_LLM_SUBAGENT -> STRIX_LLM_ORCHESTRATOR -> STRIX_LLM
- compressor:   STRIX_LLM_COMPRESSOR -> STRIX_LLM_ORCHESTRATOR -> STRIX_LLM
- role=None:    STRIX_LLM (legacy behaviour preserved)
"""

import pytest

from strix.config.config import resolve_llm_config


_ALL_ROLE_VARS = (
    "STRIX_LLM",
    "STRIX_LLM_ORCHESTRATOR",
    "STRIX_LLM_SUBAGENT",
    "STRIX_LLM_COMPRESSOR",
    "STRIX_LLM_ORCHESTRATOR_API_BASE",
    "STRIX_LLM_SUBAGENT_API_BASE",
    "STRIX_LLM_COMPRESSOR_API_BASE",
    "LLM_API_BASE",
    "OPENAI_API_BASE",
    "LITELLM_BASE_URL",
    "OLLAMA_API_BASE",
    "LLM_API_KEY",
)


@pytest.fixture(autouse=True)
def _clear_role_env(monkeypatch):
    for var in _ALL_ROLE_VARS:
        monkeypatch.delenv(var, raising=False)


def test_only_strix_llm_set_all_roles_inherit(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-7")

    for role in (None, "orchestrator", "subagent", "compressor"):
        model, _, _ = resolve_llm_config(role=role)
        assert model == "anthropic/claude-opus-4-7"


def test_compressor_override_isolated(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-7")
    monkeypatch.setenv("STRIX_LLM_COMPRESSOR", "openai/qwen3.6-7b")

    assert resolve_llm_config(role="orchestrator")[0] == "anthropic/claude-opus-4-7"
    assert resolve_llm_config(role="subagent")[0] == "anthropic/claude-opus-4-7"
    assert resolve_llm_config(role="compressor")[0] == "openai/qwen3.6-7b"


def test_orchestrator_override_subagent_inherits_compressor_inherits(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-7")
    monkeypatch.setenv("STRIX_LLM_ORCHESTRATOR", "anthropic/claude-sonnet-4-6")

    assert resolve_llm_config(role="orchestrator")[0] == "anthropic/claude-sonnet-4-6"
    assert resolve_llm_config(role="subagent")[0] == "anthropic/claude-sonnet-4-6"
    assert resolve_llm_config(role="compressor")[0] == "anthropic/claude-sonnet-4-6"


def test_subagent_override_does_not_drag_compressor(monkeypatch):
    """Option B: setting subagent must NOT silently move compressor."""
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-7")
    monkeypatch.setenv("STRIX_LLM_SUBAGENT", "openai/qwen3.6-7b")

    assert resolve_llm_config(role="orchestrator")[0] == "anthropic/claude-opus-4-7"
    assert resolve_llm_config(role="subagent")[0] == "openai/qwen3.6-7b"
    assert resolve_llm_config(role="compressor")[0] == "anthropic/claude-opus-4-7"


def test_all_three_distinct(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-7")
    monkeypatch.setenv("STRIX_LLM_ORCHESTRATOR", "anthropic/claude-opus-4-7")
    monkeypatch.setenv("STRIX_LLM_SUBAGENT", "anthropic/claude-sonnet-4-6")
    monkeypatch.setenv("STRIX_LLM_COMPRESSOR", "openai/qwen3.6-7b")

    assert resolve_llm_config(role="orchestrator")[0] == "anthropic/claude-opus-4-7"
    assert resolve_llm_config(role="subagent")[0] == "anthropic/claude-sonnet-4-6"
    assert resolve_llm_config(role="compressor")[0] == "openai/qwen3.6-7b"


def test_explicit_model_name_overrides_role():
    from strix.llm.config import LLMConfig

    cfg = LLMConfig(model_name="anthropic/claude-haiku-4-5", role="orchestrator")
    assert cfg.model_name == "anthropic/claude-haiku-4-5"


def test_per_role_api_base_resolution(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-7")
    monkeypatch.setenv("STRIX_LLM_COMPRESSOR", "openai/qwen3.6-7b")
    monkeypatch.setenv("LLM_API_BASE", "https://bedrock-proxy.example.com")
    monkeypatch.setenv(
        "STRIX_LLM_COMPRESSOR_API_BASE", "http://localhost:1234/v1"
    )

    _, _, orch_base = resolve_llm_config(role="orchestrator")
    _, _, comp_base = resolve_llm_config(role="compressor")

    assert orch_base == "https://bedrock-proxy.example.com"
    assert comp_base == "http://localhost:1234/v1"


def test_subagent_api_base_inherits_orchestrator_then_legacy(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-7")
    monkeypatch.setenv(
        "STRIX_LLM_ORCHESTRATOR_API_BASE", "https://orch.example.com"
    )

    _, _, sub_base = resolve_llm_config(role="subagent")
    assert sub_base == "https://orch.example.com"

    monkeypatch.delenv("STRIX_LLM_ORCHESTRATOR_API_BASE")
    monkeypatch.setenv("LLM_API_BASE", "https://legacy.example.com")
    _, _, sub_base = resolve_llm_config(role="subagent")
    assert sub_base == "https://legacy.example.com"


def test_role_none_preserves_legacy_behaviour(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-7")
    monkeypatch.setenv("STRIX_LLM_ORCHESTRATOR", "should-not-be-picked-up")
    monkeypatch.setenv("STRIX_LLM_COMPRESSOR_API_BASE", "should-not-be-picked-up")
    monkeypatch.setenv("LLM_API_BASE", "https://legacy.example.com")

    model, _, api_base = resolve_llm_config(role=None)
    assert model == "anthropic/claude-opus-4-7"
    assert api_base == "https://legacy.example.com"


def test_unknown_role_raises():
    with pytest.raises(ValueError, match="Unknown LLM role"):
        resolve_llm_config(role="bogus")


def test_strix_prefix_uses_strix_api_base_regardless_of_role(monkeypatch):
    from strix.config.config import STRIX_API_BASE

    monkeypatch.setenv("STRIX_LLM_ORCHESTRATOR", "strix/some-model")
    monkeypatch.setenv("STRIX_LLM_ORCHESTRATOR_API_BASE", "https://ignored.example.com")

    _, _, api_base = resolve_llm_config(role="orchestrator")
    assert api_base == STRIX_API_BASE


def test_memory_compressor_uses_compressor_role(monkeypatch):
    from strix.llm.memory_compressor import MemoryCompressor

    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-7")
    monkeypatch.setenv("STRIX_LLM_COMPRESSOR", "openai/qwen3.6-7b")

    compressor = MemoryCompressor()
    assert compressor.model_name == "openai/qwen3.6-7b"


def test_memory_compressor_explicit_model_overrides_role(monkeypatch):
    from strix.llm.memory_compressor import MemoryCompressor

    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-7")
    monkeypatch.setenv("STRIX_LLM_COMPRESSOR", "openai/qwen3.6-7b")

    compressor = MemoryCompressor(model_name="anthropic/claude-haiku-4-5")
    assert compressor.model_name == "anthropic/claude-haiku-4-5"


def test_summarize_messages_dispatches_to_compressor_endpoint(monkeypatch):
    """End-to-end proof: _summarize_messages routes its litellm.completion
    call to the compressor role's api_base, NOT the orchestrator's."""
    from unittest.mock import MagicMock

    from strix.llm import memory_compressor

    monkeypatch.setenv("STRIX_LLM", "bedrock/us.anthropic.claude-opus-4-7")
    monkeypatch.setenv(
        "STRIX_LLM_ORCHESTRATOR_API_BASE", "https://orch.example.com"
    )
    monkeypatch.setenv("STRIX_LLM_COMPRESSOR", "openai/qwen3.6-7b")
    monkeypatch.setenv(
        "STRIX_LLM_COMPRESSOR_API_BASE", "http://localhost:1234/v1"
    )
    monkeypatch.setenv("LLM_API_KEY", "test-key")

    captured: dict = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        response = MagicMock()
        response.choices = [MagicMock()]
        response.choices[0].message.content = "summary"
        return response

    monkeypatch.setattr(memory_compressor.litellm, "completion", fake_completion)

    result = memory_compressor._summarize_messages(
        messages=[{"role": "user", "content": "hello world"}],
        model="openai/qwen3.6-7b",
        timeout=30,
    )

    assert captured["api_base"] == "http://localhost:1234/v1"
    assert captured["model"] == "openai/qwen3.6-7b"
    assert captured["api_key"] == "test-key"
    assert "summary" in result["content"]
