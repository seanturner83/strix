"""Per-role model resolution and its fallback chains."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.config import loader
from strix.config.roles import resolve_role_model


if TYPE_CHECKING:
    from collections.abc import Iterator


_ROLE_ENV = (
    "STRIX_LLM",
    "STRIX_LLM_ORCHESTRATOR",
    "STRIX_LLM_SUBAGENT",
    "STRIX_LLM_COMPRESSOR",
    "STRIX_LLM_ORCHESTRATOR_API_BASE",
    "STRIX_LLM_SUBAGENT_API_BASE",
    "STRIX_LLM_COMPRESSOR_API_BASE",
    "LLM_API_BASE",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
)


@pytest.fixture
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in _ROLE_ENV:
        monkeypatch.delenv(key, raising=False)
    loader._cached = None
    yield
    loader._cached = None


def _reload() -> None:
    loader._cached = None


def test_unset_roles_default_to_strix_llm(
    monkeypatch: pytest.MonkeyPatch, _clean_env: None
) -> None:
    monkeypatch.setenv("STRIX_LLM", "main-model")
    _reload()
    assert resolve_role_model("compressor") == ("main-model", None)
    assert resolve_role_model("orchestrator") == ("main-model", None)
    assert resolve_role_model("subagent") == ("main-model", None)
    assert resolve_role_model(None) == ("main-model", None)


def test_compressor_override_carries_its_api_base(
    monkeypatch: pytest.MonkeyPatch, _clean_env: None
) -> None:
    monkeypatch.setenv("STRIX_LLM", "claude-code/claude-opus-4-8")
    monkeypatch.setenv("STRIX_LLM_COMPRESSOR", "local-qwen")
    monkeypatch.setenv("STRIX_LLM_COMPRESSOR_API_BASE", "http://localhost:1234/v1")
    _reload()
    assert resolve_role_model("compressor") == ("local-qwen", "http://localhost:1234/v1")
    # The orchestrator is untouched by a compressor override.
    assert resolve_role_model("orchestrator") == ("claude-code/claude-opus-4-8", None)


def test_compressor_falls_back_through_orchestrator_not_a_cheap_default(
    monkeypatch: pytest.MonkeyPatch, _clean_env: None
) -> None:
    # With no compressor set but an orchestrator override, the compressor inherits
    # the orchestrator (capable) model — never a weak default.
    monkeypatch.setenv("STRIX_LLM", "main-model")
    monkeypatch.setenv("STRIX_LLM_ORCHESTRATOR", "orch-model")
    monkeypatch.setenv("STRIX_LLM_ORCHESTRATOR_API_BASE", "http://orch")
    _reload()
    assert resolve_role_model("compressor") == ("orch-model", "http://orch")
    assert resolve_role_model("subagent") == ("orch-model", "http://orch")


def test_subagent_override(monkeypatch: pytest.MonkeyPatch, _clean_env: None) -> None:
    monkeypatch.setenv("STRIX_LLM", "main-model")
    monkeypatch.setenv("STRIX_LLM_SUBAGENT", "sub-model")
    _reload()
    assert resolve_role_model("subagent") == ("sub-model", None)
    assert resolve_role_model("compressor") == ("main-model", None)
