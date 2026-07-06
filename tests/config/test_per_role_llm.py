"""Per-role LLM model config: orchestrator / sub-agent / compressor / reporting.

Each role falls back through a chain to the base model, so unset everywhere =
today's single-model behaviour. Setting only the orchestrator makes sub-agents
inherit it before falling to the base — the property that lets a deployment
raise the whole fleet with one env var, or cost-tier sub-agents down.
"""
from __future__ import annotations

import pytest

from strix.config.settings import LlmSettings


def _resolve(s: LlmSettings) -> tuple[str, str]:
    """Mirror runner.py's resolution (base assumed set)."""
    base = s.model or ""
    orchestrator = (s.model_orchestrator or base).strip()
    subagent = (s.model_subagent or s.model_orchestrator or base).strip()
    return orchestrator, subagent


def test_base_only_all_roles_same(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "base/model")
    for k in ("STRIX_LLM_ORCHESTRATOR", "STRIX_LLM_SUBAGENT", "STRIX_LLM_COMPRESSOR",
              "STRIX_LLM_REPORTING"):
        monkeypatch.delenv(k, raising=False)
    s = LlmSettings()
    assert _resolve(s) == ("base/model", "base/model")


def test_orchestrator_only_subagent_inherits(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "base/model")
    monkeypatch.setenv("STRIX_LLM_ORCHESTRATOR", "big/opus")
    monkeypatch.delenv("STRIX_LLM_SUBAGENT", raising=False)
    s = LlmSettings()
    orch, sub = _resolve(s)
    assert orch == "big/opus"
    assert sub == "big/opus"  # inherits orchestrator, NOT base


def test_orchestrator_and_subagent_distinct(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "base/model")
    monkeypatch.setenv("STRIX_LLM_ORCHESTRATOR", "big/opus")
    monkeypatch.setenv("STRIX_LLM_SUBAGENT", "cheap/haiku")
    s = LlmSettings()
    assert _resolve(s) == ("big/opus", "cheap/haiku")


def test_subagent_only_falls_to_base(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "base/model")
    monkeypatch.delenv("STRIX_LLM_ORCHESTRATOR", raising=False)
    monkeypatch.setenv("STRIX_LLM_SUBAGENT", "cheap/haiku")
    s = LlmSettings()
    orch, sub = _resolve(s)
    assert orch == "base/model"      # no orchestrator override → base
    assert sub == "cheap/haiku"


def test_reporting_role_field_present(monkeypatch):
    # the reporting role is defined (config surface stable) even though wiring
    # is a follow-up — a deployment can set it without an unknown-env error.
    monkeypatch.setenv("STRIX_LLM_REPORTING", "cheap/fast")
    s = LlmSettings()
    assert s.model_reporting == "cheap/fast"


def test_compressor_role_field_present(monkeypatch):
    monkeypatch.setenv("STRIX_LLM_COMPRESSOR", "cheap/compress")
    s = LlmSettings()
    assert s.model_compressor == "cheap/compress"
