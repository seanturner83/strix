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


def test_dedup_role_falls_back_to_base(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "base/model")
    monkeypatch.delenv("STRIX_LLM_DEDUP", raising=False)
    s = LlmSettings()
    assert (s.model_dedup or s.model) == "base/model"


def test_dedup_role_override(monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "base/model")
    monkeypatch.setenv("STRIX_LLM_DEDUP", "cheap/sonnet")
    s = LlmSettings()
    assert s.model_dedup == "cheap/sonnet"
    # dedupe.py resolves `model_dedup or model` → the cheap model
    assert (s.model_dedup or s.model) == "cheap/sonnet"


def test_no_inert_roles_defined(monkeypatch):
    # reporting + compressor were deliberately NOT shipped: v1 writes the report
    # inline (measured: report is ~0.1-0.4% of scan input tokens — not worth a
    # separate agent) and has no compaction path for a compressor model. Guard
    # against re-adding an inert setting.
    s = LlmSettings()
    assert not hasattr(s, "model_reporting")
    assert not hasattr(s, "model_compressor")


def test_fallback_map_empty_when_unset(monkeypatch):
    monkeypatch.delenv("STRIX_LLM_FALLBACK", raising=False)
    assert LlmSettings().fallback_map() == {}


def test_fallback_map_parses_pairs(monkeypatch):
    monkeypatch.setenv(
        "STRIX_LLM_FALLBACK",
        "bedrock/us.anthropic.claude-fable-5=bedrock/us.anthropic.claude-sonnet-5,"
        "a/b=c/d",
    )
    assert LlmSettings().fallback_map() == {
        "bedrock/us.anthropic.claude-fable-5": "bedrock/us.anthropic.claude-sonnet-5",
        "a/b": "c/d",
    }


def test_fallback_map_skips_malformed(monkeypatch):
    # bare tokens (no '='), empty sides, and stray whitespace are dropped.
    monkeypatch.setenv("STRIX_LLM_FALLBACK", " a=b , bad , =x , y= , c=d ")
    assert LlmSettings().fallback_map() == {"a": "b", "c": "d"}
