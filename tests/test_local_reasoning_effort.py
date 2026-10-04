"""Local tier models must pin reasoning_effort (default ``none``).

A local "thinking" model (e.g. a Qwen3 MoE) reasons on every turn unless told
``none`` explicitly — pure latency tax on a cheap routing tier. The tier-model
factory wraps local (custom api_base) models to force the effort, without
touching the global effort the cloud/frontier tiers rely on.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agents.model_settings import ModelSettings
from openai.types.shared import Reasoning

from strix.config import models


if TYPE_CHECKING:
    import pytest


def test_env_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    cases = [("", None), ("inherit", None), ("none", "none"), ("low", "low"),
             ("high", "high"), ("bogus", "none")]
    for val, expected in cases:
        monkeypatch.setenv("STRIX_LOCAL_REASONING_EFFORT", val)
        assert models._local_reasoning_effort() == expected
    monkeypatch.delenv("STRIX_LOCAL_REASONING_EFFORT", raising=False)
    assert models._local_reasoning_effort() == "none"  # default silences


def test_apply_overrides_global_effort() -> None:
    wrapper = models._ReasoningEffortModel(object(), "none")  # type: ignore[arg-type]
    out = wrapper._apply(ModelSettings(reasoning=Reasoning(effort="high")))
    assert out.reasoning is not None
    assert out.reasoning.effort == "none"


def test_factory_wraps_local_only(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = object()
    monkeypatch.setattr(models.StrixProvider, "_build_model", lambda *_a: sentinel)

    monkeypatch.setenv("STRIX_LOCAL_REASONING_EFFORT", "none")
    local = models._tier_model_factory("openai/whittle", "http://host:1234/v1")
    assert isinstance(local, models._ReasoningEffortModel)  # local -> pinned

    cloud = models._tier_model_factory("claude-code/claude-sonnet-4-6", None)
    assert cloud is sentinel  # no api_base -> untouched

    monkeypatch.setenv("STRIX_LOCAL_REASONING_EFFORT", "inherit")
    inherited: Any = models._tier_model_factory("openai/whittle", "http://host:1234/v1")
    assert inherited is sentinel  # inherit -> not wrapped even for local
