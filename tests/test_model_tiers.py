"""Capability/cost map: default map, overrides, and policy-driven routing."""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.config import model_tiers


if TYPE_CHECKING:
    import pytest


def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_ROUTE_POLICY", raising=False)
    for tier in ("REASONING", "STANDARD", "MECHANICAL"):
        monkeypatch.delenv(f"STRIX_TIER_{tier}", raising=False)
    for var in (
        "STRIX_LOCAL_BIG_BASE", "STRIX_LOCAL_BIG_MODEL",
        "STRIX_LOCAL_SMALL_BASE", "STRIX_LOCAL_SMALL_MODEL",
    ):
        monkeypatch.delenv(var, raising=False)


def test_default_map_is_known_good_4x(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    assert model_tiers.tier_model("reasoning") == ("claude-code/claude-opus-4-8", None)
    assert model_tiers.tier_model("standard") == ("claude-code/claude-sonnet-4-6", None)
    assert model_tiers.tier_model("mechanical") == ("claude-code/claude-haiku-4-5", None)


def test_unknown_tier_falls_back_to_reasoning(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    assert model_tiers.tier_model("bogus") == model_tiers.tier_model("reasoning")


def test_override_beats_policy_and_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("STRIX_ROUTE_POLICY", "local")
    monkeypatch.setenv("STRIX_TIER_STANDARD", "openrouter/z-ai/glm-5.3")
    assert model_tiers.tier_model("standard") == ("openrouter/z-ai/glm-5.3", None)


def test_override_with_fleet_name_carries_api_base(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("STRIX_TIER_MECHANICAL", "local-small")
    assert model_tiers.tier_model("mechanical") == (
        "openai/qwen2.5-7b-instruct",
        "http://localhost:1235/v1",
    )


def test_policy_subscription_picks_cheapest_sufficient(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("STRIX_ROUTE_POLICY", "subscription")
    # standard (med) -> haiku is the cheapest subscription model that clears med
    assert model_tiers.tier_model("standard") == ("claude-code/claude-haiku-4-5", None)
    # reasoning (high) -> sonnet is cheaper than opus, both high
    assert model_tiers.tier_model("reasoning") == ("claude-code/claude-sonnet-4-6", None)


def test_policy_api_picks_cheapest_sufficient(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("STRIX_ROUTE_POLICY", "api")
    assert model_tiers.tier_model("standard") == ("anthropic/claude-haiku-4-5", None)
    assert model_tiers.tier_model("reasoning") == ("anthropic/claude-sonnet-4-6", None)


def test_policy_local_falls_back_in_regime_when_under_capable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("STRIX_ROUTE_POLICY", "local")
    # mechanical (low) -> cheapest local meeting low = local-small (or local-big; both cost 0)
    _m_model, m_base = model_tiers.tier_model("mechanical")
    assert m_base == "http://localhost:1234/v1"
    # reasoning (high): local has no high model -> stay in regime, use most capable local
    assert model_tiers.tier_model("reasoning") == (
        "openai/qwen/qwen3.8-27b",
        "http://localhost:1234/v1",
    )


def test_fleet_spans_three_regimes() -> None:
    names = set(model_tiers.fleet())
    assert {"opus", "sonnet", "haiku"} <= names  # subscription
    assert {"api-opus", "api-sonnet", "api-haiku"} <= names  # metered
    assert {"local-big", "local-small"} <= names  # local


def test_local_endpoints_are_env_overridable(monkeypatch: pytest.MonkeyPatch) -> None:
    """A LAN rig points the local tiers at itself via env, not committed source."""
    _clear(monkeypatch)
    monkeypatch.setenv("STRIX_TIER_REASONING", "local-big")
    monkeypatch.setenv("STRIX_TIER_MECHANICAL", "local-small")
    # defaults when nothing is set
    assert model_tiers.tier_model("reasoning") == (
        "openai/qwen/qwen3.8-27b", "http://localhost:1234/v1",
    )
    # env wins for base and/or model id, independently
    monkeypatch.setenv("STRIX_LOCAL_BIG_BASE", "http://192.168.0.13:1234/v1")
    monkeypatch.setenv("STRIX_LOCAL_SMALL_MODEL", "openai/llama-3.1-8b-instruct")
    assert model_tiers.tier_model("reasoning") == (
        "openai/qwen/qwen3.8-27b", "http://192.168.0.13:1234/v1",
    )
    assert model_tiers.tier_model("mechanical") == (
        "openai/llama-3.1-8b-instruct", "http://localhost:1235/v1",
    )
