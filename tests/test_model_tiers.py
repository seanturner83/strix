"""Capability-tier → model resolution and overrides."""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.config import model_tiers


if TYPE_CHECKING:
    import pytest


def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    for tier in ("REASONING", "STANDARD", "MECHANICAL"):
        monkeypatch.delenv(f"STRIX_TIER_{tier}", raising=False)


def test_default_map_is_known_good_4x(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    assert model_tiers.tier_model("reasoning") == ("claude-code/claude-opus-4-8", None)
    assert model_tiers.tier_model("standard") == ("claude-code/claude-sonnet-4-6", None)
    assert model_tiers.tier_model("mechanical") == ("claude-code/claude-haiku-4-5", None)


def test_unknown_tier_falls_back_to_reasoning(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    assert model_tiers.tier_model("bogus") == model_tiers.tier_model("reasoning")


def test_override_with_fleet_name_carries_api_base(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("STRIX_TIER_MECHANICAL", "local-small")
    model_id, api_base = model_tiers.tier_model("mechanical")
    assert model_id == "minicpm5-1b"
    assert api_base == "http://localhost:1234/v1"


def test_override_with_raw_model_id(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("STRIX_TIER_STANDARD", "openrouter/z-ai/glm-5.3")
    assert model_tiers.tier_model("standard") == ("openrouter/z-ai/glm-5.3", None)


def test_fleet_lists_the_five_known_good() -> None:
    names = set(model_tiers.fleet())
    assert names == {"opus", "sonnet", "haiku", "local-big", "local-small"}
