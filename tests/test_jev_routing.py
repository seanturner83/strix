"""Jev routing tier classification and the confidence floor."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from strix.config import jev_routing


if TYPE_CHECKING:
    import pytest


def _answer(choice: str, confidence: float) -> dict[str, Any]:
    return {"answers": {"tier": {"choice": choice, "confidence": confidence}}}


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _classify(monkeypatch: pytest.MonkeyPatch, choice: str, conf: float, floor: str | None) -> Any:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    if floor is None:
        monkeypatch.delenv("STRIX_ROUTING_MIN_CONFIDENCE", raising=False)
    else:
        monkeypatch.setenv("STRIX_ROUTING_MIN_CONFIDENCE", floor)
    monkeypatch.setattr(jev_routing, "post", lambda _p, _t=None: _answer(choice, conf))
    return _run(jev_routing.jev_classify_tier({"last_tool": "exec_command"}))


def test_no_key_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert _run(jev_routing.jev_classify_tier({})) is None


def test_default_floor_trusts_the_pick(monkeypatch: pytest.MonkeyPatch) -> None:
    tier, _ = _classify(monkeypatch, "standard", 0.31, floor=None)  # default 0.0
    assert tier == "standard"


def test_low_confidence_routes_to_safe_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    tier, reason = _classify(monkeypatch, "standard", 0.4, floor="0.7")
    assert tier == "reasoning"  # downgrade refused under the floor
    assert "floor" in reason


def test_confident_pick_clears_the_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    tier, _ = _classify(monkeypatch, "mechanical", 0.85, floor="0.7")
    assert tier == "mechanical"


def test_unknown_choice_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _classify(monkeypatch, "gibberish", 0.99, floor=None) is None
