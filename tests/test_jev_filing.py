"""Jev filing guard: block finish only on a confident 'describes unfiled findings'.

Fail-safe toward completion — an 'all_filed' verdict, low confidence, or any error
lets the scan finish. Catches the describe-don't-file failure the regex heuristic
misses (semantic phrasing + under-filing, not just zero-filed).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from strix.report import jev_filing


if TYPE_CHECKING:
    import pytest


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _mock_post(monkeypatch: pytest.MonkeyPatch, choice: str, confidence: float) -> None:
    def fake(_payload: dict[str, Any]) -> dict[str, Any]:
        return {"answers": {"verdict": {"choice": choice, "confidence": confidence}}}

    monkeypatch.setattr(jev_filing, "_post", fake)


def test_enabled_gating(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.delenv("STRIX_FILING_GUARD", raising=False)
    assert jev_filing.jev_enabled() is False  # no key
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    assert jev_filing.jev_enabled() is True  # key, default on
    monkeypatch.setenv("STRIX_FILING_GUARD", "off")
    assert jev_filing.jev_enabled() is False  # explicitly disabled


def test_confident_unfiled_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    _mock_post(monkeypatch, "unfiled_findings", 0.9)
    v = _run(jev_filing.jev_claims_unfiled_findings("Fix the SSTI on /hello", ["XSS on /hello"]))
    assert v is not None and v["claims_unfiled"] is True


def test_all_filed_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    _mock_post(monkeypatch, "all_filed", 0.95)
    v = _run(jev_filing.jev_claims_unfiled_findings("All issues filed above", ["SSTI", "XSS"]))
    assert v is not None and v["claims_unfiled"] is False


def test_low_confidence_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    _mock_post(monkeypatch, "unfiled_findings", 0.4)  # below default 0.7 floor
    v = _run(jev_filing.jev_claims_unfiled_findings("maybe something", []))
    assert v is not None and v["claims_unfiled"] is False


def test_error_is_fail_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")

    def boom(_payload: dict[str, Any]) -> dict[str, Any]:
        raise OSError("jev down")

    monkeypatch.setattr(jev_filing, "_post", boom)
    v = _run(jev_filing.jev_claims_unfiled_findings("Fix the SSTI", []))
    assert v is None  # error -> let the scan finish


def test_empty_summary_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    assert _run(jev_filing.jev_claims_unfiled_findings("   ", [])) is None
