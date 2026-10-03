"""The Jev System-1 dedup backend: gating, binary framing, and fail-safe floor."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from strix.report import jev_dedupe


if TYPE_CHECKING:
    import pytest


_EXISTING = [
    {"id": "vuln-0001", "title": "SQL injection in /login", "endpoint": "/login"},
    {"id": "vuln-0002", "title": "Reflected XSS in /hello", "endpoint": "/hello"},
]
# Lexically closest to vuln-0001 (SQLi at /login), far from the XSS report.
_CANDIDATE = {"id": "vuln-0003", "title": "Auth bypass via SQLi at login", "endpoint": "/login"}


def _answer(choice: str, confidence: float = 0.9) -> dict[str, Any]:
    return {"answers": {"is_duplicate": {"choice": choice, "confidence": confidence}}}


def test_jev_enabled_requires_flag_and_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_DEDUPE_BACKEND", raising=False)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert jev_dedupe.jev_enabled() is False

    monkeypatch.setenv("STRIX_DEDUPE_BACKEND", "jev")
    assert jev_dedupe.jev_enabled() is False  # no key

    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    assert jev_dedupe.jev_enabled() is True

    monkeypatch.setenv("STRIX_DEDUPE_BACKEND", "llm")
    assert jev_dedupe.jev_enabled() is False  # wrong backend


def test_nearest_report_is_the_lexically_closest() -> None:
    assert jev_dedupe._nearest_report(_CANDIDATE, _EXISTING)["id"] == "vuln-0001"


def test_confident_duplicate_merges_into_nearest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_DEDUPE_MIN_CONFIDENCE", raising=False)
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    monkeypatch.setattr(jev_dedupe, "_post", lambda _p: _answer("duplicate", 0.92))

    result = _run(jev_dedupe.jev_check_duplicate(_CANDIDATE, _EXISTING))
    assert result["is_duplicate"] is True
    assert result["duplicate_id"] == "vuln-0001"  # the nearest report
    assert result["confidence"] == 0.92


def test_distinct_keeps_the_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    monkeypatch.setattr(jev_dedupe, "_post", lambda _p: _answer("distinct", 0.88))

    result = _run(jev_dedupe.jev_check_duplicate(_CANDIDATE, _EXISTING))
    assert result["is_duplicate"] is False
    assert result["duplicate_id"] == ""


def test_low_confidence_duplicate_fails_safe_to_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    """The coverage-preserving fix: a shaky 'duplicate' must NOT merge (keep the finding)."""
    monkeypatch.delenv("STRIX_DEDUPE_MIN_CONFIDENCE", raising=False)  # default floor 0.7
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    monkeypatch.setattr(jev_dedupe, "_post", lambda _p: _answer("duplicate", 0.5))

    result = _run(jev_dedupe.jev_check_duplicate(_CANDIDATE, _EXISTING))
    assert result["is_duplicate"] is False  # below floor -> keep distinct
    assert result["duplicate_id"] == ""


def test_floor_is_env_tunable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    monkeypatch.setenv("STRIX_DEDUPE_MIN_CONFIDENCE", "0.4")  # lower the bar
    monkeypatch.setattr(jev_dedupe, "_post", lambda _p: _answer("duplicate", 0.5))

    result = _run(jev_dedupe.jev_check_duplicate(_CANDIDATE, _EXISTING))
    assert result["is_duplicate"] is True  # 0.5 now clears the 0.4 floor


def test_transport_error_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")

    def _boom(_payload: dict[str, Any]) -> dict[str, Any]:
        raise OSError("connection refused")

    monkeypatch.setattr(jev_dedupe, "_post", _boom)
    assert _run(jev_dedupe.jev_check_duplicate(_CANDIDATE, _EXISTING)) is None


def test_no_existing_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    assert _run(jev_dedupe.jev_check_duplicate(_CANDIDATE, [])) is None


def _run(coro: Any) -> Any:
    return asyncio.run(coro)
