"""The Jev System-1 dedup backend: gating, mapping, and fail-safe fallback."""

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
_CANDIDATE = {"id": "vuln-0003", "title": "Auth bypass via SQLi at login", "endpoint": "/login"}


def _answer(choice: str, confidence: float = 0.9) -> dict[str, Any]:
    return {"answers": {"duplicate_of": {"choice": choice, "confidence": confidence}}}


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


def test_maps_choice_to_duplicate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    monkeypatch.setattr(jev_dedupe, "_post", lambda _payload: _answer("vuln-0001", 0.92))

    result = _run(jev_dedupe.jev_check_duplicate(_CANDIDATE, _EXISTING))
    assert result == {
        "is_duplicate": True,
        "duplicate_id": "vuln-0001",
        "confidence": 0.92,
        "reason": "Jev matched the candidate to vuln-0001",
    }


def test_none_choice_is_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    monkeypatch.setattr(jev_dedupe, "_post", lambda _payload: _answer("none", 0.88))

    result = _run(jev_dedupe.jev_check_duplicate(_CANDIDATE, _EXISTING))
    assert result is not None
    assert result["is_duplicate"] is False
    assert result["duplicate_id"] == ""


def test_unknown_choice_is_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    """A label Jev returns that isn't a known id must not be treated as a match."""
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    monkeypatch.setattr(jev_dedupe, "_post", lambda _payload: _answer("vuln-9999"))

    result = _run(jev_dedupe.jev_check_duplicate(_CANDIDATE, _EXISTING))
    assert result is not None
    assert result["is_duplicate"] is False


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
