"""The Jev System-1 verify gate: gating, asymmetric rejection, fail-open."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from strix.report import jev_verify


if TYPE_CHECKING:
    import pytest


_REPORT = {
    "id": "vuln-0001",
    "title": "SQL injection in /login",
    "description": "User parameter concatenated into the login SQL query.",
    "technical_analysis": "sqlmap confirmed a boolean-based blind injection.",
}


def _answer(choice: str, confidence: float) -> dict[str, Any]:
    return {"answers": {"verdict": {"choice": choice, "confidence": confidence}}}


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_enabled_requires_flag_and_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_VERIFY_BACKEND", raising=False)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert jev_verify.jev_enabled() is False

    monkeypatch.setenv("STRIX_VERIFY_BACKEND", "jev")
    assert jev_verify.jev_enabled() is False  # no key

    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    assert jev_verify.jev_enabled() is True


def test_confident_false_positive_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    monkeypatch.setattr(jev_verify, "_post", lambda _p: _answer("false_positive", 0.95))
    verdict = _run(jev_verify.jev_check_false_positive(_REPORT))
    assert verdict is not None
    assert verdict["is_false_positive"] is True
    assert verdict["confidence"] == 0.95


def test_low_confidence_fp_does_not_reject(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    monkeypatch.delenv("STRIX_VERIFY_MIN_CONFIDENCE", raising=False)  # default 0.7
    monkeypatch.setattr(jev_verify, "_post", lambda _p: _answer("false_positive", 0.55))
    verdict = _run(jev_verify.jev_check_false_positive(_REPORT))
    assert verdict is not None
    assert verdict["is_false_positive"] is False


def test_real_verdict_does_not_reject(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    monkeypatch.setattr(jev_verify, "_post", lambda _p: _answer("real", 0.99))
    verdict = _run(jev_verify.jev_check_false_positive(_REPORT))
    assert verdict is not None
    assert verdict["is_false_positive"] is False


def test_min_confidence_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    monkeypatch.setenv("STRIX_VERIFY_MIN_CONFIDENCE", "0.5")
    monkeypatch.setattr(jev_verify, "_post", lambda _p: _answer("false_positive", 0.55))
    verdict = _run(jev_verify.jev_check_false_positive(_REPORT))
    assert verdict is not None
    assert verdict["is_false_positive"] is True  # 0.55 >= 0.5 floor


def test_transport_error_fails_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")

    def _boom(_p: dict[str, Any]) -> dict[str, Any]:
        raise OSError("connection refused")

    monkeypatch.setattr(jev_verify, "_post", _boom)
    assert _run(jev_verify.jev_check_false_positive(_REPORT)) is None
