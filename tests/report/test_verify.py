"""In-scan verify-before-emit pass tests.

Load-bearing behaviours (the whole point is a SAFE FP reducer):
  1. OFF by default — never fires unless STRIX_VERIFY=1.
  2. Fail-open everywhere — REAL / uncertain / unparseable / error / no-model /
     below-min-severity all EMIT (return None). Only a confident FALSE_POSITIVE
     rejects. A verifier miss must never suppress a real finding.
  3. Severity gating — only high/critical by default.
  4. Confidence floor — a low-confidence FALSE_POSITIVE does NOT reject.
"""

from __future__ import annotations

import pytest

from strix.config import loader
from strix.report import verify as v
from strix.report.verify import _meets_min_severity, _parse_verify_response, verify_finding


@pytest.fixture(autouse=True)
def _reset_settings_cache():
    """load_settings() memoises into loader._cached, so env changes made with
    monkeypatch.setenv don't take effect unless the cache is cleared. Reset
    before AND after each test so verify_finding re-reads the patched env."""
    loader._cached = None
    yield
    loader._cached = None


def _candidate(title="OS Command Injection in /ping"):
    return {
        "title": title,
        "description": "user input reaches subprocess with shell=True",
        "impact": "RCE",
        "target": "app.py",
        "technical_analysis": "host param -> check_output(..., shell=True)",
        "poc_description": "?host=;id",
        "poc_script_code": "curl 'http://t/ping?host=;id'",
    }


# ---- pure logic ----

def test_parse_fenced_json():
    out = _parse_verify_response(
        '```json\n{"verdict":"FALSE_POSITIVE","confidence":0.9,"reason":"allowlist covers it"}\n```'
    )
    assert out == {"verdict": "FALSE_POSITIVE", "confidence": 0.9, "reason": "allowlist covers it"}


def test_parse_garbage_fails_open_to_real():
    out = _parse_verify_response("the model just rambled with no json")
    assert out["verdict"] == "REAL"  # fail-open
    assert out["confidence"] == 0.0


def test_parse_unknown_verdict_coerced_to_real():
    out = _parse_verify_response('{"verdict":"MAYBE","confidence":0.8}')
    assert out["verdict"] == "REAL"


def test_parse_confidence_clamped():
    assert _parse_verify_response('{"verdict":"REAL","confidence":5}')["confidence"] == 1.0
    assert _parse_verify_response('{"verdict":"REAL","confidence":-2}')["confidence"] == 0.0


def test_severity_gating():
    assert _meets_min_severity("critical", "high")
    assert _meets_min_severity("high", "high")
    assert not _meets_min_severity("medium", "high")
    assert not _meets_min_severity("low", "high")
    assert _meets_min_severity("medium", "medium")


# ---- verify_finding: disabled / gating (no LLM call) ----

async def test_disabled_by_default_emits(monkeypatch):
    monkeypatch.delenv("STRIX_VERIFY", raising=False)
    # even if a model would flag it, disabled => None (emit)
    assert await verify_finding(_candidate(), "critical") is None


async def test_below_min_severity_emits(monkeypatch):
    monkeypatch.setenv("STRIX_VERIFY", "1")
    monkeypatch.setenv("STRIX_VERIFY_MODEL", "bedrock/x")
    # medium < high default -> skip, emit (and never calls the model)
    called = {"model": False}
    monkeypatch.setattr(v, "StrixProvider", lambda: (_ for _ in ()).throw(AssertionError("model called")))
    assert await verify_finding(_candidate(), "medium") is None
    assert called["model"] is False


async def test_no_model_configured_emits(monkeypatch):
    monkeypatch.setenv("STRIX_VERIFY", "1")
    monkeypatch.delenv("STRIX_VERIFY_MODEL", raising=False)
    monkeypatch.delenv("STRIX_LLM_DEDUP", raising=False)
    monkeypatch.delenv("STRIX_LLM", raising=False)
    assert await verify_finding(_candidate(), "critical") is None


# ---- verify_finding: verdict handling (stub the model) ----

class _FakeResponse:
    def __init__(self, text):
        self._text = text
        self.usage = None


def _stub_model(monkeypatch, response_text):
    """Make StrixProvider().get_model(...).get_response(...) return response_text,
    and _extract_text pull it out. Also neutralise usage recording + settings."""
    class _Model:
        async def get_response(self, **kwargs):
            return _FakeResponse(response_text)

    class _Provider:
        def get_model(self, name):
            return _Model()

    monkeypatch.setenv("STRIX_VERIFY", "1")
    monkeypatch.setenv("STRIX_VERIFY_MODEL", "bedrock/converse/test")
    monkeypatch.setattr(v, "StrixProvider", _Provider)
    monkeypatch.setattr(v, "configure_sdk_model_defaults", lambda s: None)
    monkeypatch.setattr(v, "_extract_text", lambda r: r._text)
    monkeypatch.setattr(v, "get_global_report_state", lambda: None)


async def test_confident_false_positive_rejects(monkeypatch):
    _stub_model(monkeypatch,
                '{"verdict":"FALSE_POSITIVE","confidence":0.95,"reason":"host is IP-validated before the call"}')
    out = await verify_finding(_candidate(), "critical")
    assert out is not None
    assert out["success"] is False
    assert out["verify_rejected"] is True
    assert "FALSE POSITIVE" in out["error"]


async def test_real_verdict_emits(monkeypatch):
    _stub_model(monkeypatch,
                '{"verdict":"REAL","confidence":0.9,"reason":"shell=True with raw host, no validation"}')
    assert await verify_finding(_candidate(), "critical") is None


async def test_low_confidence_false_positive_does_not_reject(monkeypatch):
    # FALSE_POSITIVE but below the 0.7 floor -> hold on doubt, emit.
    _stub_model(monkeypatch,
                '{"verdict":"FALSE_POSITIVE","confidence":0.4,"reason":"maybe validated, unsure"}')
    assert await verify_finding(_candidate(), "critical") is None


async def test_unparseable_response_emits(monkeypatch):
    _stub_model(monkeypatch, "I could not decide")
    assert await verify_finding(_candidate(), "critical") is None


async def test_model_error_fails_open_emits(monkeypatch):
    class _Boom:
        def get_model(self, name):
            raise RuntimeError("bedrock 500")
    monkeypatch.setenv("STRIX_VERIFY", "1")
    monkeypatch.setenv("STRIX_VERIFY_MODEL", "bedrock/converse/test")
    monkeypatch.setattr(v, "StrixProvider", _Boom)
    monkeypatch.setattr(v, "configure_sdk_model_defaults", lambda s: None)
    assert await verify_finding(_candidate(), "critical") is None
