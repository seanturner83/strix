"""SEC-7400: warm_up_llm()'s connectivity probe must retry transient 5xx.

Regression for the fleet flake where warm_up_llm()'s single bare
model.get_response() died on the first transient Bedrock 5xx and exited 1
BEFORE the runtime retry budget (DEFAULT_MODEL_RETRY / run_agent_loop) could
engage (protoc-lint-data-classification#4, 2026-08-13: LLM CONNECTION FAILED,
13.8s, iteration 1, no run dir; a re-dispatch of the same sha cleared it).

_warm_up_probe now retries with the SAME transient classifier + backoff the
runtime loop uses (strix.core.execution._is_transient_model_error /
_transient_model_retry_delay), so a startup blip rides out while a real
config/auth error still fails fast.

warm_up_llm lives in strix.interface.main, whose import chain is heavy and pulls
private deps. We compile JUST _warm_up_probe from the source file against a
namespace whose strix.core.execution symbols are the REAL ones (imported lazily
inside the function), so the retry semantics under test match production.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest
from openai import APIStatusError

from strix.core.execution import (
    _MAX_TRANSIENT_MODEL_RETRIES,
    _is_transient_model_error,
)


def _status_error(code: int) -> APIStatusError:
    """A real openai.APIStatusError so _is_transient_model_error classifies it
    exactly as it would a live Bedrock 5xx (via litellm → openai-agents)."""
    request = httpx.Request("POST", "http://model.invalid")
    response = httpx.Response(code, request=request)
    return APIStatusError(f"HTTP {code}", response=response, body=None)


def _load_warm_up_probe() -> Any:
    """Extract _warm_up_probe from main.py without importing the whole module."""
    src = Path(__file__).resolve().parents[2] / "strix" / "interface" / "main.py"
    tree = ast.parse(src.read_text())
    picked = [
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_warm_up_probe"
    ]
    assert len(picked) == 1, "_warm_up_probe not found in main.py"

    # Stub the module-level names _warm_up_probe closes over. ModelTracing is only
    # referenced as an argument value, so a sentinel is fine; asyncio is real.
    module = ast.Module(body=picked, type_ignores=[])
    ns: dict[str, Any] = {
        "asyncio": asyncio,
        "Any": Any,
        "logger": _NullLogger(),
        "ModelTracing": type("ModelTracing", (), {"DISABLED": object()}),
    }
    exec(compile(module, str(src), "exec"), ns)  # noqa: S102
    return ns["_warm_up_probe"]


class _NullLogger:
    def warning(self, *a: Any, **k: Any) -> None:  # noqa: D102
        pass


class _FakeModel:
    """Model stub whose get_response raises a scripted sequence then succeeds."""

    def __init__(self, errors: list[Exception]) -> None:
        self._errors = errors
        self.calls = 0

    async def get_response(self, **_kw: Any) -> str:  # noqa: D102
        idx = self.calls
        self.calls += 1
        if idx < len(self._errors):
            raise self._errors[idx]
        return "OK"


@pytest.fixture(autouse=True)
def _fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    # Neutralise the real backoff sleeps so the retry tests are instant.
    import strix.core.execution as ex

    monkeypatch.setattr(ex, "_transient_model_retry_delay", lambda _attempt: 0.0)


def _assert_transient_precondition() -> None:
    # Guard the tests' premise: a 503 must be classified transient by the shared
    # classifier, else the retry-then-succeed test would prove nothing.
    assert _is_transient_model_error(_status_error(503)) is True
    assert _is_transient_model_error(_status_error(400)) is False


def test_probe_retries_transient_then_succeeds() -> None:
    _assert_transient_precondition()
    probe = _load_warm_up_probe()
    model = _FakeModel([_status_error(503), _status_error(503)])
    asyncio.run(probe(model, object(), timeout=5))
    assert model.calls == 3, "should retry twice then succeed"


def test_probe_does_not_retry_non_transient() -> None:
    probe = _load_warm_up_probe()
    model = _FakeModel([_status_error(400)])  # bad request — real error
    with pytest.raises(APIStatusError):
        asyncio.run(probe(model, object(), timeout=5))
    assert model.calls == 1, "a non-transient error must NOT be retried"


def test_probe_exhausts_budget_then_raises() -> None:
    probe = _load_warm_up_probe()
    # Always-503: budget is _MAX_TRANSIENT_MODEL_RETRIES retries after the first
    # attempt = _MAX_TRANSIENT_MODEL_RETRIES + 1 total calls, then re-raise
    # (warm_up_llm's own except turns that into sys.exit(1)).
    model = _FakeModel([_status_error(503)] * 100)
    with pytest.raises(APIStatusError):
        asyncio.run(probe(model, object(), timeout=5))
    assert model.calls == _MAX_TRANSIENT_MODEL_RETRIES + 1


def test_probe_retries_asyncio_timeout() -> None:
    probe = _load_warm_up_probe()

    class _SlowModel:
        def __init__(self) -> None:
            self.calls = 0

        async def get_response(self, **_kw: Any) -> str:
            self.calls += 1
            if self.calls == 1:
                raise asyncio.TimeoutError
            return "OK"

    model = _SlowModel()
    asyncio.run(probe(model, object(), timeout=0.01))
    assert model.calls == 2, "an outer wait_for timeout should be retried once"
