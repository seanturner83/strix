"""Tests for memory_compressor's narrow trap on the known Bedrock-LiteLLM
content_filtered enum mismatch.

Background: Bedrock's Converse API returns `stopReason: "content_filtered"`
when Anthropic guardrails trip. LiteLLM 1.81.x (and upstream main as of
2026-05-21) only recognises `"content_filter"` (no trailing `d`) in its
`OpenAIChatCompletionFinishReason` Literal, so the response fails Pydantic
validation. Caught in production on seedcx/strix-scan-workflow run
26204328785 (staking-controller#260 scan).
"""
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError
from typing import Literal

from strix.llm.memory_compressor import _is_known_bedrock_content_filtered_bug, _summarize_messages


# Mirror LiteLLM's Choices.finish_reason Literal so we can synthesise the
# exact ValidationError shape without depending on LiteLLM internals.
class _ChoicesFixture(BaseModel):
    finish_reason: Literal[
        "stop", "content_filter", "function_call", "tool_calls",
        "length", "guardrail_intervened", "eos",
        "finish_reason_unspecified", "malformed_function_call",
    ]


def _make_content_filtered_validation_error() -> ValidationError:
    try:
        _ChoicesFixture(finish_reason="content_filtered")  # type: ignore[arg-type]
    except ValidationError as exc:
        return exc
    raise AssertionError("expected ValidationError, didn't fire")


def _make_other_literal_error() -> ValidationError:
    try:
        _ChoicesFixture(finish_reason="wibble")  # type: ignore[arg-type]
    except ValidationError as exc:
        return exc
    raise AssertionError("expected ValidationError, didn't fire")


def test_detects_known_bedrock_content_filtered_bug() -> None:
    exc = _make_content_filtered_validation_error()
    assert _is_known_bedrock_content_filtered_bug(exc) is True


def test_does_not_swallow_unrelated_literal_errors() -> None:
    """Other finish_reason values that fail validation must NOT match —
    we only want to quiet the specific known-upstream-gap. Unknown shapes
    stay loud so new bugs surface."""
    exc = _make_other_literal_error()
    assert _is_known_bedrock_content_filtered_bug(exc) is False


def test_summarize_messages_returns_fallback_on_content_filtered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When litellm.completion raises the known ValidationError, the
    function should return messages[0] (graceful fallback) without
    re-raising."""
    def raise_content_filtered(*args: Any, **kwargs: Any) -> Any:
        raise _make_content_filtered_validation_error()

    import strix.llm.memory_compressor as mc
    monkeypatch.setattr(mc.litellm, "completion", raise_content_filtered)
    monkeypatch.setattr(
        mc, "resolve_llm_config", lambda: (None, None, None)
    )

    messages = [{"role": "user", "content": "hello"}]
    result = _summarize_messages(messages, model="bedrock/anthropic.claude-3-7-sonnet", timeout=5)
    assert result == messages[0]


def test_summarize_messages_logs_known_bug_at_info_not_exception(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The known-bug path logs a one-liner at INFO. The full
    `logger.exception` traceback path is reserved for unknown failures."""
    import logging

    def raise_content_filtered(*args: Any, **kwargs: Any) -> Any:
        raise _make_content_filtered_validation_error()

    import strix.llm.memory_compressor as mc
    monkeypatch.setattr(mc.litellm, "completion", raise_content_filtered)
    monkeypatch.setattr(
        mc, "resolve_llm_config", lambda: (None, None, None)
    )

    messages = [{"role": "user", "content": "hello"}]
    with caplog.at_level(logging.INFO, logger="strix.llm.memory_compressor"):
        _summarize_messages(messages, model="bedrock/anthropic.claude-3-7-sonnet", timeout=5)

    info_records = [r for r in caplog.records if r.levelno == logging.INFO]
    exc_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("content_filtered" in r.getMessage() for r in info_records), (
        "expected the known-bug INFO log line; got: " + repr([r.getMessage() for r in caplog.records])
    )
    assert not exc_records, (
        "known content_filtered bug must not produce ERROR-level traceback; "
        "got: " + repr([r.getMessage() for r in exc_records])
    )


def test_summarize_messages_still_loud_on_unknown_validation_error(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unrelated ValidationErrors must still produce the full traceback."""
    import logging

    def raise_other(*args: Any, **kwargs: Any) -> Any:
        raise _make_other_literal_error()

    import strix.llm.memory_compressor as mc
    monkeypatch.setattr(mc.litellm, "completion", raise_other)
    monkeypatch.setattr(
        mc, "resolve_llm_config", lambda: (None, None, None)
    )

    messages = [{"role": "user", "content": "hello"}]
    with caplog.at_level(logging.ERROR, logger="strix.llm.memory_compressor"):
        _summarize_messages(messages, model="bedrock/anthropic.claude-3-7-sonnet", timeout=5)

    err_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert err_records, "unknown ValidationError must still log at ERROR"


# --- LiteLLM-wrapped form (the actual production shape) ----------------------
# In real LiteLLM, the Pydantic ValidationError raised inside
# AmazonConverseConfig._transform_response is re-raised as
# litellm.exceptions.APIConnectionError by exception_mapping_utils.py before
# it propagates to _summarize_messages. The message is preserved verbatim.
# Tests that only synthesise bare ValidationError missed this shape — caught
# on strix-targeted-rescan run 26242905324 (cc-apps infra scan).
def _wrapped_content_filtered_exception() -> Exception:
    """Construct an exception that mirrors what LiteLLM actually raises in
    production: type = APIConnectionError-equivalent, message contains the
    ValidationError text including the literal_error + finish_reason +
    content_filtered tokens.

    We use a stand-in class rather than importing
    litellm.exceptions.APIConnectionError so the test doesn't depend on
    LiteLLM's internal exception module layout being stable.
    """
    msg = (
        "litellm.APIConnectionError: 1 validation error for Choices\n"
        "finish_reason\n"
        "  Input should be 'stop', 'content_filter', 'function_call', "
        "'tool_calls', 'length', 'guardrail_intervened', 'eos', "
        "'finish_reason_unspecified' or 'malformed_function_call' "
        "[type=literal_error, input_value='content_filtered', input_type=str]"
    )

    class _APIConnectionErrorLike(Exception):
        pass

    return _APIConnectionErrorLike(msg)


def test_detects_litellm_wrapped_content_filtered_bug() -> None:
    """The prod shape — LiteLLM wraps the ValidationError in
    APIConnectionError. Detector must recognise the signature in str(exc),
    not just on bare pydantic.ValidationError."""
    exc = _wrapped_content_filtered_exception()
    assert _is_known_bedrock_content_filtered_bug(exc) is True


def test_does_not_swallow_unrelated_api_connection_error() -> None:
    """A LiteLLM APIConnectionError without the content_filtered signature
    must NOT match — keep network / auth / rate-limit failures loud."""

    class _APIConnectionErrorLike(Exception):
        pass

    exc = _APIConnectionErrorLike("litellm.APIConnectionError: 503 Service Unavailable from upstream")
    assert _is_known_bedrock_content_filtered_bug(exc) is False


def test_summarize_messages_quiets_wrapped_content_filtered(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Regression for the production miss: when litellm.completion raises
    the wrapped APIConnectionError form, the trap must still fire and log
    at INFO, not let it fall through to the broad except's noisy traceback."""
    import logging

    def raise_wrapped(*args: Any, **kwargs: Any) -> Any:
        raise _wrapped_content_filtered_exception()

    import strix.llm.memory_compressor as mc
    monkeypatch.setattr(mc.litellm, "completion", raise_wrapped)
    monkeypatch.setattr(
        mc, "resolve_llm_config", lambda: (None, None, None)
    )

    messages = [{"role": "user", "content": "hello"}]
    with caplog.at_level(logging.INFO, logger="strix.llm.memory_compressor"):
        result = _summarize_messages(messages, model="bedrock/anthropic.claude-3-7-sonnet", timeout=5)

    assert result == messages[0]
    info_records = [r for r in caplog.records if r.levelno == logging.INFO]
    exc_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("content_filtered" in r.getMessage() for r in info_records), (
        "expected the known-bug INFO log line; got: " + repr([r.getMessage() for r in caplog.records])
    )
    assert not exc_records, (
        "wrapped content_filtered must not produce ERROR-level traceback; "
        "got: " + repr([r.getMessage() for r in exc_records])
    )
