"""Regression tests for LLM._should_retry's Bedrock 5xx body-marker fallback.

Background: 2026-06-12 opus-4-8 rollout surfaced a transient
`BedrockException - internalServerException` from Bedrock that LiteLLM
mis-mapped to `litellm.BadRequestError(400)`. Pre-fix, the
status-code-driven `_should_retry` returned False (400-class isn't retried
by design), so the agent died on first turn (24s, 0 vulnerabilities).

The Bedrock message body is a 5xx-class server error; retrying is the
correct behavior. SEC-6994 added a body-string check that runs BEFORE the
status-code check so the LiteLLM exception class mapping doesn't matter.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from strix.llm.llm import LLM


class _FakeException(Exception):
    """Stand-in for litellm.BadRequestError without depending on the
    LiteLLM internal exception class layout."""
    def __init__(self, msg: str, status_code: int | None = None):
        super().__init__(msg)
        self.status_code = status_code


def _llm() -> LLM:
    """Construct an LLM wrapper without actually wiring config — we only
    exercise _should_retry which is purely about the exception."""
    instance = LLM.__new__(LLM)
    instance.config = MagicMock()
    return instance


# --- Bedrock 5xx body-string mismatches that LiteLLM mis-maps to 400 ---

@pytest.mark.parametrize("marker", [
    "internalServerException",
    "ServiceUnavailableException",
    "ThrottlingException",
    "ModelTimeoutException",
    "ModelStreamErrorException",
])
def test_retries_bedrock_transient_body_markers_even_when_400(marker: str) -> None:
    """LiteLLM occasionally wraps a Bedrock 5xx as BadRequestError(400). The
    body-string check must fire BEFORE the status-code check so we retry."""
    msg = (
        f"litellm.BadRequestError: BedrockException - {marker} "
        '{"message":"The system encountered an unexpected error during '
        'processing. Try your request again."}'
    )
    exc = _FakeException(msg, status_code=400)
    assert _llm()._should_retry(exc) is True


def test_retries_internalServerException_real_production_shape() -> None:
    """Verbatim message from the 2026-06-12 tf-aws-iam-sso#154 failure
    (run 27444692392)."""
    msg = (
        "litellm.BadRequestError: BedrockException - internalServerException "
        '{"message":"The system encountered an unexpected error during '
        'processing. Try your request again."}'
    )
    exc = _FakeException(msg, status_code=400)
    assert _llm()._should_retry(exc) is True


# --- non-transient 400s must NOT be retried ----------------------------------

def test_does_not_retry_unrelated_400() -> None:
    """A genuine BadRequestError without a Bedrock-5xx marker should NOT
    retry — that's an actual client-side bug we want to surface, not a
    transient capacity issue."""
    exc = _FakeException(
        "litellm.BadRequestError: invalid model parameter `foo`", status_code=400
    )
    # Returns False because 400 is not retriable per litellm._should_retry
    # AND the body has no transient marker.
    assert _llm()._should_retry(exc) is False


def test_does_not_retry_unrelated_403() -> None:
    """403 is auth — never retry."""
    exc = _FakeException("AccessDenied: token lacks bedrock:InvokeModel", status_code=403)
    assert _llm()._should_retry(exc) is False


# --- existing behavior preserved ---------------------------------------------

def test_retries_5xx_status_code_unchanged() -> None:
    """The status-code path must still work for cases where LiteLLM DOES
    map correctly — 502/503/504 still retry."""
    for code in (502, 503, 504):
        exc = _FakeException(f"BedrockException ({code})", status_code=code)
        assert _llm()._should_retry(exc) is True, f"status {code} should retry"


def test_retries_when_status_code_is_none() -> None:
    """No status code at all → fall back to retrying. Existing semantic
    (transient network issues without HTTP shape)."""
    exc = _FakeException("connection reset")
    # No status_code attribute
    delattr(exc, "status_code") if hasattr(exc, "status_code") else None
    exc.status_code = None
    assert _llm()._should_retry(exc) is True


# --- guard: marker matching is type-narrow enough not to over-trigger -------

def test_does_not_retry_on_unrelated_text_mentioning_retry() -> None:
    """A 400 whose body mentions \"try again\" but doesn't carry a Bedrock
    5xx-class exception name must NOT retry. Markers are type-specific."""
    exc = _FakeException(
        "litellm.BadRequestError: invalid input — please try again with a different value",
        status_code=400,
    )
    assert _llm()._should_retry(exc) is False
