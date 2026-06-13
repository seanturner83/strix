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


# --- SEC-6994 follow-up: _is_bad_request must NOT shadow the 5xx markers ------
#
# The original SEC-6994 patch added the markers to _should_retry, but the retry
# loop checks _is_bad_request (code==400) FIRST and routes a 400 through the
# one-shot bad-request handler — so a Bedrock 5xx mis-mapped to 400 only got a
# single bare retry and never reached _should_retry's marker check. Observed
# as a cluster of single-digit-minute failures (daily-settlement weekly run
# 27454948115; jurisdiction-command#152 run 27452115581): 2 occurrences, then
# death, not the intended 8-retry budget. These pin the precedence fix.

@pytest.mark.parametrize("marker", [
    "internalServerException",
    "ServiceUnavailableException",
    "ThrottlingException",
    "ModelTimeoutException",
    "ModelStreamErrorException",
])
def test_is_bad_request_excludes_bedrock_5xx_markers(marker: str) -> None:
    """A 400-wrapped Bedrock 5xx must NOT be classified as a bad request, so
    the retry loop lets it fall through to the _should_retry marker path
    (full max_retries budget) instead of the one-shot bad-request handler."""
    msg = (
        f"litellm.BadRequestError: BedrockException - {marker} "
        '{"message":"...Try your request again."}'
    )
    exc = _FakeException(msg, status_code=400)
    assert _llm()._is_bad_request(exc) is False


def test_is_bad_request_still_true_for_genuine_400() -> None:
    """A real client-side 400 (no Bedrock-5xx marker) is still a bad request —
    we only exclude the mis-mapped transient case."""
    exc = _FakeException(
        "litellm.BadRequestError: invalid model parameter `foo`", status_code=400
    )
    assert _llm()._is_bad_request(exc) is True


def test_loop_ordering_invariant_5xx_marker_reaches_should_retry() -> None:
    """The load-bearing invariant the original fix missed: for a 400-wrapped
    Bedrock 5xx, the retry loop's _is_bad_request gate (which runs first and
    only retries once) must defer to _should_retry (which grants the full
    budget). Concretely: _is_bad_request False AND _should_retry True. If a
    future change makes _is_bad_request match these again, this fails."""
    msg = (
        "litellm.BadRequestError: BedrockException - internalServerException "
        '{"message":"The system encountered an unexpected error during '
        'processing. Try your request again."}'
    )
    exc = _FakeException(msg, status_code=400)
    llm = _llm()
    assert llm._is_bad_request(exc) is False, "must not be routed to one-shot bad-request handler"
    assert llm._should_retry(exc) is True, "must reach the full-budget retry path"


# --- SEC-6994: retry backoff floor (sustained-5xx window spanning) -----------
# Opus 4.8 throws multi-minute internalServerException windows that outlasted
# the old 8-retry / pure-exp budget (first ~6 attempts fired in ~14s). These
# pin the floored backoff so early retries span real time + the budget covers
# minutes, and guard against a revert to the unfloored curve.

def test_retry_backoff_floor_applies_to_early_attempts():
    # Pure exp would give 2,4,8 for attempts 0-2; the 15s floor lifts them.
    assert LLM._retry_backoff(0, floor_s=15) == 15
    assert LLM._retry_backoff(1, floor_s=15) == 15
    assert LLM._retry_backoff(2, floor_s=15) == 15
    # Once exp exceeds the floor it takes over: 2*2^4 = 32.
    assert LLM._retry_backoff(4, floor_s=15) == 32


def test_retry_backoff_caps_at_120():
    # 2*2^6 = 128 -> capped to 120; high attempts stay capped.
    assert LLM._retry_backoff(6, floor_s=15) == 120
    assert LLM._retry_backoff(20, floor_s=15) == 120


def test_retry_backoff_floor_zero_is_pure_exp():
    # floor=0 (env override) reverts to the original exponential curve.
    assert LLM._retry_backoff(0, floor_s=0) == 2
    assert LLM._retry_backoff(2, floor_s=0) == 8


def test_retry_budget_spans_minutes_not_seconds():
    # The load-bearing invariant: 12 retries with the 15s floor must cumulate
    # to >10min so a sustained Bedrock window is actually ridden out — the old
    # 8/pure-exp budget front-loaded into ~14s + a couple of 120s tails.
    total = sum(LLM._retry_backoff(a, floor_s=15) for a in range(12))
    assert total > 600, f"cumulative backoff {total}s too short to span a sustained outage"
    # And the first 4 attempts must NOT all fire inside 60s (the old failure).
    first4 = sum(LLM._retry_backoff(a, floor_s=15) for a in range(4))
    assert first4 >= 45, f"early retries still bunched ({first4}s) — won't span a minute-scale window"
