"""Tests for prompt-cache TTL flow-through across both cache breakpoints.

Bug history: ``LLM._add_cache_control`` resolves the right cache-control
object via ``_cache_control()`` (5m default, 1h on long-budget scans or
``STRIX_CACHE_TTL=1h``) and applies it to the system-prompt breakpoint.
Earlier versions hardcoded ``{"type": "ephemeral"}`` on the second
breakpoint (the ``<agent_identity>`` user message), which silently fell
back to the 5-minute default. This pinned the 1h-TTL extension applied
to the system prompt while the agent-identity segment expired every 5
minutes and forced a re-cache at full input rate plus the cache-write
premium on long scans. Test pins the invariant that both breakpoints
carry the same cache_control object.
"""

from unittest.mock import patch

import pytest

from strix.llm.config import LLMConfig
from strix.llm.llm import LLM


_AGENT_IDENTITY = (
    "<agent_identity>\nname=root_agent\nid=test-agent-id\n</agent_identity>\n"
)


@pytest.fixture(autouse=True)
def _clear_cache_ttl_env(monkeypatch):
    monkeypatch.delenv("STRIX_CACHE_TTL", raising=False)


def _build_llm(monkeypatch, *, max_iterations: int | None = None) -> LLM:
    """Build an LLM whose canonical_model claims to support prompt caching."""
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-opus-4-7")
    cfg = LLMConfig(enable_prompt_caching=True)
    return LLM(cfg, agent_name="root_agent", max_iterations=max_iterations)


def _add_cache_control_supported(llm: LLM, messages: list) -> list:
    """Force ``supports_prompt_caching`` to True so the function does work
    regardless of the local litellm cost-map state for the test model."""
    with patch("strix.llm.llm.supports_prompt_caching", return_value=True):
        return llm._add_cache_control(messages)


def _system_breakpoint(messages: list) -> dict:
    return messages[0]["content"][0]["cache_control"]


def _identity_breakpoint(messages: list) -> dict:
    content = messages[1]["content"]
    if isinstance(content, list):
        return content[-1]["cache_control"]
    raise AssertionError(
        f"agent-identity breakpoint did not become a list-content block: {content!r}"
    )


def test_default_5m_ttl_on_both_breakpoints(monkeypatch):
    """No env override + short scan → both breakpoints use the bare 5m default."""
    llm = _build_llm(monkeypatch, max_iterations=5)
    out = _add_cache_control_supported(
        llm,
        [
            {"role": "system", "content": "SYSTEM"},
            {"role": "user", "content": _AGENT_IDENTITY},
        ],
    )
    assert _system_breakpoint(out) == {"type": "ephemeral"}
    assert _identity_breakpoint(out) == {"type": "ephemeral"}


def test_explicit_1h_override_flows_to_both_breakpoints(monkeypatch):
    """``STRIX_CACHE_TTL=1h`` must apply to BOTH cache breakpoints — the bug
    was that the agent-identity breakpoint silently kept the 5m default."""
    monkeypatch.setenv("STRIX_CACHE_TTL", "1h")
    llm = _build_llm(monkeypatch, max_iterations=5)
    out = _add_cache_control_supported(
        llm,
        [
            {"role": "system", "content": "SYSTEM"},
            {"role": "user", "content": _AGENT_IDENTITY},
        ],
    )
    assert _system_breakpoint(out) == {"type": "ephemeral", "ttl": "1h"}
    assert _identity_breakpoint(out) == {
        "type": "ephemeral",
        "ttl": "1h",
    }, (
        "agent-identity breakpoint must inherit the resolved TTL — "
        "regression: hardcoded 5m default leaked back in"
    )


def test_long_scan_threshold_elects_1h_on_both_breakpoints(monkeypatch):
    """``max_iterations >= _CACHE_TTL_1H_THRESHOLD`` elects 1h without env
    override — both breakpoints must see it."""
    threshold = LLM._CACHE_TTL_1H_THRESHOLD
    llm = _build_llm(monkeypatch, max_iterations=threshold)
    out = _add_cache_control_supported(
        llm,
        [
            {"role": "system", "content": "SYSTEM"},
            {"role": "user", "content": _AGENT_IDENTITY},
        ],
    )
    assert _system_breakpoint(out) == {"type": "ephemeral", "ttl": "1h"}
    assert _identity_breakpoint(out) == {"type": "ephemeral", "ttl": "1h"}


def test_explicit_5m_override_pins_5m_on_both_breakpoints(monkeypatch):
    """``STRIX_CACHE_TTL=5m`` must override the long-scan-threshold path."""
    monkeypatch.setenv("STRIX_CACHE_TTL", "5m")
    llm = _build_llm(
        monkeypatch, max_iterations=LLM._CACHE_TTL_1H_THRESHOLD * 2
    )
    out = _add_cache_control_supported(
        llm,
        [
            {"role": "system", "content": "SYSTEM"},
            {"role": "user", "content": _AGENT_IDENTITY},
        ],
    )
    assert _system_breakpoint(out) == {"type": "ephemeral"}
    assert _identity_breakpoint(out) == {"type": "ephemeral"}


def test_list_content_branch_also_inherits_ttl(monkeypatch):
    """The agent-identity branch has TWO code paths: the str-content path
    upgrades to a list, and the list-content path mutates the last block.
    The bug was present in both — pin the list-content path too."""
    monkeypatch.setenv("STRIX_CACHE_TTL", "1h")
    llm = _build_llm(monkeypatch)
    out = _add_cache_control_supported(
        llm,
        [
            {"role": "system", "content": "SYSTEM"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "preamble"},
                    {"type": "text", "text": _AGENT_IDENTITY},
                ],
            },
        ],
    )
    # The last content block of the agent-identity message is what actually
    # carries the cache_control breakpoint in the list-content branch.
    assert out[1]["content"][-1]["cache_control"] == {
        "type": "ephemeral",
        "ttl": "1h",
    }
    # And the FIRST content block of the same message must NOT have been
    # mutated — only the trailing block is the breakpoint.
    assert "cache_control" not in out[1]["content"][0]


# ---------------------------------------------------------------------------
# Cohort-routing boundary (SEC-7045): the TTL must split PR/diff scans (5m)
# from full-scope scans (1h) via max_iterations as a scope proxy. These pin
# the ACTUAL routing at concrete cap values from the real curves, so the
# split is asserted independent of the exact threshold constant — the prior
# tests used threshold-relative values (threshold, threshold*2) and would
# pass at ANY threshold, missing a misalignment with the dispatch caps.
#
# Real caps (strix-pr-dispatch resolve_turn_cap, verified 2026-06-21):
#   PR app curve:  clamp(10,40, 5+5*files) -> 10,15,20,25,30,35,40 ceiling
#   PR infra curve: clamp(8,30, 4+4*files) -> 8,12,16,20,24,28,30 ceiling
#   Full-scope (weekly/infra/targeted/advisory/DAST): NO cap set -> CLI default 100
# Invariant: PR is the ONLY caller that sets a cap (<=40); full = 100.
# ---------------------------------------------------------------------------

def _ttl(monkeypatch, cap):
    return _build_llm(monkeypatch, max_iterations=cap)._cache_control().get("ttl", "5m")


@pytest.mark.parametrize("cap", [8, 10, 12, 15, 16, 20, 24, 25, 28, 30, 35])
def test_pr_cohort_caps_get_5m(monkeypatch, cap):
    """Typical PR/diff scans (cap well under the 40 ceiling) must get 5m —
    they run short + dense (median ~8 turns, turns every ~38s) and never
    leave the cached preamble untouched >5min, so 1h would only burn the
    cache-write premium."""
    assert _ttl(monkeypatch, cap) == "5m", (
        f"PR-cohort cap={cap} should route to 5m at threshold "
        f"{LLM._CACHE_TTL_1H_THRESHOLD}"
    )


def test_full_scope_default_cap_gets_1h(monkeypatch):
    """Full-scope scans set no STRIX_MAX_ITERATIONS -> CLI default 100 ->
    must get 1h (median 68 turns, ~49min span, 66% have a >5min gap)."""
    assert _ttl(monkeypatch, 100) == "1h"


def test_pr_app_ceiling_boundary(monkeypatch):
    """The 40-file-ceiling app PR sits exactly on the threshold. Gate is
    `>=`, so a max-size 7+-file app PR (cap 40) currently elects 1h — a
    small, genuinely-large slice that plausibly runs long enough to want it.
    Pin the boundary so a future threshold/curve change is a conscious one."""
    assert _ttl(monkeypatch, 39) == "5m"   # just under ceiling -> 5m
    assert _ttl(monkeypatch, 40) == "1h"   # at ceiling -> 1h (>= gate)


def test_no_cap_defaults_5m(monkeypatch):
    """max_iterations=None (not passed) must not crash and must default 5m
    (the `self.max_iterations and ...` guard)."""
    assert _ttl(monkeypatch, None) == "5m"
