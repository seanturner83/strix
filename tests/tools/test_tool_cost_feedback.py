"""Tests for the per-call tool-cost feedback annotation (SEC-???? spike).

The feature appends an approximate context-token cost to each tool result so
the agent can price its tool choices. It is DEFAULT OFF and gated on
`strix_tool_cost_feedback`; these tests pin both the off (inert) and on
behaviour, the token math, and — critically — that the annotation does NOT
break the history-truncation regex that controls long-scan context growth.
"""

from __future__ import annotations

import pytest  # noqa: TC002 — used as a runtime annotation (pytest.MonkeyPatch)

from strix.llm.llm import _TOOL_RESULT_PATTERN
from strix.tools import executor
from strix.tools.executor import _cost_feedback_line, _format_tool_result


# ---------------------------------------------------------------------------
# Default OFF: no annotation, observation unchanged
# ---------------------------------------------------------------------------


def test_cost_feedback_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_TOOL_COST_FEEDBACK", False)
    xml, _ = _format_tool_result("search_files", "some result body")
    assert "<cost>" not in xml
    assert xml.endswith("</tool_result>")


def test_cost_feedback_line_empty_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_TOOL_COST_FEEDBACK", False)
    assert _cost_feedback_line("x" * 1000) == ""


# ---------------------------------------------------------------------------
# Enabled: annotation present, sits OUTSIDE the wrapper, token math sane
# ---------------------------------------------------------------------------


def test_cost_feedback_appended_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_TOOL_COST_FEEDBACK", True)
    body = "x" * 400  # ~100 tokens at 4 chars/token
    xml, _ = _format_tool_result("batch_view_files", body)
    assert "<cost>~100 tokens added to context by this result</cost>" in xml
    # The cost annotation must sit AFTER the closing </tool_result> so it
    # cannot break the truncation regex (see regression test below).
    assert xml.index("</tool_result>") < xml.index("<cost>")


def test_cost_reflects_pre_truncation_size(monkeypatch: pytest.MonkeyPatch) -> None:
    # A >10k result is display-truncated to ~8k, but the cost must report the
    # FULL size the agent is actually charged for in context.
    monkeypatch.setattr(executor, "_TOOL_COST_FEEDBACK", True)
    body = "y" * 40000  # ~10000 tokens
    xml, _ = _format_tool_result("batch_view_files", body)
    assert "... [middle content truncated] ..." in xml  # display truncated
    assert "<cost>~10000 tokens added to context by this result</cost>" in xml


def test_none_result_has_no_misleading_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_TOOL_COST_FEEDBACK", True)
    xml, _ = _format_tool_result("agent_finish", None)
    # cost_basis is "" for a None result -> ~0 tokens, not a fabricated number
    assert "<cost>~0 tokens added to context by this result</cost>" in xml


# ---------------------------------------------------------------------------
# Regression: the truncation regex must STILL match a cost-annotated result.
# A cost-feedback feature must not silently defeat history-truncation (cost
# control). This is the bug avoided by placing <cost> outside </tool_result>.
# ---------------------------------------------------------------------------


def test_annotation_does_not_break_truncation_regex(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_TOOL_COST_FEEDBACK", True)
    xml, _ = _format_tool_result("search_files", "z" * 500)
    m = _TOOL_RESULT_PATTERN.search(xml)
    assert m is not None, "cost annotation broke the tool-result truncation regex"
    # The captured body is the result content, not the cost tag.
    assert "z" * 500 in m.group(2)
    assert "<cost>" not in m.group(2)


def test_truncation_regex_still_matches_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(executor, "_TOOL_COST_FEEDBACK", False)
    xml, _ = _format_tool_result("search_files", "z" * 500)
    assert _TOOL_RESULT_PATTERN.search(xml) is not None
