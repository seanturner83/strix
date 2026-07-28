"""Regression test for the Bedrock tool-call repair patch.

Reproduces the live failure (2026-07-28, zh-global-infrastructure#16539): a
``finish_scan`` tool call whose ``arguments`` JSON was truncated at the model's
output ceiling (cut mid-first-field, no closing brace, 3 required fields
missing) crashed the whole run when litellm re-serialized message history to
Bedrock. The patch degrades the truncated tool call to empty-args instead of
raising.
"""

from __future__ import annotations

import pytest

from strix.config import litellm_bedrock_toolcall_repair_patch as repair
from strix.config.litellm_bedrock_toolcall_repair_patch import _sanitize_tool_calls


factory = pytest.importorskip("litellm.litellm_core_utils.prompt_templates.factory")


# The exact shape that crashed: valid opening, one field, then cut off — no
# closing brace, no other fields. ``json.loads`` raises "Expecting ',' delimiter".
_TRUNCATED_ARGS = (
    '{"executive_summary": "# Executive Summary\\n\\nThis session re-validated '
    "the prior finding. The outstanding default-credential weakness on the "
    "trading control plane remains the priority remediation item; the new "
    'infrastructure is well-secured."'
)


def _tool_call(arguments: str) -> list:
    return [
        {
            "id": "tooluse_test123",
            "type": "function",
            "function": {"name": "finish_scan", "arguments": arguments},
        }
    ]


def test_truncated_toolcall_crashes_unpatched_but_survives_patched() -> None:
    repair._PATCHED[0] = False  # order-independent: reach past the import-once guard
    original = factory._convert_to_bedrock_tool_call_invoke
    calls = _tool_call(_TRUNCATED_ARGS)

    # Baseline: the raw litellm converter raises on truncated arguments.
    with pytest.raises(Exception):  # noqa: B017 — litellm raises a bare Exception
        original(calls)

    try:
        repair.apply()
        blocks = factory._convert_to_bedrock_tool_call_invoke(calls)
        assert len(blocks) == 1
        block = blocks[0]
        tool_use = block["toolUse"] if isinstance(block, dict) else block.toolUse
        # Truncated args blanked to {}, but name + id preserved so the message
        # is still a coherent, replayable tool-use block.
        assert tool_use["input"] == {}
        assert tool_use["name"] == "finish_scan"
        assert tool_use["toolUseId"] == "tooluse_test123"
    finally:
        factory._convert_to_bedrock_tool_call_invoke = original
        repair._PATCHED[0] = False


def test_valid_toolcall_passes_through_untouched() -> None:
    repair._PATCHED[0] = False
    original = factory._convert_to_bedrock_tool_call_invoke
    valid = _tool_call(
        '{"executive_summary": "ok", "methodology": "m", '
        '"technical_analysis": "t", "recommendations": "r"}'
    )
    try:
        repair.apply()
        blocks = factory._convert_to_bedrock_tool_call_invoke(valid)
        assert len(blocks) == 1
        tool_use = blocks[0]["toolUse"] if isinstance(blocks[0], dict) else blocks[0].toolUse
        # Valid args preserved verbatim — the patch only touches offenders.
        assert tool_use["input"]["executive_summary"] == "ok"
        assert tool_use["input"]["recommendations"] == "r"
    finally:
        factory._convert_to_bedrock_tool_call_invoke = original
        repair._PATCHED[0] = False


def test_sanitize_leaves_valid_calls_identity() -> None:
    valid = _tool_call('{"a": 1}')
    # No offender → returns the SAME object, so the wrapper knows nothing was
    # repairable and re-raises the original error rather than masking it.
    assert _sanitize_tool_calls(valid) is valid


def test_sanitize_blanks_only_the_offender() -> None:
    mixed = [
        {"id": "a", "type": "function", "function": {"name": "ok", "arguments": '{"x": 1}'}},
        {"id": "b", "type": "function", "function": {"name": "bad", "arguments": _TRUNCATED_ARGS}},
    ]
    out = _sanitize_tool_calls(mixed)
    assert out is not mixed  # something changed
    assert out[0]["function"]["arguments"] == '{"x": 1}'  # valid one untouched
    assert out[1]["function"]["arguments"] == "{}"  # offender blanked
