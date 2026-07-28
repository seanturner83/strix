"""Fail-open on a truncated/malformed tool-call ``arguments`` during Bedrock
history replay, instead of crashing the whole agent loop.

WHY: When Claude-on-Bedrock emits a tool call whose ``arguments`` JSON is
truncated (observed live: a ``finish_scan`` call cut off mid-first-field at the
model's output ceiling — the string ended at ``...well-secured."`` with no
closing ``}`` and 3 required fields missing), litellm's
``_convert_to_bedrock_tool_call_invoke`` does:

    try:
        arguments_dict = json.loads(arguments)         # → JSONDecodeError (truncated)
    except json.JSONDecodeError:
        parsed_objects = split_concatenated_json_objects(arguments)   # ← re-raises!

``split_concatenated_json_objects`` is meant for the *concatenated* case
(``{...}{...}``) and itself calls ``json.loads``; on *truncated* (non-
concatenated) input it raises again, the exception escapes the ``except``
branch, and the outer ``raise Exception("Unable to convert openai tool
calls=...")`` fires. That aborts the run while converting message HISTORY on the
NEXT turn — so one truncated tool call is fatal, discarding an otherwise-complete
scan (the finding was already persisted; only the loop dies).

This is a genuine litellm bug: its own JSONDecodeError branch clearly *intends*
to degrade (it sets ``arguments_dict = {}`` when the fallback yields nothing),
it just lets ``split_concatenated_json_objects`` re-raise first. Rather than
depend on an upstream release, wrap the converter here (same pattern as
``litellm_bedrock_strict_patch``): if the underlying call raises, retry with any
tool call whose ``arguments`` won't ``json.loads`` rewritten to ``"{}"``. A
truncated tool call becomes an empty-args tool-use block — replayable, non-fatal.

Idempotent, import-once, fail-open (a repair error must never break a scan).
Upstream candidate: litellm's ``except json.JSONDecodeError`` must not let
``split_concatenated_json_objects`` propagate — wrap it and default to ``{}``.
"""

from __future__ import annotations

import json
import logging


logger = logging.getLogger(__name__)

_PATCHED = [False]


def _sanitize_tool_calls(tool_calls: object) -> object:
    """Return a copy of ``tool_calls`` with any un-parseable ``arguments``
    string replaced by ``"{}"``. Only rewrites the offenders; leaves valid
    tool calls untouched. Best-effort — returns the input unchanged on any
    unexpected shape."""
    if not isinstance(tool_calls, list):
        return tool_calls
    repaired: list = []
    changed = False
    for tool in tool_calls:
        if not isinstance(tool, dict) or "function" not in tool:
            repaired.append(tool)
            continue
        fn = tool.get("function")
        args = fn.get("arguments", "") if isinstance(fn, dict) else ""
        if isinstance(args, str) and args.strip():
            try:
                parsed = json.loads(args)
                if isinstance(parsed, dict):
                    repaired.append(tool)
                    continue
            except json.JSONDecodeError:
                pass
            else:
                # parsed but not a dict — leave litellm's own {} coercion to it
                repaired.append(tool)
                continue
            # unparseable: shallow-copy and blank the arguments
            new_fn = dict(fn)
            new_fn["arguments"] = "{}"
            new_tool = dict(tool)
            new_tool["function"] = new_fn
            repaired.append(new_tool)
            changed = True
            logger.warning(
                "Bedrock tool-call repair: tool %r had unparseable arguments "
                "(%d chars, likely truncated at the output ceiling) — replaced "
                "with {} so history replay does not abort the run.",
                new_fn.get("name", "?"),
                len(args),
            )
        else:
            repaired.append(tool)
    return repaired if changed else tool_calls


def apply() -> None:
    if _PATCHED[0]:
        return
    try:
        from litellm.litellm_core_utils.prompt_templates import factory
    except ImportError as exc:  # litellm layout changed — fail open, don't break scans
        logger.warning("bedrock tool-call repair patch skipped (litellm layout): %r", exc)
        return

    _orig = getattr(factory, "_convert_to_bedrock_tool_call_invoke", None)
    if _orig is None:
        logger.warning(
            "bedrock tool-call repair: _convert_to_bedrock_tool_call_invoke absent "
            "— litellm layout changed, skipping"
        )
        return

    def _patched(tool_calls, *args, **kwargs):  # type: ignore[no-untyped-def]
        try:
            return _orig(tool_calls, *args, **kwargs)
        except Exception:
            # First failure: retry once with unparseable arguments blanked. If it
            # still fails, re-raise the ORIGINAL behaviour (don't mask a genuine,
            # unrelated conversion bug).
            try:
                sanitized = _sanitize_tool_calls(tool_calls)
            except Exception:
                logger.debug("tool-call repair: sanitize failed", exc_info=True)
                raise
            if sanitized is tool_calls:
                raise  # nothing was repairable → not our case, preserve original error
            logger.warning(
                "bedrock tool-call repair: retrying conversion after blanking "
                "unparseable tool-call arguments"
            )
            return _orig(sanitized, *args, **kwargs)

    factory._convert_to_bedrock_tool_call_invoke = _patched  # type: ignore[attr-defined]
    _PATCHED[0] = True
    logger.info("Applied Bedrock tool-call repair patch (_convert_to_bedrock_tool_call_invoke)")
