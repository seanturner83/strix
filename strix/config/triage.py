"""OODA turn triage — a System-1 gate on the per-turn orchestrator loop.

The orchestrator's turn loop is the hot path (~99% of a scan's tokens). Most
turns cost a full big-model generation over a large context, yet many need far
less capability than the frontier model brings. This module decides, per turn,
the **capability tier** the turn needs; routing (later) maps each tier to the
cheapest model that can serve it — a fleet of N models ordered by capability,
not a binary cheap/big split.

Two backends (``STRIX_TRIAGE_BACKEND``):

- ``heuristic`` (default, zero-dependency) — keys off the last tool action. It
  can only reliably tell ``mechanical`` (observation follow-ups) from
  ``reasoning`` (everything else). This is the measurement *floor*.
- ``jev`` — a System-1 classifier returns the full tier set with calibrated
  confidence from a compact digest of the turn. **This is what unlocks true
  N-way capability routing**; the heuristic cannot separate ``standard`` from
  ``reasoning`` reliably, and Jev can.

**Phase 1 is shadow-only** (``STRIX_TRIAGE=shadow``): the tier is logged, not
acted on, so we can measure the tier distribution of the hot path — and compare
the heuristic floor against what Jev unlocks — at zero quality risk.
"""

from __future__ import annotations

import os
from typing import Any


# Capability tiers, ordered low→high. Open vocabulary: the Jev backend may
# return finer tiers later (e.g. "recon", "exploit", "specialized"), each mapped
# to a model by routing config. Routing treats an unknown tier as "reasoning".
TIERS = ("mechanical", "standard", "reasoning")
_DEFAULT_TIER = "reasoning"

# Strix's read-only tools: after one of these the next step is usually
# mechanical. NOTE the sharp limit measured on real runs: Strix routes almost
# all real work — file reads, greps, exploits alike — through one generic
# ``exec_command`` tool, so the tool NAME does not reveal capability need. The
# heuristic therefore has a very low ceiling on Strix and classifies most turns
# ``reasoning``; separating a mechanical ``exec_command`` from a reasoning one
# needs the command/output CONTENT — i.e. the Jev backend, which reads the
# digest. That gap is the whole reason the System-1 classifier unlocks routing.
_MECHANICAL_TOOLS = frozenset(
    {
        "list_coverage",
        "list_reports",
        "list_requests",
        "record_coverage",
        "view_agent_graph",
        "get_threat_model",
        "code_graph_grep",
        "find_definition",
        "find_references",
    }
)


def triage_mode() -> str:
    """``"off"`` (default), ``"shadow"`` (classify + log, serve from default), or
    ``"live"`` (classify + log + route the turn to the tier's model)."""
    mode = os.environ.get("STRIX_TRIAGE", "").strip().lower()
    return mode if mode in ("shadow", "live") else "off"


def triage_backend() -> str:
    """``"jev"`` when a TypeSafe/Jevstiller endpoint is configured, else ``"heuristic"``.

    Explicit ``STRIX_TRIAGE_BACKEND`` wins. Otherwise we lean on Jev/Jevstiller
    as the System-1 whenever it is available — the heuristic is only the
    fail-open floor for when no S1 service is configured (or a call errors).
    """
    backend = os.environ.get("STRIX_TRIAGE_BACKEND", "").strip().lower()
    if backend in ("heuristic", "jev"):
        return backend
    from strix.config.jev_client import api_key  # noqa: PLC0415  # avoid import cost when off

    return "jev" if api_key() else "heuristic"


def _last_tool_name(model_input: str | list[Any]) -> str | None:
    if not isinstance(model_input, list):
        return None
    for item in reversed(model_input):
        if isinstance(item, dict) and item.get("type") == "function_call" and item.get("name"):
            return str(item["name"])
    return None


def _last_call_args(model_input: str | list[Any], limit: int = 400) -> str:
    """The arguments of the most recent function call (truncated).

    For Strix this is the real signal: the tool name is almost always the
    generic ``exec_command``, so *what command it runs* — ``cat app.py`` vs
    ``sqlmap --dump`` — is what reveals the capability the turn needs.
    """
    if not isinstance(model_input, list):
        return ""
    for item in reversed(model_input):
        if isinstance(item, dict) and item.get("type") == "function_call":
            args = item.get("arguments")
            return (args if isinstance(args, str) else str(args))[:limit]
    return ""


def _last_output_snippet(model_input: str | list[Any], limit: int = 600) -> str:
    """A short snippet of the most recent tool output, for the Jev digest."""
    if not isinstance(model_input, list):
        return ""
    for item in reversed(model_input):
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            out = item.get("output")
            text = out if isinstance(out, str) else str(out)
            return text[:limit]
    return ""


def digest(model_input: str | list[Any]) -> dict[str, str]:
    """Compact features for a triage decision — never the whole context.

    Sending the full conversation to the classifier would defeat the purpose;
    the tier is decidable from the last action (its command and a snippet of
    its result). The command matters most on Strix's generic-tool surface.
    """
    return {
        "last_tool": _last_tool_name(model_input) or "",
        "last_command": _last_call_args(model_input),
        "last_output": _last_output_snippet(model_input),
    }


def _heuristic_tier(model_input: str | list[Any]) -> tuple[str, str]:
    last_tool = _last_tool_name(model_input)
    if last_tool and last_tool in _MECHANICAL_TOOLS:
        return "mechanical", f"last action '{last_tool}' is mechanical"
    if last_tool:
        return _DEFAULT_TIER, f"last action '{last_tool}' may need reasoning"
    return _DEFAULT_TIER, "no recent tool action"


async def classify_turn(model_input: str | list[Any], tools: list[Any]) -> tuple[str, str]:
    """Return ``(tier, reason)`` for a turn. Fail-safe: ambiguity → ``reasoning``.

    Not an agent OODA turn (no tools) → ``reasoning`` (never routed anyway).
    """
    if not tools:
        return _DEFAULT_TIER, "non-agent turn"
    if triage_backend() == "jev":
        # Local import: jev_triage imports TIERS from this module.
        from strix.config.jev_triage import jev_classify_tier  # noqa: PLC0415

        result = await jev_classify_tier(digest(model_input))
        if result is not None:
            return result
        # Fail open to the heuristic when Jev is unavailable.
    return _heuristic_tier(model_input)


async def classify_mission(task: str) -> tuple[str, str]:
    """Classify a whole sub-agent mission into a tier (for spawn-time routing).

    Jev-backed when configured; the heuristic can't read a free-text mission, so
    it falls back to the safe (frontier) tier rather than guess.
    """
    if triage_backend() == "jev":
        from strix.config.jev_triage import jev_classify_mission  # noqa: PLC0415

        result = await jev_classify_mission(task)
        if result is not None:
            return result
    return _DEFAULT_TIER, "no jev backend; mission defaults to the safe tier"
