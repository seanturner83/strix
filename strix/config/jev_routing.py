"""System-1 routing backend: classify a turn's capability tier via Jev.

This is the highest-frequency Jev call (every agent turn) and the most
domain-specific (pentest capability tiers), so it is the case that most wants
Jevstiller: point ``TYPESAFE_BASE_URL`` at a Jevstiller proxy and, after warmup,
a *local* student trained on our own turn distribution answers per-turn calls —
no per-turn hit to the remote API, and the classification adapts to what a
general upstream model would not understand.

Fail-open: any error returns ``None`` so routing falls back to the heuristic.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.error

from strix.config.jev_client import api_key, post
from strix.config.routing import TIERS


logger = logging.getLogger(__name__)

_TIMEOUT_S = 10.0  # per-turn: keep it tight, fall back to heuristic if slow
# Safe tier for a low-confidence classification: the most capable one. A security
# tool should not downgrade a possibly-critical turn to a weak model on a guess.
_SAFE_TIER = "reasoning"


def _min_confidence() -> float:
    """Below this, don't trust the classification — route to the safe tier.

    Default 0.0 (trust Jev's pick). Raise it to be conservative: with a
    high floor most turns route to the frontier tier until a Jevstiller student,
    calibrated on our own traffic, is confident enough to clear it. That's the
    dial that trades quota saving against the risk of a bad downgrade.
    """
    try:
        return float(os.environ.get("STRIX_ROUTING_MIN_CONFIDENCE", "").strip())
    except ValueError:
        return 0.0

# Domain framing carried in the request — this is the pentest-specific knowledge
# upstream Jev lacks, and exactly what a Jevstiller student distils and adapts.
_TIER_CRITERIA = {
    "mechanical": (
        "A routine observation follow-up — recording a file read, a directory "
        "listing, or a grep result and moving on. No real analysis needed."
    ),
    "standard": (
        "An ordinary next step — a straightforward request, a simple check, a "
        "mechanical probe — that needs competent but not frontier reasoning."
    ),
    "reasoning": (
        "Novel analysis: synthesising an exploit, chaining findings, or "
        "interpreting an unexpected result. Needs the strongest model."
    ),
}


async def _classify(state: dict[str, str], instructions: str) -> tuple[str, str] | None:
    """Ask Jev for a capability tier over ``state``; apply the confidence floor.

    Returns ``(tier, reason)`` or ``None`` to fall back. Below the floor the
    classification isn't trusted and routes to the safe (frontier) tier.
    """
    if not api_key():
        return None
    criteria = {tier: _TIER_CRITERIA.get(tier, tier) for tier in TIERS}
    payload = {
        "model": "jev-latest",
        "state": json.dumps(state),
        "questions": {
            "tier": {"type": "choice", "instructions": instructions, "criteria": criteria}
        },
    }
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(post, payload, _TIMEOUT_S), timeout=_TIMEOUT_S
        )
        answer = (result.get("answers") or {}).get("tier") or {}
        choice = str(answer.get("choice") or "").strip()
        confidence = float(answer.get("confidence") or 0.0)
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, OSError) as exc:
        logger.warning("Jev classify failed (%s); falling back", exc)
        return None

    if choice not in TIERS:
        return None
    floor = _min_confidence()
    if confidence < floor:
        return _SAFE_TIER, f"jev {choice}@{confidence:.2f} < floor {floor:.2f} -> safe tier"
    return choice, f"jev tier={choice} confidence={confidence:.2f}"


async def jev_classify_tier(digest: dict[str, str]) -> tuple[str, str] | None:
    """Classify a single turn's tier from a compact digest of its last action."""
    return await _classify(
        digest,
        "Given the last action in an autonomous security-testing agent's turn, "
        "what capability tier does the NEXT step most likely need?",
    )


async def jev_classify_mission(task: str) -> tuple[str, str] | None:
    """Classify a whole sub-agent mission's tier from its task description.

    One call at spawn binds the sub-agent to a model for its life — coarser than
    per-turn, cache-coherent, and where the multi-agent cost actually lives.
    """
    return await _classify(
        {"mission": task[:2000]},
        "Given this security-testing sub-agent's assigned mission, what capability "
        "tier does carrying it out need overall?",
    )
