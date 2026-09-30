"""System-1 verify gate: reject confident false positives with a Jev classifier.

A sibling of the Jev dedup backend (``jev_dedupe``). Where dedup asks "is this a
repeat?", verify asks "is this finding actually real?" — a fixed-shape decision
repeated per finding, so another natural System-1 task.

It is deliberately **asymmetric / fail-open**: a finding is rejected only when
Jev is confidently sure it is a false positive (``>= STRIX_VERIFY_MIN_CONFIDENCE``);
anything else — a "real" verdict, low confidence, or any error — returns a
non-rejecting result so a genuine finding is never dropped. Cut false positives
without adding false negatives.

Selected with ``STRIX_VERIFY_BACKEND=jev``; shares the Jev transport and
``TYPESAFE_*`` configuration with ``jev_dedupe``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.error
from typing import Any

from strix.report.dedupe import _prepare_report_for_comparison
from strix.report.jev_dedupe import _post


logger = logging.getLogger(__name__)

_TIMEOUT_S = 30.0
_DEFAULT_MIN_CONFIDENCE = 0.7


def jev_enabled() -> bool:
    """Whether the Jev verify gate is selected and has a key to use."""
    if os.environ.get("STRIX_VERIFY_BACKEND", "").strip().lower() != "jev":
        return False
    return bool(os.environ.get("TYPESAFE_API_KEY", "").strip())


def _min_confidence() -> float:
    try:
        return float(os.environ.get("STRIX_VERIFY_MIN_CONFIDENCE", "").strip())
    except ValueError:
        return _DEFAULT_MIN_CONFIDENCE


async def jev_check_false_positive(report: dict[str, Any]) -> dict[str, Any] | None:
    """Return a verify verdict, or ``None`` to let the finding through.

    Shape: ``{is_false_positive, confidence, reason}``. Non-rejecting unless Jev
    is confidently sure the finding is a false positive.
    """
    payload = {
        "model": "jev-latest",
        "state": json.dumps(_prepare_report_for_comparison(report)),
        "questions": {
            "verdict": {
                "type": "choice",
                "instructions": (
                    "Given this vulnerability report and its evidence/PoC, is it a genuine, "
                    "exploitable finding, or a false positive (not actually exploitable, "
                    "misidentified, or unsupported by the evidence)?"
                ),
                "criteria": {
                    "real": "A genuine, exploitable vulnerability supported by the evidence.",
                    "false_positive": (
                        "Not actually exploitable, misidentified, or unsupported by the evidence."
                    ),
                },
            }
        },
    }

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_post, payload), timeout=_TIMEOUT_S)
        answer = (result.get("answers") or {}).get("verdict") or {}
        choice = str(answer.get("choice") or "").strip()
        confidence = float(answer.get("confidence") or 0.0)
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, OSError) as exc:
        logger.warning("Jev verify gate failed (%s); letting the finding through", exc)
        return None

    if choice == "false_positive" and confidence >= _min_confidence():
        return {
            "is_false_positive": True,
            "confidence": confidence,
            "reason": "Jev classified the finding as a false positive",
        }
    return {
        "is_false_positive": False,
        "confidence": confidence,
        "reason": "Jev did not confidently reject the finding",
    }
