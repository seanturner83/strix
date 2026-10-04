"""System-1 filing gate: catch findings described in the final report but never filed.

A sibling of ``jev_dedupe`` / ``jev_verify``. Where verify asks "is this finding
real?", filing asks "does the finish write-up describe findings that were NOT filed
as reports?" — the *describe-don't-file* failure, where a weak orchestrator writes
vulnerabilities into its prose/remediation advice but skips
``create_vulnerability_report``. A fixed-shape decision, so another natural
System-1 task.

It supersedes the regex ``_summary_claims_findings`` heuristic in two ways:
  - it reads MEANING, so remediation-advice phrasing ("fix X", "disable Y") trips
    it, not only CVSS scores / severity tables; and
  - it compares the write-up against what was ALREADY filed, so it fires on
    UNDER-filing (described 5, filed 2), not only on the zero-filed case.

Fail-safe toward completion: it blocks finish ONLY when Jev is confidently sure the
write-up describes unfiled findings (``>= STRIX_FILING_GUARD_MIN_CONFIDENCE``,
default 0.7). An "all filed" verdict, low confidence, or any transport error lets
the scan finish, so a genuinely clean scan is never wedged.

Active when ``TYPESAFE_API_KEY`` is set and ``STRIX_FILING_GUARD`` is not off;
shares the Jev transport and ``TYPESAFE_*`` configuration with ``jev_dedupe``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.error
from typing import Any

from strix.report.jev_dedupe import _post


logger = logging.getLogger(__name__)

_TIMEOUT_S = 30.0
_DEFAULT_MIN_CONFIDENCE = 0.7


def jev_enabled() -> bool:
    """Whether the Jev filing guard is active: a key present and not disabled."""
    if not os.environ.get("TYPESAFE_API_KEY", "").strip():
        return False
    disabled = ("off", "0", "false", "no")
    return os.environ.get("STRIX_FILING_GUARD", "").strip().lower() not in disabled


def _min_confidence() -> float:
    try:
        return float(os.environ.get("STRIX_FILING_GUARD_MIN_CONFIDENCE", "").strip())
    except ValueError:
        return _DEFAULT_MIN_CONFIDENCE


async def jev_claims_unfiled_findings(
    summary: str, filed_titles: list[str]
) -> dict[str, Any] | None:
    """Return a filing verdict, or ``None`` to let the scan finish (fail-safe).

    Shape: ``{claims_unfiled, confidence, reason}``. ``claims_unfiled`` is True only
    when Jev is confidently sure the write-up describes a security finding that is
    NOT among ``filed_titles``.
    """
    if not summary.strip():
        return None
    state = {"write_up": summary[:6000], "filed_report_titles": filed_titles}
    payload = {
        "model": "jev-latest",
        "state": json.dumps(state),
        "questions": {
            "verdict": {
                "type": "choice",
                "instructions": (
                    "This is an autonomous pentest's final write-up plus the titles of the "
                    "vulnerability reports it actually filed. A finding counts as recorded ONLY "
                    "if it was filed (its title appears in the list). Does the write-up describe "
                    "one or more security vulnerabilities — in ANY phrasing, including "
                    "remediation advice such as 'fix X' or 'disable Y' — that are NOT represented "
                    "among the filed report titles?"
                ),
                "criteria": {
                    "unfiled_findings": (
                        "The write-up describes at least one vulnerability that is not among the "
                        "filed report titles (described but not filed)."
                    ),
                    "all_filed": (
                        "Every vulnerability the write-up describes is represented among the "
                        "filed titles, or the write-up describes no vulnerabilities (clean scan)."
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
        logger.warning("Jev filing guard failed (%s); letting the scan finish", exc)
        return None

    if choice == "unfiled_findings" and confidence >= _min_confidence():
        return {
            "claims_unfiled": True,
            "confidence": confidence,
            "reason": "Jev: write-up describes findings not among the filed reports",
        }
    return {
        "claims_unfiled": False,
        "confidence": confidence,
        "reason": "Jev did not confidently find unfiled findings",
    }
