"""System-1 dedup backend: route the duplicate decision to a Jev classifier.

Strix's default dedup is an LLM that reasons in tokens and emits a JSON verdict
(``strix/report/dedupe.py``). That decision has a fixed shape and is repeated
per finding, so it is a natural System-1 task: Jev (TypeSafe AI) picks a label
with a calibrated probability in one forward pass, no token decode.

**Binary framing (not 1-of-N):** we first pick the single nearest existing
report by a cheap lexical score, then ask Jev one fixed ``duplicate`` vs
``distinct`` question about that pair. A fixed two-label space (a) gives a stable
confidence to threshold on, and (b) is distillable by a Jevstiller proxy — unlike
the old "choose among the existing report ids" shape, whose labels changed every
scan so a local student could never learn them.

**Fail-safe toward keeping-distinct:** a candidate is merged into the nearest
report ONLY when Jev says ``duplicate`` *and* ``confidence >= STRIX_DEDUPE_MIN_CONFIDENCE``
(default 0.7). A ``distinct`` verdict, a low-confidence ``duplicate``, or any error
keeps the finding — because wrongly merging destroys coverage (a real second vuln
is lost), whereas a missed merge only costs a duplicate report. Mirrors the
asymmetry of the verify gate (``jev_verify``), which only *rejects* when confident.

Selected with ``STRIX_DEDUPE_BACKEND=jev``. ``TYPESAFE_BASE_URL`` points at the
Jev API directly or at a Jevstiller proxy (which distils the task to a local
model and only defers novel/low-confidence calls upstream). Any transport error
returns ``None`` so the caller falls back to the LLM dedup path.
"""

from __future__ import annotations

import asyncio
import difflib
import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

from strix.report.dedupe import _prepare_report_for_comparison


logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://api.typesafe.ai"
_DEFAULT_MIN_CONFIDENCE = 0.7
_TIMEOUT_S = 30.0


def jev_enabled() -> bool:
    """Whether the Jev dedup backend is selected and has a key to use."""
    if os.environ.get("STRIX_DEDUPE_BACKEND", "").strip().lower() != "jev":
        return False
    return bool(_api_key())


def _api_key() -> str | None:
    key = os.environ.get("TYPESAFE_API_KEY", "").strip()
    return key or None


def _base_url() -> str:
    return (os.environ.get("TYPESAFE_BASE_URL", "").strip() or _DEFAULT_BASE_URL).rstrip("/")


def _min_confidence() -> float:
    """Floor below which a ``duplicate`` verdict is NOT trusted (keep-distinct)."""
    try:
        return float(os.environ.get("STRIX_DEDUPE_MIN_CONFIDENCE", "").strip())
    except ValueError:
        return _DEFAULT_MIN_CONFIDENCE


def _summary(report: dict[str, Any]) -> str:
    """A compact one-line label description for a report (title/target/cve)."""
    cleaned = _prepare_report_for_comparison(report)
    title = str(cleaned.get("title") or "untitled").strip()
    bits = [title]
    for field in ("endpoint", "method", "cve", "target"):
        val = str(cleaned.get(field) or "").strip()
        if val:
            bits.append(val)
    return " | ".join(bits)[:300]


def _nearest_report(
    candidate: dict[str, Any], existing_reports: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """The lexically closest existing report to the candidate (by its summary).

    A true repeat has near-identical text, so the closest-by-text report is the
    right one to ask Jev about; genuinely distinct findings score low and Jev then
    rules them ``distinct``.
    """
    cand = _summary(candidate)
    best: dict[str, Any] | None = None
    best_score = -1.0
    for report in existing_reports:
        if not str(report.get("id") or "").strip():
            continue
        score = difflib.SequenceMatcher(None, cand, _summary(report)).ratio()
        if score > best_score:
            best, best_score = report, score
    return best


def _post(payload: dict[str, Any]) -> dict[str, Any]:
    """Blocking POST to the Jev/Jevstiller endpoint; raises on failure."""
    req = urllib.request.Request(  # noqa: S310  # fixed https host + scheme
        f"{_base_url()}/v1/systemone",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {_api_key()}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:  # noqa: S310  # fixed https host
        return json.loads(resp.read().decode("utf-8"))


async def jev_check_duplicate(
    candidate: dict[str, Any], existing_reports: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Return a dedup verdict from Jev, or ``None`` so the caller falls back.

    The verdict shape matches the LLM path: ``is_duplicate`` / ``duplicate_id`` /
    ``confidence`` / ``reason``. Merges only on a confident ``duplicate`` against
    the nearest existing report; otherwise keeps the finding (fail-safe).
    """
    if not existing_reports:
        return None
    nearest = _nearest_report(candidate, existing_reports)
    if nearest is None:
        return None
    nid = str(nearest.get("id") or "").strip()

    state = {
        "candidate": _prepare_report_for_comparison(candidate),
        "nearest_report": _prepare_report_for_comparison(nearest),
    }
    payload = {
        "model": "jev-latest",
        "state": json.dumps(state),
        "questions": {
            "is_duplicate": {
                "type": "choice",
                "instructions": (
                    "Does the candidate describe the SAME underlying vulnerability as the "
                    "nearest existing report (same root cause and location)? Answer 'duplicate' "
                    "only if they are the same finding; 'distinct' if the candidate is a "
                    "different vulnerability."
                ),
                "criteria": {
                    "duplicate": (
                        "Same underlying vulnerability as the nearest report "
                        "(same root cause and location)."
                    ),
                    "distinct": "A different vulnerability from the nearest report.",
                },
            }
        },
    }

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_post, payload), timeout=_TIMEOUT_S)
        answer = (result.get("answers") or {}).get("is_duplicate") or {}
        choice = str(answer.get("choice") or "").strip()
        confidence = float(answer.get("confidence") or 0.0)
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, OSError) as exc:
        logger.warning("Jev dedup backend failed (%s); falling back to LLM path", exc)
        return None

    # Fail-safe toward keeping-distinct: merge only on a CONFIDENT 'duplicate'.
    # 'distinct', or a low-confidence 'duplicate', keeps the finding — coverage
    # (never lose a real vuln) is worth more than suppressing a duplicate report.
    if choice == "duplicate" and confidence >= _min_confidence():
        return {
            "is_duplicate": True,
            "duplicate_id": nid,
            "confidence": confidence,
            "reason": f"Jev confidently matched the candidate to {nid}",
        }
    return {
        "is_duplicate": False,
        "duplicate_id": "",
        "confidence": confidence,
        "reason": "Jev did not confidently classify the candidate as a duplicate",
    }
