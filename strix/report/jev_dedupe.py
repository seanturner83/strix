"""System-1 dedup backend: route the duplicate decision to a Jev classifier.

Strix's default dedup is an LLM that reasons in tokens and emits a JSON verdict
(``strix/report/dedupe.py``). That decision has a fixed shape and is repeated
per finding, so it is a natural System-1 task: Jev (TypeSafe AI) picks exactly
one label with calibrated probabilities in one forward pass, no token decode.

This adapter maps the 1-vs-N dedup question onto Jev's ``choice`` primitive:
the labels are the existing report ids plus ``"none"``, and Jev selects the
report the candidate duplicates, or ``"none"`` for a genuinely new finding.

Selected with ``STRIX_DEDUPE_BACKEND=jev``. ``TYPESAFE_BASE_URL`` points at the
Jev API directly or at a Jevstiller proxy (which distils the task to a local
model and only defers novel/low-confidence calls upstream). It is deliberately
fail-safe: any error returns ``None`` so the caller falls back to the LLM path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

from strix.report.dedupe import _prepare_report_for_comparison


logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://api.typesafe.ai"
_NONE_LABEL = "none"
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

    The verdict shape matches the LLM path: ``is_duplicate`` / ``duplicate_id``
    / ``confidence`` / ``reason``.
    """
    if not existing_reports:
        return None

    # Labels are the existing report ids; Jev either picks one or "none".
    criteria: dict[str, str] = {}
    id_by_label: dict[str, str] = {}
    state_existing: dict[str, Any] = {}
    for report in existing_reports:
        rid = str(report.get("id") or "").strip()
        if not rid:
            continue
        label = rid[:64]
        criteria[label] = _summary(report)
        id_by_label[label] = rid
        state_existing[label] = _prepare_report_for_comparison(report)
    if not criteria:
        return None
    criteria[_NONE_LABEL] = (
        "The candidate is a new, distinct vulnerability that does not match any existing report."
    )

    state = {
        "candidate": _prepare_report_for_comparison(candidate),
        "existing_reports": state_existing,
    }
    payload = {
        "model": "jev-latest",
        "state": json.dumps(state),
        "questions": {
            "duplicate_of": {
                "type": "choice",
                "instructions": (
                    "Which existing report, if any, describes the SAME underlying "
                    "vulnerability as the candidate (same root cause and location)? "
                    "Choose 'none' if the candidate is genuinely distinct."
                ),
                "criteria": criteria,
            }
        },
    }

    try:
        result = await asyncio.wait_for(asyncio.to_thread(_post, payload), timeout=_TIMEOUT_S)
        answer = (result.get("answers") or {}).get("duplicate_of") or {}
        choice = str(answer.get("choice") or "").strip()
        confidence = float(answer.get("confidence") or 0.0)
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, OSError) as exc:
        logger.warning("Jev dedup backend failed (%s); falling back to LLM path", exc)
        return None

    if not choice or choice == _NONE_LABEL or choice not in id_by_label:
        return {
            "is_duplicate": False,
            "duplicate_id": "",
            "confidence": confidence,
            "reason": "Jev classified the candidate as a distinct finding",
        }
    return {
        "is_duplicate": True,
        "duplicate_id": id_by_label[choice],
        "confidence": confidence,
        "reason": f"Jev matched the candidate to {id_by_label[choice]}",
    }
