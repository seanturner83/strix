"""In-scan verify-before-emit pass — the FP-reduction sibling of report/dedupe.py.

Fires right before a vulnerability report is persisted (reporting/tool.py::
_do_create, after the dedup check). Re-derives the source->sink chain from the
reported code + PoC and decides REAL vs FALSE_POSITIVE. This catches the
confident-but-wrong FP class the report-tool's prompt-level "only file verified
findings" guard cannot: on the VLB corpus, an adjudication pass cut Phase-B FPs
10->4 at FN=0, which prompt/mode tuning could not (verification moves the ROC
curve; wording only slides the operating point).

SAFETY (fail-open, asymmetric — a verifier miss must NEVER suppress a real bug):
  - only FALSE_POSITIVE with confidence >= min_confidence rejects the report;
  - REAL / uncertain / unparseable / any error -> EMIT (return None = no veto);
  - only fires on findings at/above VerifySettings.min_severity;
  - OFF by default (VerifySettings.enabled) — opt-in, +1 bounded LLM call/finding.

Mirrors dedupe.py's SDK-native shape: StrixProvider().get_model(...).get_response
with a system prompt, no tools, JSON out, usage recorded. Its own cheap-model
role (STRIX_VERIFY_MODEL -> STRIX_LLM_DEDUP -> base) — verification is a bounded
re-derivation, same tier as dedup.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing

from strix.config import load_settings
from strix.config.models import (
    StrixProvider,
    configure_sdk_model_defaults,
)
from strix.core.inputs import make_model_settings
from strix.report.dedupe import _extract_text, _prepare_report_for_comparison
from strix.report.state import get_global_report_state


if TYPE_CHECKING:
    from strix.config.settings import VerifySettings


logger = logging.getLogger(__name__)

# crit > high > medium > low > info. A finding is verified only when its severity
# rank >= the configured min_severity rank.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

VERIFY_SYSTEM_PROMPT = """\
You are a vulnerability-report VERIFIER. You receive ONE candidate finding an \
agent is about to file: its title, severity, the vulnerable code / sink, the \
proof-of-concept, and the technical analysis. Your job is to independently decide \
whether it is a REAL, presently-exploitable vulnerability or a FALSE_POSITIVE.

Re-derive from the evidence given — do NOT trust the agent's own conclusion:
  1. Trace the claimed source -> sink. Is untrusted input actually reaching the \
dangerous sink in the code shown?
  2. Is there a control on the path (validation, allowlist, escaping, authz \
check, parameterisation) or a hardened sink that neutralises the exploit? A \
sanitizer being PRESENT is not enough — check that it actually covers the \
characters/inputs the PoC needs.
  3. Does the PoC, as written, actually work against the code as shown — or does \
it assume a condition the code contradicts (a guard, a default, a type check)?
  4. Reject INCOMPLETE fixes only in the other direction: if the code shows the \
vuln still reachable despite a partial mitigation, it is REAL.

Decision rules (asymmetric — hold on doubt):
  - FALSE_POSITIVE only when you can point to the specific reason the exploit \
does NOT work in the code shown (a covering control, a contradicted PoC \
assumption, non-reachable sink). Cite it.
  - REAL when the chain holds, OR when you cannot confidently refute it. Never \
mark FALSE_POSITIVE on a hunch — an emitted false positive is cheap to dismiss; \
a suppressed real vulnerability is a breach.

Respond with ONLY this JSON object, no prose:
{
  "verdict": "REAL" | "FALSE_POSITIVE",
  "confidence": 0.0-1.0,
  "reason": "one or two sentences citing the specific code/PoC evidence"
}"""


def _verify_model_settings(
    verify: VerifySettings, model_name: str, request_timeout: float | None
) -> ModelSettings:
    settings = make_model_settings(
        verify.reasoning_effort,
        model_name=model_name,
        force_required_tool_choice=False,
        request_timeout=request_timeout,
    )
    extra: dict[str, str] = {}
    if verify.api_key:
        extra["api_key"] = verify.api_key
    if verify.api_base:
        extra["api_base"] = verify.api_base
    if extra:
        settings = settings.resolve(ModelSettings(extra_args=extra))
    return settings


def _meets_min_severity(severity: str, min_severity: str) -> bool:
    sev = _SEVERITY_RANK.get((severity or "").strip().lower(), -1)
    floor = _SEVERITY_RANK.get((min_severity or "").strip().lower(), _SEVERITY_RANK["high"])
    return sev >= floor


def _parse_verify_response(content: str) -> dict[str, Any]:
    """Parse the verifier's JSON verdict; tolerate code-fences / surrounding prose.
    On any parse failure return a REAL/low-confidence default (fail-open)."""
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        first, last = text.find("{"), text.rfind("}")
        obj = None
        if first != -1 and last > first:
            try:
                obj = json.loads(text[first : last + 1])
            except json.JSONDecodeError:
                obj = None
        if not isinstance(obj, dict):
            return {"verdict": "REAL", "confidence": 0.0, "reason": "unparseable verifier response"}
    verdict = str(obj.get("verdict", "REAL")).strip().upper()
    if verdict not in ("REAL", "FALSE_POSITIVE"):
        verdict = "REAL"
    try:
        confidence = float(obj.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    return {
        "verdict": verdict,
        "confidence": max(0.0, min(1.0, confidence)),
        "reason": str(obj.get("reason", ""))[:500],
    }


async def verify_finding(candidate: dict[str, Any], severity: str) -> dict[str, Any] | None:
    """Adjudicate ONE candidate finding. Returns a REJECT dict (mirroring the
    dedup-reject shape) when the finding is a confident FALSE_POSITIVE; returns
    None to EMIT (the fail-open default) in every other case — disabled, below
    min_severity, REAL, uncertain, no model, or any error.

    `candidate` is the same dict the dedup check builds (title/description/impact/
    target/technical_analysis/poc_*). `severity` is the computed CVSS severity."""
    settings = load_settings()
    verify = settings.verify
    if not verify.enabled:
        return None
    if not _meets_min_severity(severity, verify.min_severity):
        return None

    # Own cheap-model role -> dedup model -> base. Same tier as dedup.
    model_name = (
        (verify.model or "").strip()
        or (settings.llm.model_dedup or "").strip()
        or (settings.llm.model or "").strip()
    )
    if not model_name:
        logger.info("verify: no LLM model configured; emitting finding unverified")
        return None

    try:
        cleaned = _prepare_report_for_comparison(candidate)
        user_msg = (
            "Verify this candidate vulnerability finding:\n\n"
            f"severity: {severity}\n"
            f"{json.dumps(cleaned, indent=2)}\n\n"
            "Respond with ONLY the JSON object described in the system prompt."
        )
        configure_sdk_model_defaults(settings)
        model = StrixProvider().get_model(model_name)
        response = await model.get_response(
            system_instructions=VERIFY_SYSTEM_PROMPT,
            input=user_msg,
            model_settings=_verify_model_settings(verify, model_name, settings.llm.timeout),
            tools=[],
            output_schema=None,
            handoffs=[],
            tracing=ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
        report_state = get_global_report_state()
        if report_state is not None:
            report_state.record_sdk_usage(
                agent_id="verify", agent_name="verify",
                model=model_name, usage=response.usage,
            )
        content = _extract_text(response)
        if not content:
            logger.info("verify: empty response; emitting finding unverified")
            return None
        result = _parse_verify_response(content)
    except Exception:  # noqa: BLE001 — verification is advisory; a failure must NEVER suppress a finding
        logger.exception("verify: check failed; emitting finding (fail-open)")
        return None

    logger.info(
        "verify: verdict=%s confidence=%.2f title=%s",
        result["verdict"], result["confidence"], candidate.get("title", "?"),
    )
    if result["verdict"] == "FALSE_POSITIVE" and result["confidence"] >= verify.min_confidence:
        return {
            "success": False,
            "error": (
                "Verify pass rejected this finding as a likely FALSE POSITIVE "
                f"(confidence {result['confidence']:.2f}): {result['reason']} "
                "Re-check the source->sink chain and any covering control before "
                "re-filing; if you can show the exploit works against the current "
                "code, include that proof."
            ),
            "verify_rejected": True,
            "confidence": result["confidence"],
            "reason": result["reason"],
        }
    return None
