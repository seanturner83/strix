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

You are trying to REFUTE the finding, but the bar to refute is HIGH. Only a
finding you can PROVE harmless gets marked FALSE_POSITIVE. Re-derive from the
code shown; do NOT trust the agent's own conclusion — and do NOT trust that a
visible mitigation is sufficient.

  1. Trace the source -> sink. Is untrusted input reaching the dangerous sink in
the code shown?
  2. If a control/mitigation is present, you must prove it is COMPLETE, not just
present. A partial fix is a REAL finding. Specifically:
     - A sanitizer/allowlist must cover EVERY character or input the exploit
       needs — enumerate the class's dangerous chars and confirm each is blocked.
       (e.g. a shell-arg sanitizer that strips quotes but NOT $(), backticks, ;,
       |, & does NOT stop command injection → REAL.)
     - A lexical path guard (startsWith/HasPrefix/Clean) does NOT stop a SYMLINK
       or a sibling-dir escape → REAL for path-traversal unless symlinks are also
       handled.
     - A blocklist must cover the ALIASES/equivalents (e.g. operator vs _operator,
       decimal/octal IP vs dotted, __proto__ vs constructor.prototype) → REAL if
       any bypass class is unlisted.
  3. MISSING PoC IS NOT A REFUTATION. The absence of a concrete PoC/input in the
report is NOT evidence the vuln is fake — if the sink is reachable and the
control is incomplete, it is REAL regardless of whether a PoC was supplied. Never
mark FALSE_POSITIVE because "no PoC was provided" or "no concrete bypass shown".
  4. "This file is a scanner/library, not a live sink" is NOT a refutation unless
you can show the dangerous construct is genuinely unreachable — a deser/eval/exec
in a tool is still exploitable by whoever feeds it input.

Decision rules (ASYMMETRIC — an emitted false positive is cheap to dismiss; a
SUPPRESSED REAL VULNERABILITY IS A BREACH. When in any doubt, verdict=REAL):
  - FALSE_POSITIVE ONLY when you can cite the SPECIFIC, COMPLETE reason the
exploit cannot work in the code shown — a control that covers every needed
input, or a sink the untrusted data provably never reaches. State exactly which
dangerous inputs are blocked and how.
  - REAL in every other case: the chain holds, OR the fix is partial/incomplete,
OR you cannot COMPLETELY refute it, OR you're unsure, OR no PoC was given.
  - Set confidence >= 0.8 ONLY when the refutation is airtight (you enumerated the
attack inputs and every one is blocked). Any residual doubt -> confidence < 0.7
(which, being below the reject threshold, keeps the finding live).

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
