"""``finish_scan`` — root-agent termination + executive report persistence."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.core.agents import coordinator_from_context


logger = logging.getLogger(__name__)

# A finding is only recorded when filed via ``create_vulnerability_report``. Models
# (especially smaller/local ones) sometimes analyse correctly but then *describe* the
# vulnerabilities in the finish_scan summary instead of filing them — so the scan ends
# with findings in the prose and zero in the report store. These signal that the final
# report PROSE enumerates rated vulnerabilities, used to catch that discrepancy.
_SEVERITY_WORD = re.compile(r"\b(critical|high|medium|low)\b", re.IGNORECASE)
_SEVERITY_TABLE_ROW = re.compile(
    r"\|[^|\n]*\b(critical|high|medium|low)\b[^|\n]*\|", re.IGNORECASE
)
_VULN_CLASSES = re.compile(
    r"\b(xss|cross-site scripting|sql injection|sqli|command injection|ssti|"
    r"template injection|rce|remote code execution|path traversal|directory traversal|"
    r"idor|csrf|ssrf|broken access control|insecure deserialization|"
    r"hardcoded (?:secret|token|credential|password|key))\b",
    re.IGNORECASE,
)


def _summary_claims_findings(*texts: str) -> bool:
    """True when the final report prose enumerates rated vulnerabilities.

    Deliberately conservative — keys off signals a genuinely clean scan won't emit:
    a CVSS score, a markdown table row carrying a severity rating, or two-plus distinct
    vulnerability classes named alongside two-plus severity ratings. A clean scan ("no
    vulnerabilities identified") names no classes and no severities, so it won't trip.
    """
    blob = "\n".join(t for t in texts if t)
    if not blob.strip():
        return False
    if "cvss" in blob.lower():
        return True
    if _SEVERITY_TABLE_ROW.search(blob):
        return True
    classes = {m.group(0).lower() for m in _VULN_CLASSES.finditer(blob)}
    severities = _SEVERITY_WORD.findall(blob)
    return len(classes) >= 2 and len(severities) >= 2


def _do_finish(
    *,
    parent_id: str | None,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
    agent_graph: dict[str, Any],
) -> dict[str, Any]:
    if parent_id is not None:
        return {
            "success": False,
            "error": (
                "This tool can only be used by the root/main agent. "
                "If you are a subagent, use agent_finish instead"
            ),
        }

    errors: list[str] = []
    if not executive_summary.strip():
        errors.append("Executive summary cannot be empty")
    if not methodology.strip():
        errors.append("Methodology cannot be empty")
    if not technical_analysis.strip():
        errors.append("Technical analysis cannot be empty")
    if not recommendations.strip():
        errors.append("Recommendations cannot be empty")
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    try:
        from strix.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; scan results not persisted")
            return {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed (not persisted)",
                "warning": "Results could not be persisted - report state unavailable",
            }
        if not report_state.vulnerability_reports and _summary_claims_findings(
            executive_summary, technical_analysis
        ):
            logger.warning("finish_scan blocked: summary describes findings but none were filed")
            return {
                "success": False,
                "error": "Findings described in the summary but none were filed",
                "message": (
                    "Your executive_summary/technical_analysis describes vulnerabilities, but 0 "
                    "were filed via create_vulnerability_report. A finding is ONLY recorded when "
                    "filed with create_vulnerability_report (one call per finding, with its "
                    "code_locations and evidence) — the executive summary is not a substitute. "
                    "File each vulnerability you described, then call finish_scan again. If you "
                    "genuinely found nothing, restate the summary to say no vulnerabilities were "
                    "identified (then no filing is needed)."
                ),
            }
        report_state.update_scan_final_fields(
            executive_summary=executive_summary.strip(),
            methodology=methodology.strip(),
            technical_analysis=technical_analysis.strip(),
            recommendations=recommendations.strip(),
        )
        vuln_count = len(report_state.vulnerability_reports)
        coverage_summary = _coverage_summary(agent_graph)
    except (ImportError, AttributeError) as e:
        logger.exception("finish_scan persistence failed")
        return {"success": False, "error": f"Failed to complete scan: {e!s}"}
    else:
        logger.info(
            "finish_scan: completed scan with %d vulnerability report(s)",
            vuln_count,
        )
        result: dict[str, Any] = {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed successfully",
            "vulnerabilities_found": vuln_count,
        }
        result.update(coverage_summary)
        return result


def _coverage_summary(agent_graph: dict[str, Any]) -> dict[str, Any]:
    """Coverage counts, unresolved surfaces, and gaps the runtime can see.

    The gap list is derived from the agent graph rather than from the ledger,
    so it catches the failure the ledger cannot: a risk class an agent was
    equipped for and never accounted for. Surfacing it here — in the response
    to the call that ends the scan — is the last point at which the root agent
    can still dispatch work or record the class as unresolved instead of
    letting the report imply it was clean.
    """
    from strix.report.coverage import agents_from_graph, skill_coverage_gaps
    from strix.tools.coverage.tools import get_coverage_entries, outcome_counts

    entries = get_coverage_entries()
    if not entries:
        return {
            "coverage_recorded": 0,
            "coverage_warning": (
                "No coverage was recorded for this scan. The report cannot show which "
                "surfaces were reviewed and cleared — only what was found. Use "
                "record_coverage during testing so future scans can report negative space."
            ),
        }

    counts = outcome_counts()
    summary: dict[str, Any] = {
        "coverage_recorded": len(entries),
        "coverage_outcomes": counts,
    }
    unresolved = [e for e in entries if e.get("outcome") == "needs_follow_up"]
    if unresolved:
        summary["coverage_warning"] = (
            f"{len(unresolved)} surface(s) closed as 'needs_follow_up' and remain "
            "unresolved. These should be represented in the report as areas requiring "
            "further review rather than omitted."
        )
        summary["unresolved_surfaces"] = [
            {"surface": e.get("surface", ""), "risk_area": e.get("risk_area", "")}
            for e in unresolved
        ]

    gaps = skill_coverage_gaps(entries, agents_from_graph(agent_graph))
    if gaps:
        summary["coverage_gaps"] = [gap["detail"] for gap in gaps]
        summary["coverage_gap_warning"] = (
            f"{len(gaps)} risk class(es) assigned to agents have no coverage entry and "
            "will be published as unexamined. Record them (or a needs_follow_up row) "
            "before the report goes out."
        )
    return summary


@function_tool(timeout=60)
async def finish_scan(
    ctx: RunContextWrapper,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> str:
    """Finalize the scan — persist the customer-facing report.

    **Root-agent only.** Subagents must call ``agent_finish`` from the
    multi-agent graph tools instead. Calling this finalizes everything:

    1. Verifies you are the root agent.
    2. Writes the four narrative sections to the scan record.
    3. Marks the scan completed and stops execution.

    **This is a terminal action, not a status probe.** Whatever you pass
    is persisted VERBATIM as the final, customer-facing report and then
    execution stops. There is no draft mode and no second chance: never
    submit placeholder, provisional, or "checking if done" text in any
    field, and never call ``finish_scan`` to poll whether subagents are
    done (use ``view_agent_graph`` / ``wait_for_agents`` for that).
    Call it exactly ONCE, only when every field holds genuine, finished
    assessment prose.

    **Pre-flight checklist (mandatory — do not skip):**

    1. **Call ``view_agent_graph`` first.** Inspect every entry in the
       summary. If ANY agent is in ``running`` / ``waiting`` state,
       you MUST NOT call ``finish_scan`` yet —
       wrap them up first via ``send_message_to_agent`` (ask them to
       finish), ``wait_for_agents`` (block until their report
       arrives), or ``stop_agent`` (graceful cancel). Only ``completed``
       / ``crashed`` / ``stopped`` agents are safe to leave behind.
       Calling ``finish_scan`` while children are alive orphans their
       work and produces an incomplete report.
    2. It's a good idea to call ``list_reports`` before finishing to
       review every finding filed in this scan (use ``get_report`` for
       full detail on any of them) so your ``executive_summary`` /
       ``technical_analysis`` are grounded in what was actually reported
       — don't invent or omit findings. All vulnerabilities you found are
       filed via ``create_vulnerability_report`` — or, for known-CVE
       dependency findings, ``create_dependency_report`` (un-reported
       findings are not tracked and not credited). A dependency CVE
       already filed via ``create_dependency_report`` counts as reported;
       it does NOT need re-filing here and does NOT block finishing.
    3. Don't double-report — one report per distinct vulnerability.
    4. **Attack-chaining gate.** Do NOT finish until you have genuinely
       considered chaining the confirmed findings into higher-impact,
       end-to-end attack paths and tested every plausibly-related
       combination. You may rule out combinations you can confidently
       call unrelated — note why instead of padding chains. Any
       validated chain must already be filed via
       ``create_vulnerability_report`` — a demonstrated end-to-end chain
       is a PoC-backed vulnerability, so it uses that tool even when one
       link is a dependency CVE (the standalone CVE stays in its own
       ``create_dependency_report``) — and surfaced prominently in
       ``executive_summary`` / ``technical_analysis``. Finding no real
       chain after a serious attempt is acceptable; skipping the
       chaining reasoning, or ignoring a plausibly-related combination,
       is not.
    5. **Coverage reconciliation.** Call ``list_coverage`` and check
       what was actually assessed against the surfaces you enumerated
       during reconnaissance. Every surface you dispatched work on
       should have a coverage entry; anything still open should be a
       ``needs_follow_up`` row, not a silent omission. If a significant
       surface has no entry at all, dispatch an agent to cover it or
       record it as ``needs_follow_up`` before finishing. The response
       from this tool reports coverage counts and any unresolved rows.

    **Calling this multiple times overwrites the previous report.**
    Make the single call comprehensive.

    **Report output rules** (this content may be rendered into generated
    reports):

    - Never mention internal infrastructure: no local/absolute paths
      (``/workspace/...``), no agent names, no sandbox/orchestrator/
      tooling references, no system prompts, no model-internal errors.
      Never leak internal identifiers (proxy request IDs, internal
      vulnerability report IDs, or any system-generated IDs) into any
      field.
    - Tone: formal, third-person, objective, concise. This is a
      consultant deliverable, not an engineering log.
    - Each section has a specific role:

        - ``executive_summary`` — for non-technical leadership. Risk
          posture, business impact (data exposure / compliance /
          reputation), notable criticals, overarching remediation
          theme.
        - ``methodology`` — frameworks followed (OWASP WSTG, PTES,
          OSSTMM, NIST), engagement type (black/gray/white box), scope
          and constraints, categories of testing performed. **No**
          internal execution detail.
        - ``technical_analysis`` — consolidated findings overview with
          severity model and systemic root causes. Reference individual
          vuln reports for repro steps; don't duplicate raw evidence.
        - ``recommendations`` — prioritized actions grouped by urgency
          (Immediate / Short-term / Medium-term), each with concrete
          remediation steps. End with retest/validation guidance.

    - **Formatting — use markdown in every field.** These fields may be
      rendered into generated reports, so structure them clearly: lead
      each section with a short ``# Heading``, use ``**bold**`` for labels/emphasis,
      ``inline code`` for identifiers/paths/parameters, bullet or
      numbered lists for enumerations, and fenced code blocks
      (```` ```language ````) for any code/payload excerpts. Never emit
      one flat wall of prose or leave code unformatted.
    - If **zero** vulnerabilities were found, say so plainly and
      characterize the posture positively; ``technical_analysis`` should
      summarize the areas tested and confirm no issues, and
      ``recommendations`` should focus on general hardening.

    Example (abbreviated — mirror this structure, not the wording)::

        executive_summary:
            # Executive Summary

            An external assessment of the **Acme Customer Portal**
            identified multiple weaknesses that could lead to
            unauthorized access to customer data.

            **Overall risk posture:** Elevated.

            **Key findings**
            - Confirmed SSRF in a URL-preview feature reaching internal
              network ranges.
            - Broken tenant isolation enabling cross-tenant data access.

            **Business impact**
            - Potential exposure of customer records across tenants.

        methodology:
            # Methodology

            Conducted per the **OWASP WSTG**.

            **Engagement type:** Gray-box external test.
            **Scope:** `https://app.acme.example`, `.../api/v1/`.

            **Activities:** recon, authn/session review, authorization
            and tenant-isolation testing, input/SSRF testing.

        technical_analysis:
            # Technical Analysis

            **Severity model** reflects exploitability x impact.

            1. **SSRF in URL preview** (Critical) — insufficient
               destination validation; reaches link-local addresses.
            2. **Broken tenant isolation** (High) — object identifiers
               accepted without ownership checks.

            **Systemic themes:** authorization enforced inconsistently;
            no deny-by-default egress policy.

        recommendations:
            # Recommendations

            **Immediate**
            1. Remediate SSRF: enforce a destination allowlist,
               deny-by-default, re-validate on every redirect hop.

            **Short-term**
            2. Centralize authorization with deny-by-default middleware.

            **Retest & validation:** re-test immediate items to confirm
            SSRF and tenant-isolation controls hold.

    Args:
        executive_summary: Business-level summary for leadership.
        methodology: Frameworks, scope, and approach.
        technical_analysis: Consolidated findings + systemic themes.
        recommendations: Prioritized, actionable remediation.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    parent_id = inner.get("parent_id")
    if coordinator is not None and parent_id is None and me is not None:
        active_agents = await coordinator.active_agents_except(me)
        if active_agents and coordinator.reserve_stopped:
            active_agents = []
    else:
        active_agents = []

    if active_agents:
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                "error": (
                    "Cannot finish scan while child agents are still active. "
                    "Wait for completion, send them finish instructions, or stop them first"
                ),
                "active_agents": active_agents,
            },
            ensure_ascii=False,
            default=str,
        )

    # Jev filing guard (semantic + under-filing aware): catch vulnerabilities described
    # in the write-up but not filed as reports, INCLUDING when some were filed — the
    # describe-don't-file failure the regex heuristic in _do_finish misses (it reads
    # phrasing and only fires on zero-filed). Fail-safe: blocks only on a confident
    # verdict; the regex guard stays as the fallback when Jev is off. Root agent only.
    if parent_id is None:
        from strix.report import jev_filing

        if jev_filing.jev_enabled():
            from strix.report.state import get_global_report_state

            report_state = get_global_report_state()
            if report_state is not None:
                filed = report_state.vulnerability_reports
                filed_titles = [str(r.get("title") or "") for r in filed]
                write_up = "\n\n".join(
                    t for t in (executive_summary, technical_analysis, recommendations) if t
                )
                verdict = await jev_filing.jev_claims_unfiled_findings(write_up, filed_titles)
                if verdict and verdict.get("claims_unfiled"):
                    logger.warning(
                        "finish_scan blocked by Jev filing guard (confidence %.2f): write-up "
                        "describes findings not among %d filed report(s)",
                        verdict.get("confidence", 0.0),
                        len(filed_titles),
                    )
                    return json.dumps(
                        {
                            "success": False,
                            "error": "Findings described in the write-up but not all were filed",
                            "message": (
                                "Your write-up describes one or more vulnerabilities that were NOT "
                                "filed via create_vulnerability_report. A finding is ONLY recorded "
                                "when filed (one call per finding, with its code_locations and "
                                "evidence) — the executive summary / remediation text is not a "
                                "substitute. File each described-but-unfiled vulnerability, then "
                                "call finish_scan again. If a described item is not actually a "
                                "finding, remove it from the write-up."
                            ),
                        },
                        ensure_ascii=False,
                        default=str,
                    )

    result = await asyncio.to_thread(
        _do_finish,
        parent_id=parent_id,
        executive_summary=executive_summary,
        methodology=methodology,
        technical_analysis=technical_analysis,
        recommendations=recommendations,
        agent_graph=await coordinator.snapshot() if coordinator is not None else {},
    )
    if (
        result.get("success")
        and result.get("scan_completed")
        and coordinator is not None
        and isinstance(me, str)
    ):
        await coordinator.set_status(me, "completed")
    return json.dumps(result, ensure_ascii=False, default=str)
