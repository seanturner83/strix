import contextlib
import re
from pathlib import PurePosixPath
from typing import Any

from strix.tools.registry import register_tool


_CVSS_FIELDS = (
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality",
    "integrity",
    "availability",
)


def parse_cvss_xml(xml_str: str) -> dict[str, str] | None:
    if not xml_str or not xml_str.strip():
        return None
    result = {}
    for field in _CVSS_FIELDS:
        match = re.search(rf"<{field}>(.*?)</{field}>", xml_str, re.DOTALL)
        if match:
            result[field] = match.group(1).strip()
    return result if result else None


def parse_code_locations_xml(xml_str: str) -> list[dict[str, Any]] | None:
    if not xml_str or not xml_str.strip():
        return None
    locations = []
    for loc_match in re.finditer(r"<location>(.*?)</location>", xml_str, re.DOTALL):
        loc: dict[str, Any] = {}
        loc_content = loc_match.group(1)
        for field in (
            "file",
            "start_line",
            "end_line",
            "snippet",
            "label",
            "fix_before",
            "fix_after",
        ):
            field_match = re.search(rf"<{field}>(.*?)</{field}>", loc_content, re.DOTALL)
            if field_match:
                raw = field_match.group(1)
                value = (
                    raw.strip("\n")
                    if field in ("snippet", "fix_before", "fix_after")
                    else raw.strip()
                )
                if field in ("start_line", "end_line"):
                    with contextlib.suppress(ValueError, TypeError):
                        loc[field] = int(value)
                elif value:
                    loc[field] = value
        if loc.get("file") and loc.get("start_line") is not None:
            locations.append(loc)
    return locations if locations else None


def _validate_file_path(path: str) -> str | None:
    if not path or not path.strip():
        return "file path cannot be empty"
    p = PurePosixPath(path)
    if p.is_absolute():
        return f"file path must be relative, got absolute: '{path}'"
    if ".." in p.parts:
        return f"file path must not contain '..': '{path}'"
    return None


def _validate_code_locations(locations: list[dict[str, Any]]) -> list[str]:
    errors = []
    for i, loc in enumerate(locations):
        path_err = _validate_file_path(loc.get("file", ""))
        if path_err:
            errors.append(f"code_locations[{i}]: {path_err}")
        start = loc.get("start_line")
        if not isinstance(start, int) or start < 1:
            errors.append(f"code_locations[{i}]: start_line must be a positive integer")
        end = loc.get("end_line")
        if end is None:
            errors.append(f"code_locations[{i}]: end_line is required")
        elif not isinstance(end, int) or end < 1:
            errors.append(f"code_locations[{i}]: end_line must be a positive integer")
        elif isinstance(start, int) and end < start:
            errors.append(f"code_locations[{i}]: end_line ({end}) must be >= start_line ({start})")
    return errors


def _extract_cve(cve: str) -> str:
    match = re.search(r"CVE-\d{4}-\d{4,}", cve)
    return match.group(0) if match else cve.strip()


def _validate_cve(cve: str) -> str | None:
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return f"invalid CVE format: '{cve}' (expected 'CVE-YYYY-NNNNN')"
    return None


def _extract_cwe(cwe: str) -> str:
    match = re.search(r"CWE-\d+", cwe)
    return match.group(0) if match else cwe.strip()


def _validate_cwe(cwe: str) -> str | None:
    if not re.match(r"^CWE-\d+$", cwe):
        return f"invalid CWE format: '{cwe}' (expected 'CWE-NNN')"
    return None


def calculate_cvss_and_severity(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
) -> tuple[float, str, str]:
    try:
        from cvss import CVSS3

        vector = (
            f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/"
            f"PR:{privileges_required}/UI:{user_interaction}/S:{scope}/"
            f"C:{confidentiality}/I:{integrity}/A:{availability}"
        )

        c = CVSS3(vector)
        scores = c.scores()
        severities = c.severities()

        base_score = scores[0]
        base_severity = severities[0]

        severity = base_severity.lower()

    except Exception:
        import logging

        logging.exception("Failed to calculate CVSS")
        return 7.5, "high", ""
    else:
        return base_score, severity, vector


def _validate_required_fields(**kwargs: str | None) -> list[str]:
    validation_errors: list[str] = []

    required_fields = {
        "title": "Title cannot be empty",
        "description": "Description cannot be empty",
        "impact": "Impact cannot be empty",
        "target": "Target cannot be empty",
        "technical_analysis": "Technical analysis cannot be empty",
        "poc_description": "PoC description cannot be empty",
        "poc_script_code": "PoC script/code is REQUIRED - provide the actual exploit/payload",
        "remediation_steps": "Remediation steps cannot be empty",
    }

    for field_name, error_msg in required_fields.items():
        value = kwargs.get(field_name)
        if not value or not str(value).strip():
            validation_errors.append(error_msg)

    return validation_errors


def _validate_cvss_parameters(**kwargs: str) -> list[str]:
    validation_errors: list[str] = []

    cvss_validations = {
        "attack_vector": ["N", "A", "L", "P"],
        "attack_complexity": ["L", "H"],
        "privileges_required": ["N", "L", "H"],
        "user_interaction": ["N", "R"],
        "scope": ["U", "C"],
        "confidentiality": ["N", "L", "H"],
        "integrity": ["N", "L", "H"],
        "availability": ["N", "L", "H"],
    }

    for param_name, valid_values in cvss_validations.items():
        value = kwargs.get(param_name)
        if value not in valid_values:
            validation_errors.append(
                f"Invalid {param_name}: {value}. Must be one of: {valid_values}"
            )

    return validation_errors


_LOCATION_REQUIRED_MSG = (
    "code_locations is REQUIRED for code-based findings and was missing or "
    "empty. ~96% of historical reports landed with no real file:line and were "
    "silently anchored to the synthetic 'SECURITY.md' placeholder, which makes "
    "them un-triageable and un-dismissable. Before resubmitting:\n"
    "  1. Open the affected file(s) and read the actual lines (do NOT guess "
    "line numbers). For Go/TS source use code_graph; for YAML/JSON config, "
    "workflow, or IaC files use structured_query(file, path) — e.g. "
    "structured_query('.github/workflows/ci.yml', 'jobs.build.steps[3].run') "
    "— which returns the exact start_line/end_line for the node; otherwise "
    "read_file.\n"
    "  2. Provide code_locations with <file>, <start_line>, <end_line> for every "
    "place the vulnerability manifests (and fix_before/fix_after where you "
    "propose a fix).\n"
    "\n"
    "DO NOT DROP THIS FINDING. This gate exists to make findings locatable, "
    "NEVER to suppress a real one. If you cannot produce code_locations for "
    "ANY reason — the finding genuinely has no single source line "
    "(black-box/DAST endpoint, cross-cutting architectural property), OR a "
    "locating tool is unavailable/failing (code_graph index missing, "
    "structured_query/read_file erroring), OR you are otherwise blocked — "
    "RESUBMIT THE SAME FINDING with "
    "location_justification=\"<one sentence: why no file:line — name the "
    "blocker, e.g. 'code_graph index unavailable for this Go target'>\". "
    "The finding is then accepted and recorded. Abandoning a real "
    "vulnerability because you could not line-locate it is the worst "
    "outcome and is never correct. The justification is only to stop the "
    "lazy path of skipping location on a normal, locatable finding."
)


def _looks_like_url(s: str | None) -> bool:
    """True only for a genuine network locator (URL / host:port / scheme://),
    NOT a file path. The endpoint exemption must not fire just because the
    field is non-empty: agents were observed satisfying the location gate by
    stuffing source FILE PATHS into `endpoint` (e.g.
    'internal/nats/client.go') — which is exactly the locationless finding we
    want to reject. A real runtime endpoint has a scheme, a host:port, or a
    leading '/' route on a hostful target — never a *.go / *.py / dotted file.
    """
    if not s or not s.strip():
        return False
    v = s.strip().lower()
    if v.startswith(("http://", "https://", "ws://", "wss://", "grpc://", "tcp://", "nats://")):
        return True
    # bare host:port (api.foo:8080) or host with a route (foo.com/x) — require
    # a dot-bearing host token before any '/' and reject obvious file paths.
    first = v.split("/", 1)[0]
    if ":" in first and not first.endswith((".go", ".py", ".ts", ".js", ".rs", ".java", ".rb")):
        host = first.split(":", 1)[0]
        if "." in host or host in ("localhost",):
            return True
    return False


def _looks_like_runtime_target(target: str | None, endpoint: str | None) -> bool:
    """A finding is runtime/black-box (legitimately location-less) when it has
    a genuine network endpoint, or its target is a URL rather than a repo path.
    A file path in `endpoint` does NOT count — see _looks_like_url."""
    return _looks_like_url(endpoint) or _looks_like_url(target)


@register_tool(sandbox_execution=False)
def create_vulnerability_report(  # noqa: PLR0912
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    cvss_breakdown: str,
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: str | None = None,
    location_justification: str | None = None,
) -> dict[str, Any]:
    validation_errors = _validate_required_fields(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
    )

    parsed_cvss = parse_cvss_xml(cvss_breakdown)
    if not parsed_cvss:
        validation_errors.append("cvss: could not parse CVSS breakdown XML")
    else:
        validation_errors.extend(_validate_cvss_parameters(**parsed_cvss))

    parsed_locations = parse_code_locations_xml(code_locations) if code_locations else None

    if parsed_locations:
        validation_errors.extend(_validate_code_locations(parsed_locations))
    elif not _looks_like_runtime_target(target, endpoint) and not (
        location_justification and location_justification.strip()
    ):
        # Location enforcement (SEC-7xxx): a code finding with no resolvable
        # code_locations and no explicit justified exemption is rejected and
        # bounced back to the agent to locate. Runtime/black-box findings
        # (endpoint set, or URL target) are auto-exempt — their location is
        # the endpoint, not a file. The exemption (location_justification) is
        # logged on the report so synthetic-anchored findings are an explicit,
        # auditable choice rather than the silent default they used to be.
        validation_errors.append(_LOCATION_REQUIRED_MSG)
    if cve:
        cve = _extract_cve(cve)
        cve_err = _validate_cve(cve)
        if cve_err:
            validation_errors.append(cve_err)
    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            validation_errors.append(cwe_err)

    if validation_errors:
        return {"success": False, "message": "Validation failed", "errors": validation_errors}

    assert parsed_cvss is not None
    cvss_score, severity, cvss_vector = calculate_cvss_and_severity(**parsed_cvss)

    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            from strix.llm.dedupe import check_duplicate

            existing_reports = tracer.get_existing_vulnerabilities()

            candidate = {
                "title": title,
                "description": description,
                "impact": impact,
                "target": target,
                "technical_analysis": technical_analysis,
                "poc_description": poc_description,
                "poc_script_code": poc_script_code,
                "endpoint": endpoint,
                "method": method,
            }

            dedupe_result = check_duplicate(candidate, existing_reports)

            if dedupe_result.get("is_duplicate"):
                duplicate_id = dedupe_result.get("duplicate_id", "")

                duplicate_title = ""
                for report in existing_reports:
                    if report.get("id") == duplicate_id:
                        duplicate_title = report.get("title", "Unknown")
                        break

                return {
                    "success": False,
                    "message": (
                        f"Potential duplicate of '{duplicate_title}' "
                        f"(id={duplicate_id[:8]}...). Do not re-report the same vulnerability."
                    ),
                    "duplicate_of": duplicate_id,
                    "duplicate_title": duplicate_title,
                    "confidence": dedupe_result.get("confidence", 0.0),
                    "reason": dedupe_result.get("reason", ""),
                }

            report_id = tracer.add_vulnerability_report(
                title=title,
                description=description,
                severity=severity,
                impact=impact,
                target=target,
                technical_analysis=technical_analysis,
                poc_description=poc_description,
                poc_script_code=poc_script_code,
                remediation_steps=remediation_steps,
                cvss=cvss_score,
                cvss_breakdown=parsed_cvss,
                endpoint=endpoint,
                method=method,
                cve=cve,
                cwe=cwe,
                code_locations=parsed_locations,
                location_justification=location_justification,
            )

            return {
                "success": True,
                "message": f"Vulnerability report '{title}' created successfully",
                "report_id": report_id,
                "severity": severity,
                "cvss_score": cvss_score,
            }

        import logging

        logging.warning("Current tracer not available - vulnerability report not stored")

    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to create vulnerability report: {e!s}"}
    else:
        return {
            "success": True,
            "message": f"Vulnerability report '{title}' created (not persisted)",
            "warning": "Report could not be persisted - tracer unavailable",
        }


def _prior_finding_locations(run_dir: "Path", report_id: str) -> list[dict[str, Any]] | None:
    """Recover a prior finding's code_locations from the run dir's events.jsonl.

    Rehydration (SEC-6802) drops code_locations (they don't round-trip through
    vulnerabilities.csv/.md), so the in-memory rehydrated report can't tell us
    WHERE the vuln was or its verbatim snippet. But the original
    `finding.created` event recorded the full report incl. code_locations, and
    events.jsonl is carried in the resumable-PR-session bundle. Read it back so
    the retraction guard can re-check the vuln site. Returns None if no
    locations are recoverable (guard then can't verify → caller decides).
    """
    import json as _json

    events = run_dir / "events.jsonl"
    if not events.exists():
        return None
    locations: list[dict[str, Any]] | None = None
    try:
        with events.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or "finding.created" not in line:
                    continue
                try:
                    evt = _json.loads(line)
                except ValueError:
                    continue
                report = (evt.get("payload") or {}).get("report") or {}
                if report.get("id") == report_id and report.get("code_locations"):
                    # Last finding.created for this id wins (re-reports overwrite).
                    locations = report["code_locations"]
    except OSError:
        return None
    return locations


def _vuln_still_present(
    locations: list[dict[str, Any]], workspace_root: str = "/workspace"
) -> tuple[bool, str]:
    """Groundedness guard: is the vulnerable code still in the current tree?

    We check ONLY locations that carry a `fix_before` block — that is the
    verbatim vulnerable code the finding proposed to REPLACE, i.e. the actual
    vuln SITE / sink. Locations with only a `snippet` (no fix_before) are
    informational context per the create_vulnerability_report schema — the
    tainted-data source, surrounding code, or a proposed NEW helper to add —
    and must NOT be checked: that context is frequently unchanged by a fix
    (e.g. the source line stays; the sink is what's hardened), so matching on
    it false-refuses a genuine fix (over-strict → fixed finding stuck forever).

    If the fix_before block is STILL present verbatim in the current file, the
    vuln was NOT fixed → refuse the retraction (otherwise a real finding
    silently vanishes from the gate = fail-OPEN). Cross-file-safe: it checks
    the vuln site, not where the fix lives. Returns (still_present, detail);
    still_present=True => REFUSE. When no fix_before location is checkable
    (deleted file, locationless/DAST finding, or context-only), returns
    (False, "...") = can't disprove the fix, allow — we don't manufacture a
    block from missing data (that's the agent's reason's job, same as pre-guard).
    """
    from pathlib import Path as _Path

    checked = 0
    for loc in locations or []:
        rel = loc.get("file")
        # ONLY the fix-bearing (sink) locations represent the vulnerable code
        # to replace. Skip context/source/addition locations (snippet-only).
        needle = loc.get("fix_before")
        if not rel or not needle or not needle.strip():
            continue
        target = _Path(workspace_root) / rel
        if not target.exists():
            # Vulnerable file deleted entirely → vuln gone. Strong fix signal.
            continue
        checked += 1
        try:
            body = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if needle.strip() in body or needle in body:
            return True, (
                f"the vulnerable code is still present in {rel} "
                f"(unchanged sink: {needle.strip()[:80]!r})"
            )
    if checked == 0:
        return False, "no fix-bearing vulnerable snippet available to re-check"
    return False, "vulnerable code no longer present at the recorded sink location(s)"


@register_tool(sandbox_execution=False)
def retract_vulnerability_report(report_id: str, reason: str) -> dict[str, Any]:
    """Remove a previously-reported finding that no longer applies to the
    current code — use this when a resumed scan confirms a prior finding has
    been FIXED by a new push.

    Resumable-PR-session context: when you --resume a session, the findings you
    reported on earlier pushes are restored into your finding set. If this
    push's diff genuinely fixes one of them, you MUST retract it here so it is
    dropped from the cumulative report. Without an explicit retraction the
    finding re-emits on every push and the pull request can never pass the
    security gate even after the bug is fixed.

    Only retract a finding you have VERIFIED is resolved by re-reading the
    current code (e.g. a hardcoded secret now read from the environment, a
    missing auth check now present, an injection sink now parameterised). Do
    NOT retract a finding that is merely hard to reach or that you have not
    re-confirmed against the current code — when in doubt, keep it.

    Args:
        report_id: the id of the finding to retract (e.g. "vuln-0001").
        reason: a concrete justification grounded in the current code —
            cite WHAT changed and WHERE (file:line) that resolves it.
            Required; an empty reason is rejected.
    """
    if not report_id or not report_id.strip():
        return {"success": False, "message": "report_id is required"}
    if not reason or not reason.strip():
        return {
            "success": False,
            "message": (
                "reason is required — cite what changed in the current code "
                "(file:line) that resolves this finding. Do not retract without "
                "re-verifying the fix."
            ),
        }

    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            import logging

            logging.warning("Current tracer not available - retraction not persisted")
            return {
                "success": False,
                "message": "Report could not be retracted - tracer unavailable",
            }

        # Groundedness guard (resumable-PR-session): do NOT trust the agent's
        # claim that the finding is fixed. Recover the finding's original
        # code_locations from the run dir's events.jsonl and check whether the
        # vulnerable code (fix_before / snippet) is STILL VERBATIM in the
        # current tree. If it is, the vuln was not actually fixed — refuse the
        # retraction so a real finding can't be silently dropped from the gate
        # (fail-OPEN). Cross-file-safe: it checks the vuln SITE, not where a fix
        # lives. Best-effort: if the run dir / events / snippet are unavailable
        # we cannot disprove the fix and fall through to allow (same signal as
        # before the guard existed — we don't fabricate a block from missing
        # data). Errors here must never crash the retract path.
        try:
            import os as _os

            workspace_root = _os.environ.get("STRIX_WORKSPACE_ROOT", "/workspace")
            run_dir = tracer._compute_run_dir_if_exists()  # noqa: SLF001
            if run_dir is not None:
                locations = _prior_finding_locations(run_dir, report_id.strip())
                if locations:
                    still_present, detail = _vuln_still_present(locations, workspace_root)
                    if still_present:
                        return {
                            "success": False,
                            "retracted": False,
                            "message": (
                                f"Retraction REFUSED for {report_id}: {detail}. "
                                "Re-read the file — if the vulnerability is genuinely "
                                "resolved the original vulnerable code must no longer be "
                                "present at that location. If you believe this is a "
                                "false block, the finding is NOT fixed and must remain."
                            ),
                            "guard": "vuln_still_present",
                        }
        except Exception:  # noqa: BLE001 — guard must never break the tool
            import logging

            logging.warning("retract groundedness guard errored; allowing retraction", exc_info=True)

        result = tracer.retract_vulnerability_report(report_id.strip(), reason.strip())
        if result.get("retracted"):
            result["message"] = (
                f"Finding {report_id} retracted from the cumulative report "
                f"({result.get('remaining', '?')} finding(s) remain)."
            )
        else:
            result["message"] = (
                f"Finding {report_id} was not in the current set (already retracted "
                f"or never reported) — nothing to do."
            )
        return result
    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to retract finding: {e!s}"}
