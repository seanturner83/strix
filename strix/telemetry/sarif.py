"""SARIF 2.1.0 output for Strix vulnerability reports.

Builds a GitHub code-scanning compatible SARIF document from Strix findings
so CI pipelines can upload findings via ``github/codeql-action/upload-sarif``,
ingest into ASPM platforms, or normalise across scanners.

Schema: SARIF 2.1.0 (OASIS). The output is validated against the official
schema at https://json.schemastore.org/sarif-2.1.0.json in tests.

Integration points:
  - ``write_sarif_report`` writes a SARIF document to disk (CLI-driven,
    invoked by ``--sarif-output`` on the Strix entrypoint).
  - The module is also imported by ``strix.telemetry.tracer`` to emit a
    ``findings.sarif`` sidecar alongside the existing CSV + markdown
    artefacts on every run. Failure to emit SARIF never blocks CSV + MD.

Design notes:
  * Rules are keyed on CWE (``id = CWE-NNN``), falling back to CVE, then
    to finding-id, then to a title slug. CWE values are normalised from
    Strix output variants (``CWE-306``, ``cwe: 306``, ``306``) to the
    canonical ``CWE-NNN`` form so dedup works across runs.
  * SARIF only has three levels (error / warning / note). Strix's five
    severities collapse into them. The raw severity label and CVSS score
    survive in ``result.properties.strix`` for downstream tools that can
    distinguish CRITICAL vs HIGH.
  * GitHub code-scanning uses ``rule.properties['security-severity']``
    (a 0.0-10.0 string) to rank alerts. We populate it from CVSS when
    available, otherwise from a conservative label → score map.
  * File locations must be repo-relative POSIX paths. Paths that look
    like URIs, absolute paths, or traversal patterns are rejected rather
    than emitted as invalid code-scanning alerts.
  * Findings without safe locations still appear in the SARIF output as
    a summary in ``run.properties.locationlessFindings`` rather than
    getting dropped silently.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path, PurePosixPath
from typing import Any, cast


logger = logging.getLogger(__name__)


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Strix"
TOOL_INFORMATION_URI = "https://strix.ai"


# SARIF only has three result levels; Strix's five severities collapse here.
# Original label survives in ``result.properties.strix.severity``.
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}

# GitHub code-scanning reads ``rule.properties['security-severity']`` (a
# 0.0-10.0 string) to rank alerts. We prefer CVSS from the finding; absent
# that we fall back to a conservative label → score map.
_SEVERITY_TO_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
    "informational": "1.0",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_sarif_report(
    vulnerability_reports: list[dict[str, Any]],
    *,
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Return a SARIF 2.1.0 document for findings with safe source locations."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    locationless_findings: list[dict[str, Any]] = []
    dropped_unsafe_location_findings: list[dict[str, Any]] = []

    for report in vulnerability_reports:
        locations, dropped_location_count = _build_locations(
            report.get("code_locations")
        )
        if not locations:
            # Locationless findings survive as a run-properties summary rather
            # than invalid code-scanning alerts. Some SARIF consumers would
            # accept a result without a location, but GitHub code-scanning's
            # UI handling of locationless alerts is unreliable — the summary
            # approach is how reviewers actually see these findings.
            locationless_findings.append(_locationless_summary(report))
            continue

        if dropped_location_count:
            dropped_unsafe_location_findings.append(
                _dropped_location_summary(report, dropped_location_count)
            )

        rule_id = _rule_id(report)
        rules_by_id.setdefault(rule_id, _build_rule(rule_id, report))
        results.append(_build_result(rule_id, report, locations))

    driver: dict[str, Any] = {
        "name": TOOL_NAME,
        "informationUri": TOOL_INFORMATION_URI,
        "rules": list(rules_by_id.values()),
    }
    if tool_version:
        driver["version"] = tool_version

    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
    }

    run_properties: dict[str, Any] = {}
    if locationless_findings:
        run_properties["locationlessFindingCount"] = len(locationless_findings)
        run_properties["locationlessFindings"] = locationless_findings
    if dropped_unsafe_location_findings:
        run_properties["droppedUnsafeLocationCount"] = sum(
            finding["droppedLocationCount"]
            for finding in dropped_unsafe_location_findings
        )
        run_properties["droppedUnsafeLocationFindings"] = (
            dropped_unsafe_location_findings
        )
    if run_properties:
        run["properties"] = run_properties

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [run],
    }


def write_sarif_report(
    output_path: Path,
    vulnerability_reports: list[dict[str, Any]],
    *,
    tool_version: str | None = None,
) -> None:
    """Write a SARIF report to disk, creating parent directories first."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    sarif = build_sarif_report(vulnerability_reports, tool_version=tool_version)
    with output_path.open("w", encoding="utf-8") as sarif_file:
        json.dump(sarif, sarif_file, ensure_ascii=False, indent=2)
        sarif_file.write("\n")


# ---------------------------------------------------------------------------
# Backwards-compatible aliases
# ---------------------------------------------------------------------------
#
# ``build_sarif_document`` / ``write_sarif`` are the names our tracer-hook
# integration imported before the module was restructured around #477. Keep
# them as thin aliases so internal callers don't break.


def build_sarif_document(
    reports: list[dict[str, Any]],
    *,
    tool_version: str | None = None,
) -> dict[str, Any]:
    return build_sarif_report(reports, tool_version=tool_version)


def write_sarif(
    run_dir: Path,
    reports: list[dict[str, Any]],
    *,
    tool_version: str | None = None,
    filename: str = "findings.sarif",
) -> Path:
    """Write ``findings.sarif`` alongside existing outputs in ``run_dir``.

    Returns the output path. This is the tracer-hook entry point: SARIF
    writing must never break the CSV + markdown path, so the caller wraps
    it in try/except.
    """
    out = run_dir / filename
    write_sarif_report(out, reports, tool_version=tool_version)
    logger.info(
        "Wrote SARIF 2.1.0 report: %s (%d results)",
        out,
        len(reports),
    )
    return out


# ---------------------------------------------------------------------------
# Rule + result builders
# ---------------------------------------------------------------------------


def _build_rule(rule_id: str, report: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF rule descriptor from a Strix finding."""
    title = _string_value(report.get("title")) or rule_id
    full_description = _string_value(report.get("description")) or title

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": _rule_name(rule_id, title),
        "shortDescription": {"text": title},
        "fullDescription": {"text": full_description},
        "defaultConfiguration": {"level": _sarif_level(report.get("severity"))},
        "help": {"text": _help_text(report, full_description)},
    }

    properties: dict[str, Any] = {
        "security-severity": _security_severity(report),
    }
    tags = _rule_tags(rule_id, report)
    if tags:
        properties["tags"] = tags
    rule["properties"] = properties

    help_uri = _help_uri_for(rule_id)
    if help_uri:
        rule["helpUri"] = help_uri

    return rule


def _build_result(
    rule_id: str,
    report: dict[str, Any],
    locations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build one SARIF result using validated physical locations."""
    title = _string_value(report.get("title")) or rule_id
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _sarif_level(report.get("severity")),
        "message": {"text": title},
    }
    if locations:
        result["locations"] = locations
    result["properties"] = _result_properties(report)
    return result


def _result_properties(report: dict[str, Any]) -> dict[str, Any]:
    """Strix-specific metadata for downstream consumers.

    The top-level ``security-severity`` matches GitHub code-scanning's
    expected property. Strix-specific fields are namespaced under
    ``strix`` so generic SARIF consumers don't see them by default.
    """
    properties: dict[str, Any] = {
        "security-severity": _security_severity(report),
    }

    strix: dict[str, Any] = {}
    for key in (
        "id",
        "severity",
        "cvss",
        "timestamp",
        "target",
        "endpoint",
        "method",
        "cve",
        "cwe",
        "impact",
        "technical_analysis",
        "remediation_steps",
    ):
        value = report.get(key)
        if value not in (None, ""):
            strix[key] = value

    # PoC goes in a nested object so consumers that render ``strix.*`` into
    # UI don't accidentally display exploitation payloads to a wide audience.
    poc_description = _string_value(report.get("poc_description"))
    poc_script = _string_value(report.get("poc_script_code"))
    if poc_description or poc_script:
        poc: dict[str, Any] = {}
        if poc_description:
            poc["description"] = poc_description
        if poc_script:
            poc["script"] = poc_script
        strix["poc"] = poc

    if strix:
        properties["strix"] = strix

    return properties


# ---------------------------------------------------------------------------
# Location handling
# ---------------------------------------------------------------------------


def _build_locations(raw_locations: Any) -> tuple[list[dict[str, Any]], int]:
    """Return SARIF locations and a count of dropped unsafe locations."""
    if not isinstance(raw_locations, list):
        return [], 0

    raw_locations_list = cast("list[Any]", raw_locations)  # type: ignore[redundant-cast]
    locations: list[dict[str, Any]] = []
    dropped_location_count = 0
    for raw_location in raw_locations_list:
        if not isinstance(raw_location, dict):
            dropped_location_count += 1
            continue

        location = cast("dict[str, Any]", raw_location)
        file_path = _string_value(location.get("file"))
        start_line = location.get("start_line")
        end_line = location.get("end_line")
        if (
            not file_path
            or type(start_line) is not int
            or start_line < 1
        ):
            dropped_location_count += 1
            continue
        uri = _sarif_uri(file_path)
        if uri is None:
            dropped_location_count += 1
            continue

        region: dict[str, Any] = {"startLine": start_line}
        if type(end_line) is int and end_line >= start_line:
            region["endLine"] = end_line

        snippet = _string_value(location.get("snippet"))
        if snippet:
            region["snippet"] = {"text": snippet}

        physical_location: dict[str, Any] = {
            "artifactLocation": {"uri": uri},
            "region": region,
        }
        entry: dict[str, Any] = {"physicalLocation": physical_location}

        label = _string_value(location.get("label"))
        if label:
            entry["message"] = {"text": label}

        locations.append(entry)

    return locations, dropped_location_count


def _sarif_uri(file_path: str) -> str | None:
    """Return a safe repo-relative SARIF URI, or None for unsafe paths."""
    uri = PurePosixPath(file_path.replace("\\", "/")).as_posix()
    parts = PurePosixPath(uri).parts
    if not uri or uri.startswith("/") or not parts:
        return None
    if ":" in parts[0] or any(part == ".." for part in parts):
        return None
    return uri


# ---------------------------------------------------------------------------
# Rule ID resolution + CWE normalisation
# ---------------------------------------------------------------------------


def _rule_id(report: dict[str, Any]) -> str:
    """Choose a stable SARIF rule id, preferring CWE → CVE → finding-id → slug.

    CWE values are normalised from Strix output variants (``CWE-306``,
    ``cwe: 306``, ``306``) to the canonical ``CWE-NNN`` form. Without
    normalisation, the same weakness across runs dedups to separate rules.
    """
    cwe = _string_value(report.get("cwe"))
    if cwe:
        normalised = _normalise_cwe(cwe)
        if normalised:
            return normalised

    cve = _string_value(report.get("cve"))
    if cve:
        return cve

    finding_id = _string_value(report.get("id"))
    if finding_id:
        return finding_id

    title = _string_value(report.get("title")) or "strix-finding"
    return _slugify(title)


def _normalise_cwe(value: str) -> str | None:
    """``CWE-306``, ``cwe:306``, ``306`` → ``CWE-306``."""
    digits = "".join(c for c in value if c.isdigit())
    if not digits:
        return None
    return f"CWE-{digits}"


def _rule_name(rule_id: str, title: str) -> str:
    """SARIF rule.name must be a free-form string; prefer the finding title
    where available, fall back to a snake_case'd form of the rule id."""
    return title or rule_id.replace("-", "_")


def _rule_tags(rule_id: str, report: dict[str, Any]) -> list[str]:
    tags: list[str] = ["security"]
    if rule_id.startswith("CWE-"):
        tags.append(rule_id)
    cve = _string_value(report.get("cve"))
    if cve and cve not in tags:
        tags.append(cve)
    return tags


def _help_uri_for(rule_id: str) -> str | None:
    if rule_id.startswith("CWE-"):
        return f"https://cwe.mitre.org/data/definitions/{rule_id.removeprefix('CWE-')}.html"
    return None


# ---------------------------------------------------------------------------
# Severity + help text
# ---------------------------------------------------------------------------


def _sarif_level(severity: Any) -> str:
    """Map Strix severity labels to SARIF result levels."""
    normalised = (_string_value(severity) or "").lower()
    return _SEVERITY_TO_LEVEL.get(normalised, "note")


def _security_severity(report: dict[str, Any]) -> str:
    """GitHub-compatible ``security-severity`` string in 0.0-10.0.

    Uses CVSS when present, otherwise falls back to the severity label.
    """
    cvss = report.get("cvss")
    if cvss is not None:
        try:
            return f"{float(cvss):.1f}"
        except (TypeError, ValueError):
            pass
    normalised = (_string_value(report.get("severity")) or "info").lower()
    return _SEVERITY_TO_SCORE.get(normalised, "1.0")


def _help_text(report: dict[str, Any], fallback: str) -> str:
    """Assemble SARIF help text from finding details and remediation."""
    sections = [
        _string_value(report.get("description")),
        _string_value(report.get("impact")),
        _string_value(report.get("remediation_steps")),
    ]
    help_text = "\n\n".join(section for section in sections if section)
    return help_text or fallback


# ---------------------------------------------------------------------------
# Summaries for locationless + unsafe-location findings
# ---------------------------------------------------------------------------


def _locationless_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Summarize findings that cannot be emitted as code-scanning alerts."""
    summary: dict[str, Any] = {}
    for key in (
        "id",
        "title",
        "severity",
        "cwe",
        "cve",
        "target",
        "endpoint",
        "method",
    ):
        value = report.get(key)
        if value not in (None, ""):
            summary[key] = value
    return summary


def _dropped_location_summary(
    report: dict[str, Any],
    dropped_location_count: int,
) -> dict[str, Any]:
    """Summarize unsafe locations dropped from a partially emitted finding."""
    summary: dict[str, Any] = {"droppedLocationCount": dropped_location_count}
    for key in ("id", "title"):
        value = report.get(key)
        if value not in (None, ""):
            summary[key] = value
    return summary


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _string_value(value: Any) -> str | None:
    """Return a stripped non-empty string value, or None."""
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _slugify(value: str) -> str:
    """Convert arbitrary finding text into a stable lowercase slug."""
    chars = [char.lower() if char.isalnum() else "-" for char in value]
    slug = "-".join(part for part in "".join(chars).split("-") if part)
    return slug or "strix-finding"
