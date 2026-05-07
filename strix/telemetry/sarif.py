"""SARIF 2.1.0 emitter for Strix vulnerability reports.

Produces a SARIF document alongside the existing vulnerabilities/*.md and
vulnerabilities.csv outputs so CI consumers can upload findings to
`github/codeql-action/upload-sarif` (GitHub code-scanning Security tab),
ASPM platforms, GitLab/Azure Security Dashboards, or any SARIF-consumer.

Schema: SARIF 2.1.0 (OASIS). Validates against
https://json.schemastore.org/sarif-2.1.0.json.

Design choices:
  - Rules keyed on CWE (rule.id = CWE-NNN). Findings without a CWE fall back
    to rule.id = "strix-<severity>" so they still get a rule.
  - SARIF has only three levels (error/warning/note). Strix's original severity
    (CRITICAL/HIGH/MEDIUM/LOW/INFO) is preserved in result.properties.severity
    so consumers can distinguish CRITICAL-vs-HIGH or MEDIUM-vs-LOW downstream.
  - PoC code and detailed remediation live in result.properties.strix (a
    namespaced object) rather than in message.text, so consumers that display
    message.text to a wide audience (e.g. GitHub code-scanning UI) don't leak
    PoCs by default. Consumers that want PoC inclusion read properties.strix.
  - File locations come from report["code_locations"]. If absent, the result
    still emits but without a location (SARIF allows this for scope-wide
    findings such as architectural issues or missing auth frameworks).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Strix severity → SARIF level mapping. SARIF has only three levels, so
# CRITICAL+HIGH collapse to "error" and LOW+INFO collapse to "note". Original
# severity is preserved in result.properties.severity for downstream use.
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# SARIF security-severity is a 0.0-10.0 string; lines up with CVSS base when
# available, otherwise derived from the Strix severity label.
_SEVERITY_TO_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}


def _rule_id_for(report: dict[str, Any]) -> str:
    cwe = (report.get("cwe") or "").strip()
    if cwe:
        # Normalise "CWE-306" / "306" / "cwe 306" → "CWE-306"
        digits = "".join(c for c in cwe if c.isdigit())
        if digits:
            return f"CWE-{digits}"
    severity = (report.get("severity") or "unknown").lower()
    return f"strix-{severity}"


def _security_severity(report: dict[str, Any]) -> str:
    cvss = report.get("cvss")
    if cvss is not None:
        try:
            return f"{float(cvss):.1f}"
        except (TypeError, ValueError):
            pass
    severity = (report.get("severity") or "info").lower()
    return _SEVERITY_TO_SCORE.get(severity, "1.0")


def _level_for(report: dict[str, Any]) -> str:
    severity = (report.get("severity") or "info").lower()
    return _SEVERITY_TO_LEVEL.get(severity, "note")


def _short_description(report: dict[str, Any]) -> str:
    title = (report.get("title") or "").strip()
    return title or f"Strix finding {report.get('id', 'unknown')}"


def _full_description(report: dict[str, Any]) -> str:
    parts: list[str] = []
    if report.get("description"):
        parts.append(str(report["description"]).strip())
    if report.get("impact"):
        parts.append("Impact: " + str(report["impact"]).strip())
    return "\n\n".join(parts) if parts else _short_description(report)


def _help_text(report: dict[str, Any]) -> str:
    """Remediation guidance. Excludes PoC — that lives in properties."""
    return str(report.get("remediation_steps") or "").strip()


def _locations(report: dict[str, Any]) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for loc in report.get("code_locations") or []:
        file_ref = (loc.get("file") or "").strip()
        if not file_ref:
            continue
        region: dict[str, Any] = {}
        if loc.get("start_line") is not None:
            region["startLine"] = int(loc["start_line"])
        if loc.get("end_line") is not None and loc["end_line"] != loc.get("start_line"):
            region["endLine"] = int(loc["end_line"])
        if loc.get("snippet"):
            region["snippet"] = {"text": str(loc["snippet"])}
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": file_ref},
        }
        if region:
            physical["region"] = region
        entry: dict[str, Any] = {"physicalLocation": physical}
        if loc.get("label"):
            entry["message"] = {"text": str(loc["label"])}
        locations.append(entry)
    return locations


def _build_rules(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build deduplicated rule definitions, one per unique rule.id encountered."""
    seen: dict[str, dict[str, Any]] = {}
    for report in reports:
        rid = _rule_id_for(report)
        if rid in seen:
            continue
        rule: dict[str, Any] = {
            "id": rid,
            "name": rid.replace("-", "_"),
            "shortDescription": {"text": _short_description(report)},
            "defaultConfiguration": {"level": _level_for(report)},
            "properties": {
                "security-severity": _security_severity(report),
            },
        }
        help_text = _help_text(report)
        if help_text:
            rule["help"] = {"text": help_text, "markdown": help_text}
        if rid.startswith("CWE-"):
            rule["properties"]["tags"] = ["security", rid]
            rule["helpUri"] = (
                f"https://cwe.mitre.org/data/definitions/{rid.removeprefix('CWE-')}.html"
            )
        else:
            rule["properties"]["tags"] = ["security"]
        seen[rid] = rule
    return list(seen.values())


def _build_result(report: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": _rule_id_for(report),
        "level": _level_for(report),
        "message": {"text": _full_description(report)},
    }
    locations = _locations(report)
    if locations:
        result["locations"] = locations

    # Namespaced properties so downstream consumers can opt in to Strix-specific
    # fields (PoC, CVSS, original severity) without polluting SARIF core.
    strix_props: dict[str, Any] = {
        "vuln_id": report.get("id"),
        "severity": (report.get("severity") or "").upper(),
        "timestamp": report.get("timestamp"),
    }
    if report.get("cvss") is not None:
        strix_props["cvss"] = report["cvss"]
    if report.get("cve"):
        strix_props["cve"] = report["cve"]
    if report.get("cwe"):
        strix_props["cwe"] = report["cwe"]
    if report.get("target"):
        strix_props["target"] = report["target"]
    if report.get("endpoint"):
        strix_props["endpoint"] = report["endpoint"]
    if report.get("method"):
        strix_props["method"] = report["method"]
    if report.get("technical_analysis"):
        strix_props["technical_analysis"] = report["technical_analysis"]
    if report.get("poc_description") or report.get("poc_script_code"):
        strix_props["poc"] = {
            "description": report.get("poc_description"),
            "script": report.get("poc_script_code"),
        }

    result["properties"] = {
        "security-severity": _security_severity(report),
        "strix": strix_props,
    }
    return result


def build_sarif_document(
    reports: list[dict[str, Any]],
    *,
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from Strix vulnerability reports."""
    driver: dict[str, Any] = {
        "name": "Strix",
        "informationUri": "https://github.com/usestrix/strix",
        "rules": _build_rules(reports),
    }
    if tool_version:
        driver["version"] = tool_version

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {"driver": driver},
                "results": [_build_result(r) for r in reports],
            }
        ],
    }


def write_sarif(
    run_dir: Path,
    reports: list[dict[str, Any]],
    *,
    tool_version: str | None = None,
    filename: str = "findings.sarif",
) -> Path:
    """Write findings.sarif alongside existing outputs in run_dir."""
    document = build_sarif_document(reports, tool_version=tool_version)
    out = run_dir / filename
    with out.open("w", encoding="utf-8") as f:
        json.dump(document, f, indent=2, ensure_ascii=False)
    logger.info("Wrote SARIF 2.1.0 report: %s (%d results)", out, len(reports))
    return out
