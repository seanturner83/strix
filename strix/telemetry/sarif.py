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

# CWE → STRIDE leg mapping for SARIF result tagging. Maps the most-common
# CWEs Strix surfaces to one or more STRIDE legs (Spoofing / Tampering /
# Repudiation / Information disclosure / Denial of service / Elevation of
# privilege). Tags become `stride:<leg>` on each result so consumers
# (GHAS Security tab, ASPM dashboards) can group by threat-model leg.
#
# Where a CWE could plausibly map to multiple legs, list the dominant first
# (the same convention strix-triage's vuln_class → STRIDE map uses).
# Anything without an entry falls back to the dominant-T+I default that
# matches strix-triage's DEFAULT_STRIDE_LEGS.
_CWE_TO_STRIDE: dict[str, tuple[str, ...]] = {
    # Spoofing — authentication / identity
    "287": ("S",),                        # Improper Authentication
    "290": ("S",),                        # Authentication Bypass by Spoofing
    "294": ("S",),                        # Authentication Bypass by Capture-replay
    "306": ("S", "E"),                    # Missing Authentication for Critical Function
    "345": ("S", "T"),                    # Insufficient Verification of Data Authenticity
    "346": ("S",),                        # Origin Validation Error
    "352": ("T", "S"),                    # CSRF
    "384": ("S",),                        # Session Fixation
    "521": ("S",),                        # Weak Password Requirements
    "613": ("S",),                        # Insufficient Session Expiration
    "640": ("S",),                        # Weak Password Recovery
    # Tampering — integrity
    "20":  ("T",),                        # Improper Input Validation
    "73":  ("T", "I"),                    # External Control of File Name or Path
    "78":  ("T", "E"),                    # OS Command Injection
    "79":  ("T", "I"),                    # XSS
    "89":  ("T",),                        # SQL Injection
    "91":  ("T",),                        # XML Injection
    "94":  ("T", "E"),                    # Code Injection
    "434": ("T",),                        # Unrestricted File Upload
    "502": ("T", "E"),                    # Deserialization of Untrusted Data
    "915": ("E", "T"),                    # Mass Assignment
    "918": ("T", "I"),                    # SSRF
    "1336": ("T", "E"),                   # Server-Side Template Injection
    # Repudiation — audit
    "117": ("R",),                        # Improper Output Neutralization for Logs
    "223": ("R",),                        # Omission of Security-relevant Information
    "778": ("R",),                        # Insufficient Logging
    # Information disclosure — confidentiality
    "200": ("I",),                        # Exposure of Sensitive Info
    "201": ("I",),                        # Insertion of Sensitive Info into Sent Data
    "209": ("I",),                        # Sensitive Info in Error Message
    "256": ("I",),                        # Plaintext Storage of Password
    "311": ("I",),                        # Missing Encryption of Sensitive Data
    "319": ("I",),                        # Cleartext Transmission
    "327": ("I",),                        # Use of Broken/Risky Crypto
    "328": ("I",),                        # Use of Weak Hash
    "522": ("I",),                        # Insufficiently Protected Credentials
    "525": ("I",),                        # Web-Browser Cache of Sensitive Info
    "532": ("I",),                        # Insertion of Sensitive Info into Log
    "538": ("I",),                        # File / Directory Info Exposure
    "598": ("I",),                        # Sensitive Info in URL Query
    # Denial of service — availability
    "400": ("D",),                        # Uncontrolled Resource Consumption
    "770": ("D",),                        # Allocation of Resources Without Limits
    "1333": ("D",),                       # Inefficient Regex / ReDoS
    # Elevation of privilege — authorization
    "22":  ("T", "I"),                    # Path Traversal
    "269": ("E",),                        # Improper Privilege Management
    "284": ("E",),                        # Improper Access Control
    "285": ("E",),                        # Improper Authorization
    "639": ("E",),                        # Authorization Bypass via User-controlled Key (BOLA/IDOR)
    "732": ("E",),                        # Incorrect Permission Assignment for Critical Resource
    "863": ("E",),                        # Incorrect Authorization
    "1220": ("E",),                       # Insufficient Granularity of Access Control
    # XXE / XML — multi-leg
    "611": ("I", "T"),                    # XXE
    "918_alt": ("T", "I"),                # placeholder mirror
}

# Default for unmapped CWEs / no-CWE findings. Conservative: tampering +
# information-disclosure is the most-common shape for an unclassified bug.
_DEFAULT_STRIDE_LEGS: tuple[str, ...] = ("T", "I")


def _stride_legs_for_cwe(cwe_str: str | None) -> tuple[str, ...]:
    """Map a CWE id (raw, eg 'CWE-306', '306', 'cwe 306') to STRIDE legs.

    Returns the default tuple for no-CWE / unrecognised CWE so every result
    gets at least one leg tag — useful for downstream coverage reports.
    """
    if not cwe_str:
        return _DEFAULT_STRIDE_LEGS
    digits = "".join(c for c in str(cwe_str) if c.isdigit())
    if not digits:
        return _DEFAULT_STRIDE_LEGS
    return _CWE_TO_STRIDE.get(digits, _DEFAULT_STRIDE_LEGS)


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
        # STRIDE leg tags from CWE → STRIDE mapping. Always at least one
        # (default T+I for unmapped CWEs) so downstream coverage reports
        # don't have gaps. Tags appear as `stride:S`, `stride:T` etc.
        stride_tags = [f"stride:{leg}"
                       for leg in _stride_legs_for_cwe(report.get("cwe"))]
        if rid.startswith("CWE-"):
            rule["properties"]["tags"] = ["security", rid, *stride_tags]
            rule["helpUri"] = (
                f"https://cwe.mitre.org/data/definitions/{rid.removeprefix('CWE-')}.html"
            )
        else:
            rule["properties"]["tags"] = ["security", *stride_tags]
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

    # Per-result STRIDE tags — duplicated from the rule definition for
    # consumers that filter on result.properties.tags rather than walking
    # back to rules[].
    stride_tags = [f"stride:{leg}"
                   for leg in _stride_legs_for_cwe(report.get("cwe"))]
    result["properties"] = {
        "security-severity": _security_severity(report),
        "tags": stride_tags,
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
