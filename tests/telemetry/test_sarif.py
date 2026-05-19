"""Tests for strix.telemetry.sarif."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.telemetry.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    build_sarif_document,
    write_sarif,
)


def _base_report(**overrides):
    report = {
        "id": "vuln-0001",
        "title": "Missing authentication on gRPC endpoint",
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-306",
        "timestamp": "2026-05-06T08:30:00Z",
        "description": "The gRPC server registers no auth interceptor.",
        "impact": "Any caller with network reachability can invoke every RPC.",
        "technical_analysis": "server.go:82-99 chains only observability interceptors.",
        "poc_description": "grpcurl -plaintext …",
        "poc_script_code": "grpcurl -plaintext host:9101 list",
        "remediation_steps": "Add an auth interceptor to the chain.",
        "code_locations": [
            {
                "file": "internal/grpc/server.go",
                "start_line": 82,
                "end_line": 99,
                "label": "Interceptor chain assembly",
                "snippet": "grpc.ChainUnaryInterceptor(...)",
            }
        ],
    }
    report.update(overrides)
    return report


def test_document_shape_and_version():
    doc = build_sarif_document([_base_report()], tool_version="0.1.13")
    assert doc["version"] == SARIF_VERSION
    assert doc["$schema"] == SARIF_SCHEMA
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Strix"
    assert run["tool"]["driver"]["version"] == "0.1.13"
    assert run["tool"]["driver"]["informationUri"].startswith("https://github.com/")


def test_rule_id_uses_cwe_when_present():
    doc = build_sarif_document([_base_report(cwe="CWE-306")])
    run = doc["runs"][0]
    assert run["results"][0]["ruleId"] == "CWE-306"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "CWE-306" in rule_ids


def test_rule_id_falls_back_to_strix_severity_without_cwe():
    doc = build_sarif_document([_base_report(cwe=None, severity="high")])
    run = doc["runs"][0]
    assert run["results"][0]["ruleId"] == "strix-high"


def test_severity_to_level_mapping():
    reports = [
        _base_report(id="c", severity="critical"),
        _base_report(id="h", severity="high", cwe=None),
        _base_report(id="m", severity="medium", cwe=None),
        _base_report(id="l", severity="low", cwe=None),
        _base_report(id="i", severity="info", cwe=None),
    ]
    doc = build_sarif_document(reports)
    levels = [r["level"] for r in doc["runs"][0]["results"]]
    assert levels == ["error", "error", "warning", "note", "note"]


def test_security_severity_uses_cvss_when_present():
    doc = build_sarif_document([_base_report(cvss=7.4)])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "7.4"


def test_security_severity_falls_back_to_band_score():
    doc = build_sarif_document([_base_report(cvss=None, severity="medium", cwe=None)])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "5.5"


def test_locations_emitted_from_code_locations():
    doc = build_sarif_document([_base_report()])
    result = doc["runs"][0]["results"][0]
    assert len(result["locations"]) == 1
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "internal/grpc/server.go"
    assert loc["region"]["startLine"] == 82
    assert loc["region"]["endLine"] == 99
    assert loc["region"]["snippet"]["text"].startswith("grpc.ChainUnary")


def test_locations_omitted_when_no_code_locations():
    doc = build_sarif_document([_base_report(code_locations=[])])
    result = doc["runs"][0]["results"][0]
    assert "locations" not in result


def test_poc_lives_in_properties_not_message():
    """PoC must not land in message.text (which consumers display widely)."""
    doc = build_sarif_document([_base_report()])
    result = doc["runs"][0]["results"][0]
    assert "grpcurl" not in result["message"]["text"]
    assert result["properties"]["strix"]["poc"]["script"].startswith("grpcurl")


def test_strix_namespaced_properties():
    doc = build_sarif_document([_base_report()])
    props = doc["runs"][0]["results"][0]["properties"]["strix"]
    assert props["vuln_id"] == "vuln-0001"
    assert props["severity"] == "CRITICAL"
    assert props["cvss"] == 9.8
    assert props["cwe"] == "CWE-306"


def test_cwe_helpuri():
    doc = build_sarif_document([_base_report(cwe="CWE-306")])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"] == "https://cwe.mitre.org/data/definitions/306.html"


def test_rule_deduplication_across_same_cwe():
    doc = build_sarif_document(
        [
            _base_report(id="vuln-0001", cwe="CWE-306"),
            _base_report(id="vuln-0002", cwe="CWE-306", title="Second CWE-306 finding"),
        ]
    )
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "CWE-306"


def test_write_sarif_roundtrip(tmp_path: Path):
    reports = [_base_report()]
    out = write_sarif(tmp_path, reports, tool_version="0.1.13")
    assert out.exists()
    assert out.name == "findings.sarif"
    data = json.loads(out.read_text())
    assert data["version"] == SARIF_VERSION
    assert data["runs"][0]["results"][0]["ruleId"] == "CWE-306"


def test_empty_reports_produces_valid_document():
    doc = build_sarif_document([])
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_cwe_normalisation_accepts_variants():
    for raw in ["CWE-306", "306", "cwe 306", "CWE306"]:
        doc = build_sarif_document([_base_report(cwe=raw)])
        assert doc["runs"][0]["results"][0]["ruleId"] == "CWE-306"


def test_stride_tags_on_rule_for_known_cwe():
    """CWE-306 (Missing Authentication) maps to S+E STRIDE legs."""
    doc = build_sarif_document([_base_report(cwe="CWE-306")])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    tags = rule["properties"]["tags"]
    assert "stride:S" in tags
    assert "stride:E" in tags
    # Existing tags preserved.
    assert "security" in tags
    assert "CWE-306" in tags


def test_stride_tags_on_result_for_known_cwe():
    """Per-result tags duplicate from the rule for consumer-side filtering."""
    doc = build_sarif_document([_base_report(cwe="CWE-306")])
    result_tags = doc["runs"][0]["results"][0]["properties"]["tags"]
    assert "stride:S" in result_tags
    assert "stride:E" in result_tags


def test_stride_default_for_unknown_cwe():
    """Unmapped CWE falls back to T+I default — never empty."""
    doc = build_sarif_document([_base_report(cwe="CWE-99999")])
    rule_tags = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "stride:T" in rule_tags
    assert "stride:I" in rule_tags


def test_stride_default_for_no_cwe():
    """No-CWE finding still gets STRIDE tags (default T+I)."""
    doc = build_sarif_document([_base_report(cwe=None)])
    rule_tags = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "stride:T" in rule_tags
    assert "stride:I" in rule_tags


def test_stride_sql_injection_is_tampering():
    """CWE-89 (SQL Injection) is canonical Tampering."""
    doc = build_sarif_document([_base_report(cwe="CWE-89")])
    rule_tags = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "stride:T" in rule_tags
    # Should NOT include S or E for plain SQLi (it's tampering, not auth-shape).
    assert "stride:S" not in rule_tags


def test_stride_idor_is_elevation():
    """CWE-639 (Authorization Bypass via User-controlled Key, IDOR/BOLA)
    is canonical Elevation of Privilege."""
    doc = build_sarif_document([_base_report(cwe="CWE-639")])
    rule_tags = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "stride:E" in rule_tags


def test_stride_missing_authz_is_elevation():
    """CWE-862 (Missing Authorization) is canonical Elevation of Privilege.
    Sibling of CWE-863. Real-world calibration: trade-api scan
    2026-05-19 surfaced a CWE-862 finding that fell through to the
    default T+I; adding the explicit mapping."""
    doc = build_sarif_document([_base_report(cwe="CWE-862")])
    rule_tags = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "stride:E" in rule_tags
    # Should NOT carry the default T+I.
    assert "stride:T" not in rule_tags
    assert "stride:I" not in rule_tags


def test_stride_incorrect_default_perms_is_elevation():
    """CWE-276 (Incorrect Default Permissions) — also Elevation."""
    doc = build_sarif_document([_base_report(cwe="CWE-276")])
    rule_tags = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "stride:E" in rule_tags
