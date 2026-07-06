"""STRIDE-leg tagging in the SARIF emitter (strix/report/sarif.py).

Every finding's SARIF rule (and, by inheritance, its results) carries one or
more ``stride:<leg>`` tags derived from the finding's CWE, so the GitHub
code-scanning Security tab and ASPM dashboards can group/filter by threat-model
leg. Unmapped or no-CWE findings fall back to a default so coverage reports have
no gaps.

The emitter is imported in isolation (it is stdlib-only) so these tests run
without the full agents-SDK runtime installed.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SARIF = Path(__file__).resolve().parents[2] / "strix" / "report" / "sarif.py"
_spec = importlib.util.spec_from_file_location("strix_report_sarif_iso", _SARIF)
sarif = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sarif)


def _report(**overrides):
    report = {
        "id": "vuln-0001",
        "title": "Missing authentication on gRPC endpoint",
        "severity": "critical",
        "cwe": "CWE-306",
        "description": "The gRPC server registers no auth interceptor.",
    }
    report.update(overrides)
    return report


def _rule_tags(doc):
    return doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]


def test_stride_tags_on_rule_for_known_cwe():
    """CWE-306 (Missing Authentication) maps to S+E, alongside existing tags."""
    tags = _rule_tags(sarif.build_sarif_document([_report(cwe="CWE-306")]))
    assert "stride:S" in tags
    assert "stride:E" in tags
    assert "security" in tags          # existing tags preserved
    assert "CWE-306" in tags


def test_stride_tags_attach_to_rule_not_duplicated_on_result():
    """STRIDE tags live on the RULE; results inherit them via ruleId (standard
    SARIF) rather than duplicating — the result carries the matching ruleId and
    its own strix.* properties, not a redundant tags copy."""
    doc = sarif.build_sarif_document([_report(cwe="CWE-306")])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == rule["id"]                 # inherits via ruleId
    assert {"stride:S", "stride:E"} <= set(rule["properties"]["tags"])
    assert "tags" not in result["properties"]             # not duplicated


def test_stride_default_for_unmapped_cwe():
    tags = _rule_tags(sarif.build_sarif_document([_report(cwe="CWE-99999")]))
    assert "stride:T" in tags and "stride:I" in tags


def test_stride_default_for_no_cwe():
    tags = _rule_tags(sarif.build_sarif_document([_report(cwe=None)]))
    assert "stride:T" in tags and "stride:I" in tags


def test_stride_sql_injection_is_tampering_not_spoofing():
    tags = _rule_tags(sarif.build_sarif_document([_report(cwe="CWE-89")]))
    assert "stride:T" in tags
    assert "stride:S" not in tags      # SQLi is tampering, not auth-shape


def test_stride_idor_is_elevation():
    tags = _rule_tags(sarif.build_sarif_document([_report(cwe="CWE-639")]))
    assert "stride:E" in tags


def test_stride_cleartext_transmission_is_info_disclosure():
    tags = _rule_tags(sarif.build_sarif_document([_report(cwe="CWE-319")]))
    assert "stride:I" in tags


def test_stride_hardcoded_credentials_is_spoofing():
    """CWE-798 (Hard-coded Credentials) is Spoofing (+ Info disclosure), NOT the
    generic default — regression from exercising against real scan findings
    where 798 was falling through to T+I."""
    tags = _rule_tags(sarif.build_sarif_document([_report(cwe="CWE-798")]))
    assert "stride:S" in tags
    assert set(sarif._stride_legs_for_cwe("CWE-798")) != set(sarif._DEFAULT_STRIDE_LEGS)


def test_stride_missing_authorization_is_elevation():
    """CWE-862 (Missing Authorization) is Elevation of privilege — sibling of
    863 Incorrect Authorization. Regression from real findings (was defaulting)."""
    tags = _rule_tags(sarif.build_sarif_document([_report(cwe="CWE-862")]))
    assert "stride:E" in tags
    assert "stride:T" not in tags      # not the default


@pytest.mark.parametrize("raw", ["CWE-306", "306", "cwe 306", "CWE306"])
def test_stride_cwe_normalisation_variants(raw):
    """CWE id variants all resolve to the same legs (S+E for 306)."""
    tags = _rule_tags(sarif.build_sarif_document([_report(cwe=raw)]))
    assert "stride:S" in tags and "stride:E" in tags


def test_every_leg_letter_is_valid():
    """Sanity: the mapping only emits the six canonical STRIDE letters."""
    valid = {"S", "T", "R", "I", "D", "E"}
    for legs in sarif._CWE_TO_STRIDE.values():
        assert set(legs) <= valid, f"invalid STRIDE leg in {legs}"
    assert set(sarif._DEFAULT_STRIDE_LEGS) <= valid
