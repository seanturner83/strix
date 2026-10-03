"""finish_scan guard: block finishing when findings are described but never filed."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

from strix.tools.finish import tool as finish_tool


if TYPE_CHECKING:
    import pytest


def test_claims_findings_on_cvss() -> None:
    assert finish_tool._summary_claims_findings("Rated CVSS 8.8, exploitable.") is True


def test_claims_findings_on_severity_table() -> None:
    table = "| # | Issue | Severity |\n| 1 | SQLi in /login | High |"
    assert finish_tool._summary_claims_findings(table) is True


def test_claims_findings_on_prose_classes_plus_severities() -> None:
    prose = "Identified SQL injection (High) in /login and reflected XSS (Medium) in /hello."
    assert finish_tool._summary_claims_findings(prose) is True


def test_clean_scan_does_not_claim_findings() -> None:
    assert finish_tool._summary_claims_findings(
        "No vulnerabilities were identified. All reviewed paths are safe."
    ) is False


def test_empty_summary_does_not_claim_findings() -> None:
    assert finish_tool._summary_claims_findings("", "") is False


def test_guard_blocks_finish_when_described_but_unfiled(monkeypatch: pytest.MonkeyPatch) -> None:
    """The core fix: findings in the summary + 0 filed -> block with a file-them nudge."""
    monkeypatch.setattr(
        "strix.report.state.get_global_report_state",
        lambda: SimpleNamespace(vulnerability_reports=[]),  # nothing filed
    )
    result = finish_tool._do_finish(
        parent_id=None,
        executive_summary=(
            "| SQL injection in /login | High |\n| Reflected XSS in /hello | Medium |"
        ),
        methodology="Static white-box review.",
        technical_analysis="Command injection (CVSS 7.5) in /ping via shell=True.",
        recommendations="Parameterize queries; escape output.",
        agent_graph={},
    )
    assert result["success"] is False
    assert result["error"] == "Findings described in the summary but none were filed"
    assert "create_vulnerability_report" in result["message"]


def test_guard_does_not_block_when_nothing_described(monkeypatch: pytest.MonkeyPatch) -> None:
    """A genuinely clean scan (0 filed, no findings described) must finish normally."""
    captured = {}
    report_state = SimpleNamespace(
        vulnerability_reports=[],
        update_scan_final_fields=lambda **kw: captured.update(kw),
    )
    monkeypatch.setattr("strix.report.state.get_global_report_state", lambda: report_state)
    monkeypatch.setattr(finish_tool, "_coverage_summary", lambda _graph: {"coverage": "none"})
    result = finish_tool._do_finish(
        parent_id=None,
        executive_summary="No vulnerabilities were identified; all reviewed routes are safe.",
        methodology="Static white-box review.",
        technical_analysis="Reviewed all routes; inputs are validated and queries parameterized.",
        recommendations="Maintain current controls.",
        agent_graph={},
    )
    assert result["success"] is True  # not blocked
    assert captured  # the clean summary was persisted
