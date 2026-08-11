"""A tool-test probe must not become a severity-rated finding.

MEASURED LIVE on zh-global-infrastructure#16850 (strix-pr-dispatch, flag-aware
profile). The agent called create_vulnerability_report with dummy content to check
the tool worked before using it for real — a "transport check" — and it landed as
VULN-0001:

    Title:    Test title placeholder
    Severity: HIGH        CVSS: 7.7
    Target:   infrastructure/ep3-prd/aws/us-east-2/main/cluster1/platform/aws-auth/terragrunt.hcl
    Desc:     Test description placeholder for transport check.
    PoC code: echo test

Every gate passed. `_REQUIRED_FIELDS` only checks non-emptiness, and the CVSS
vector was syntactically valid with all values in range. So it reached the PR gate
as a genuine HIGH finding against a production IAM auth file and had to be
dismissed by hand.

WHY DETERMINISTIC AND NOT THE VERIFIER. STRIX_VERIFY (fork branch
feat/verify-before-emit) would probably have caught it, but it is deliberately
fail-open and asymmetric — only a FALSE_POSITIVE verdict at or above
min_confidence (default 0.8) suppresses, and it is gated on min_severity (default
high). So suppression would be probabilistic and would skip anything below HIGH.
It also was not in the prod ref at the time, so it was not "disabled by config" —
the code was not there. A string comparison is free, certain, and fails safe.

WHY SUPPRESS RATHER THAN SANCTION A TEST PATH. The tool is exercised by this
suite on every commit and is known to work. A blessed test path would
institutionalise a call with no purpose and still emit something a downstream
consumer must filter.
"""

from __future__ import annotations

import pathlib
from typing import TYPE_CHECKING

import pytest

from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting.tool import _detect_placeholder, _do_create


if TYPE_CHECKING:
    from pathlib import Path


_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "L",
    "user_interaction": "N",
    "scope": "C",
    "confidentiality": "H",
    "integrity": "N",
    "availability": "N",
}


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="placeholder-guard")
    set_global_report_state(state)
    return state


def _real() -> dict[str, str]:
    """A legitimate finding, used as the base for counter-tests."""
    return {
        "title": "aws-auth ConfigMap grants system:masters to a shared role",
        "description": "The mapRoles entry binds a shared CI role to system:masters.",
        "impact": "Any workflow assuming that role gets cluster-admin.",
        "target": "infrastructure/ep3-prd/.../aws-auth/terragrunt.hcl",
        "technical_analysis": "mapRoles[2].groups includes system:masters.",
        "poc_description": "Assume the role, then kubectl get secrets -A.",
        "poc_script_code": "kubectl --context ep3-prd get secrets -A",
        "remediation_steps": "Bind to a scoped ClusterRole instead.",
        "evidence": "terragrunt.hcl line 34 shows the system:masters group.",
        "assumptions": "Assumes the CI role is assumable by any repo.",
    }


# --- the observed probe --------------------------------------------------------


def test_the_exact_dismissed_payload_is_rejected() -> None:
    hits = _detect_placeholder(
        {
            "title": "Test title placeholder",
            "description": "Test description placeholder for transport check.",
            "impact": "Test impact.",
            "target": "infrastructure/ep3-prd/aws/us-east-2/main/cluster1/"
            "platform/aws-auth/terragrunt.hcl",
            "technical_analysis": "Test analysis.",
            "poc_description": "Test poc steps.",
            "poc_script_code": "echo test",
            "remediation_steps": "Test remediation.",
            "evidence": "Test evidence.",
            "assumptions": "Test assumptions.",
        }
    )
    assert hits, "the payload that reached the PR gate must be rejected"
    # the real target path must NOT be what flags it — a genuine finding on this
    # file has to remain reportable
    assert not any("target" in h for h in hits)


async def test_the_probe_fails_validation_end_to_end(report_state: ReportState) -> None:
    result = await _do_create(
        title="Test title placeholder",
        description="Test description placeholder for transport check.",
        impact="Test impact.",
        target="infrastructure/ep3-prd/.../aws-auth/terragrunt.hcl",
        technical_analysis="Test analysis.",
        poc_description="Test poc steps.",
        poc_script_code="echo test",
        remediation_steps="Test remediation.",
        evidence="Test evidence.",
        assumptions="Test assumptions.",
        fix_effort="low",
        cvss_breakdown=_CVSS,
        endpoint=None,
        method=None,
        cve=None,
        cwe=None,
        code_locations=None,
        fix_pr_body=None,
    )
    assert result["success"] is False
    assert not report_state.vulnerability_reports, "must not persist a probe"
    blob = " ".join(result.get("errors") or []) + str(result.get("message", ""))
    assert "needs no smoke test" in blob
    assert "submit nothing" in blob, "the agent must be told no-finding is valid"


# --- counter-tests: a real finding must never be rejected ---------------------


async def test_a_real_finding_still_persists(report_state: ReportState) -> None:
    result = await _do_create(
        **_real(),
        fix_effort="medium",
        cvss_breakdown=_CVSS,
        endpoint=None,
        method=None,
        cve=None,
        cwe="CWE-269",
        code_locations=None,
        fix_pr_body=None,
    )
    assert result["success"] is True, result
    assert len(report_state.vulnerability_reports) == 1


def test_the_word_test_in_legitimate_prose_is_not_a_hit() -> None:
    """'the test suite lacks coverage' is a normal thing to write in a finding.
    Matching the bare word "test" would reject real reports, which is why the
    markers are placeholder IDIOMS."""
    f = _real()
    f["description"] = "The test suite lacks coverage for this path, so the "
    "regression went unnoticed."
    f["technical_analysis"] = "Unit tests assert the happy path only."
    assert _detect_placeholder(f) == []


def test_a_test_file_target_is_not_a_hit() -> None:
    f = _real()
    f["target"] = "internal/testutil/harness.go"
    f["poc_script_code"] = "go test ./internal/testutil -run TestAuthBypass"
    assert _detect_placeholder(f) == []


def test_a_finding_about_placeholder_credentials_is_borderline_and_documented() -> None:
    """KNOWN LIMITATION, recorded rather than hidden: a genuine finding whose prose
    contains the word "placeholder" (e.g. "the config ships a placeholder secret
    that is never replaced") WILL be rejected and must be reworded. Accepted
    deliberately — the alternative is letting probes through, and the rejection
    message tells the agent exactly what to do. If this fires on real findings in
    practice, narrow the marker rather than dropping the guard."""
    f = _real()
    f["description"] = "The chart ships a placeholder secret that is never replaced."
    assert _detect_placeholder(f), "documents current behaviour, not a desired one"


# --- exact-match short fields --------------------------------------------------


@pytest.mark.parametrize("dummy", ["test", "N/A", "none", "-", "echo hello", "TBD"])
def test_bare_dummy_values_are_rejected(dummy: str) -> None:
    f = _real()
    f["poc_script_code"] = dummy
    assert _detect_placeholder(f), f"{dummy!r} must not satisfy the PoC field"


def test_exact_match_does_not_reject_a_short_real_poc() -> None:
    """Equality, not substring, so a terse real PoC survives."""
    f = _real()
    f["poc_script_code"] = "curl -s https://api.example.com/v1/me -H 'Authorization: Bearer $T'"
    assert _detect_placeholder(f) == []


# --- the prompt half ----------------------------------------------------------


def test_the_system_prompt_tells_the_agent_not_to_test_call() -> None:
    """The validator alone would just make the agent probe differently. The prompt
    addresses the cause: it believes the tool is fussy (see the long
    location-required message) and probes before committing."""
    p = pathlib.Path(__file__).resolve().parent.parent / "strix/agents/prompts/system_prompt.jinja"
    src = p.read_text()
    assert "NEVER TEST-CALL create_vulnerability_report" in src
    assert "needs no smoke test" in src
    assert "submit nothing" in src
