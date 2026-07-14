"""Resume → cumulative SARIF (SEC-6802) — the contract the seedcx pipeline
depends on and that v1 shipped WITHOUT an assertion-bearing test.

A resumed scan must re-emit a CUMULATIVE findings.sarif: on `--resume` the run
dir is reused, prior findings are rehydrated from vulnerabilities.json, and the
SARIF serializes from the rehydrated + new set. A downstream consumer gate
treats an ABSENT finding as "resolved", so if a resume dropped prior findings
they'd silently read as fixed (fail-open on a real vuln). These tests assert the
mechanism in-process (no sandbox) so a future refactor of ReportState can't
quietly regress it.
"""
from __future__ import annotations

import json

from strix.report.sarif import build_sarif_report
from strix.report.state import ReportState


def _sarif_finding_titles(run_dir) -> set[str]:
    """Finding identity in the SARIF = each RESULT's message text (title).
    (Rule ``id`` is the CWE and is deduped across findings, so it can't count
    distinct findings — the results array is the cumulative finding set.)"""
    doc = json.loads((run_dir / "findings.sarif").read_text())
    return {r["message"]["text"] for r in doc["runs"][0]["results"]}


def test_resume_rehydrates_prior_findings_into_sarif(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # run_dir_for → tmp_path/strix_runs/<name>

    # --- session 1: report one finding, persist ---
    s1 = ReportState("pr-acme-42")
    s1.add_vulnerability_report(
        title="SQL injection in lookup_user",
        severity="critical",
        cwe="CWE-89",
    )
    s1.save_run_data()
    run_dir = s1.get_run_dir()
    assert "SQL injection in lookup_user" in _sarif_finding_titles(run_dir)

    # --- session 2: RESUME the same run_name, add a second finding ---
    s2 = ReportState("pr-acme-42")
    s2.hydrate_from_run_dir()                      # rehydrate prior findings
    assert len(s2.vulnerability_reports) == 1, "prior finding not rehydrated"
    s2.add_vulnerability_report(
        title="Path traversal in read_config",
        severity="high",
        cwe="CWE-22",
    )
    s2.save_run_data()

    # THE contract: the resumed SARIF is CUMULATIVE — prior + new, not new-only.
    titles = _sarif_finding_titles(run_dir)
    assert "SQL injection in lookup_user" in titles, "prior finding vanished from resumed SARIF (fail-open!)"
    assert "Path traversal in read_config" in titles, "new finding missing from resumed SARIF"
    assert len(titles) == 2


def test_resume_with_no_prior_findings_is_noop(tmp_path, monkeypatch):
    # A fresh run dir (no vulnerabilities.json) hydrates to empty, never raises.
    monkeypatch.chdir(tmp_path)
    s = ReportState("pr-empty-1")
    s.hydrate_from_run_dir()
    assert s.vulnerability_reports == []


def test_retract_removes_from_cumulative_sarif(tmp_path, monkeypatch):
    # The v1 retract primitive is the DELIBERATE exception to append-only: a
    # resumed scan may emit FEWER findings when the agent re-verifies one fixed.
    # Assert a retracted finding leaves the cumulative SARIF (so the consumer
    # gate reads it as resolved — the intended behaviour, not a silent drop).
    monkeypatch.chdir(tmp_path)
    s = ReportState("pr-acme-43")
    rid = s.add_vulnerability_report(title="XSS", severity="high", cwe="CWE-79")
    s.add_vulnerability_report(title="SSRF", severity="high", cwe="CWE-918")
    s.save_run_data()
    assert len(_sarif_finding_titles(s.get_run_dir())) == 2

    s.retract_vulnerability_report(rid, reason="fixed by this push; re-read line, sink gone")
    s.save_run_data()
    titles = _sarif_finding_titles(s.get_run_dir())
    assert "XSS" not in titles and titles == {"SSRF"}
