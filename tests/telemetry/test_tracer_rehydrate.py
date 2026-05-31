"""Tests for SEC-6802 rehydration + incremental-SARIF behavior on Tracer.

The bug: --continue resume reconstructs AgentState from conversation.jsonl
but each iteration's fresh Tracer starts with empty
vulnerability_reports + _saved_vuln_ids. New findings collide on ID
(vuln-0001 again), .md writeups overwrite, CSV gets clobbered, and
the final SARIF reflects only the last iteration's runs.

The fix: rehydrate vulnerability_reports + _saved_vuln_ids from disk
(vulnerabilities.csv + per-finding .md) at Tracer.__init__, and write
SARIF on every save_run_data call rather than only at mark_complete.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _reset_globals(monkeypatch) -> None:
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()


def _seed_disk_run(tmp_path: Path, run_name: str, findings: list[dict[str, Any]]) -> Path:
    """Create a strix_runs/<run_name>/ dir with vulnerabilities.csv +
    per-finding .md files matching what save_run_data would emit."""
    run_dir = tmp_path / "strix_runs" / run_name
    vuln_dir = run_dir / "vulnerabilities"
    vuln_dir.mkdir(parents=True)

    with (run_dir / "vulnerabilities.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "title", "severity", "timestamp", "file"])
        writer.writeheader()
        for finding in findings:
            writer.writerow({
                "id": finding["id"],
                "title": finding["title"],
                "severity": finding["severity"].upper(),
                "timestamp": finding.get("timestamp", "2026-05-31 12:00:00 UTC"),
                "file": f"vulnerabilities/{finding['id']}.md",
            })

    for finding in findings:
        md_path = vuln_dir / f"{finding['id']}.md"
        lines = [f"# {finding['title']}", ""]
        lines.append(f"**ID:** {finding['id']}")
        lines.append(f"**Severity:** {finding['severity'].upper()}")
        lines.append(f"**Found:** {finding.get('timestamp', '2026-05-31 12:00:00 UTC')}")
        if finding.get("target"):
            lines.append(f"**Target:** {finding['target']}")
        if finding.get("endpoint"):
            lines.append(f"**Endpoint:** {finding['endpoint']}")
        if finding.get("method"):
            lines.append(f"**Method:** {finding['method']}")
        if finding.get("cwe"):
            lines.append(f"**CWE:** {finding['cwe']}")
        if finding.get("cvss") is not None:
            lines.append(f"**CVSS:** {finding['cvss']}")
        lines.append("")
        lines.append("## Description")
        lines.append("")
        lines.append(finding.get("description", "Description body."))
        md_path.write_text("\n".join(lines) + "\n")

    return run_dir


# ---------------------------------------------------------------------------
# Fix A — rehydrate vulnerability_reports + _saved_vuln_ids from disk
# ---------------------------------------------------------------------------

class TestRehydrate:
    def test_fresh_run_has_empty_reports(self, monkeypatch, tmp_path) -> None:
        monkeypatch.chdir(tmp_path)
        # No prior run dir → no rehydration → empty list, no error.
        t = Tracer("fresh-run")
        assert t.vulnerability_reports == []
        assert t._saved_vuln_ids == set()

    def test_resume_rehydrates_prior_findings(self, monkeypatch, tmp_path) -> None:
        # Pre: 3 findings on disk from a prior iteration.
        _seed_disk_run(tmp_path, "resumed-run", [
            {"id": "vuln-0001", "title": "Auth bypass via internal_request",
             "severity": "critical", "cwe": "CWE-290", "cvss": 10.0,
             "endpoint": "/withdrawals/requests"},
            {"id": "vuln-0002", "title": "IDOR cross-tenant disclosure",
             "severity": "high", "cwe": "CWE-639", "cvss": 7.7,
             "endpoint": "/accountDetailsByRequestId/:id"},
            {"id": "vuln-0003", "title": "Cache pollution unscoped keys",
             "severity": "medium", "cvss": 6.8},
        ])
        monkeypatch.chdir(tmp_path)

        # Resume — same run_name picks up the existing dir.
        t = Tracer("resumed-run")

        assert len(t.vulnerability_reports) == 3
        ids = sorted(r["id"] for r in t.vulnerability_reports)
        assert ids == ["vuln-0001", "vuln-0002", "vuln-0003"]
        # Severity normalised to lowercase to match add_vulnerability_report.
        sevs = {r["id"]: r["severity"] for r in t.vulnerability_reports}
        assert sevs == {"vuln-0001": "critical", "vuln-0002": "high", "vuln-0003": "medium"}
        # Header fields recovered.
        by_id = {r["id"]: r for r in t.vulnerability_reports}
        assert by_id["vuln-0001"]["cwe"] == "CWE-290"
        assert by_id["vuln-0001"]["cvss"] == 10.0
        assert by_id["vuln-0001"]["endpoint"] == "/withdrawals/requests"
        # _saved_vuln_ids populated so save_run_data won't re-write.
        assert t._saved_vuln_ids == {"vuln-0001", "vuln-0002", "vuln-0003"}

    def test_post_resume_new_finding_has_sequential_id(self, monkeypatch, tmp_path) -> None:
        # The load-bearing semantic: a new finding after resume must
        # continue the sequence (vuln-0004), not collide with vuln-0001.
        _seed_disk_run(tmp_path, "seq-test", [
            {"id": "vuln-0001", "title": "first", "severity": "high"},
            {"id": "vuln-0002", "title": "second", "severity": "high"},
            {"id": "vuln-0003", "title": "third", "severity": "high"},
        ])
        monkeypatch.chdir(tmp_path)

        t = Tracer("seq-test")
        set_global_tracer(t)
        new_id = t.add_vulnerability_report(
            title="fourth — found after resume",
            severity="critical",
        )
        assert new_id == "vuln-0004"

    def test_missing_md_skipped_with_warning(self, monkeypatch, tmp_path, caplog) -> None:
        # CSV references vuln-0002.md but the file doesn't exist.
        # Rehydration should skip the bad row, log a warning, continue
        # with the others.
        _seed_disk_run(tmp_path, "partial-run", [
            {"id": "vuln-0001", "title": "first", "severity": "high"},
            {"id": "vuln-0002", "title": "second", "severity": "high"},
        ])
        # Delete vuln-0002.md to simulate filesystem damage.
        (tmp_path / "strix_runs" / "partial-run" / "vulnerabilities" / "vuln-0002.md").unlink()
        monkeypatch.chdir(tmp_path)

        with caplog.at_level("WARNING"):
            t = Tracer("partial-run")
        # vuln-0001 still rehydrates; vuln-0002 is skipped because
        # the .md file is missing. The parser raises (file-not-found)
        # which the rehydration catches, so we get 1 report not 2.
        # _parse_writeup_to_report doesn't run if the md doesn't exist
        # because read_text raises — same result either way.
        ids = [r["id"] for r in t.vulnerability_reports]
        assert "vuln-0001" in ids
        # A warning about vuln-0002 should be in the log.
        assert any("vuln-0002" in record.message for record in caplog.records)

    def test_corrupted_csv_no_rehydration(self, monkeypatch, tmp_path) -> None:
        # CSV exists but is unparseable. Rehydration should bail and
        # start with empty state rather than crash. The findings on
        # disk stay but Tracer starts fresh.
        run_dir = tmp_path / "strix_runs" / "corrupt-csv"
        (run_dir / "vulnerabilities").mkdir(parents=True)
        # Plain garbage as CSV.
        (run_dir / "vulnerabilities.csv").write_text("this is { not csv")
        monkeypatch.chdir(tmp_path)
        # No raise — empty rehydration result.
        t = Tracer("corrupt-csv")
        # Either empty (parser failed silently) or partial (the row
        # parser accepts the garbage as a header-only row). Either
        # way, no crash.
        assert isinstance(t.vulnerability_reports, list)


# ---------------------------------------------------------------------------
# Fix B — SARIF emit outside mark_complete gate
# ---------------------------------------------------------------------------

class TestIncrementalSarif:
    def test_sarif_emitted_on_save_without_mark_complete(self, monkeypatch, tmp_path) -> None:
        monkeypatch.chdir(tmp_path)
        t = Tracer("incremental-sarif-run")
        set_global_tracer(t)
        # add_vulnerability_report → save_run_data internally (mark_complete=False)
        t.add_vulnerability_report(title="early finding", severity="high")

        sarif_path = tmp_path / "strix_runs" / "incremental-sarif-run" / "findings.sarif"
        assert sarif_path.exists(), \
            "SEC-6802: SARIF should emit on every save_run_data call, " \
            "not only at mark_complete=True"
        sarif = json.loads(sarif_path.read_text())
        # 1 result in SARIF matches the 1 in-memory report. With locationless
        # findings (no code_locations) the result lives in
        # properties.locationlessFindings.
        locationless = sarif["runs"][0]["properties"].get("locationlessFindings", [])
        results = sarif["runs"][0].get("results", [])
        assert len(locationless) + len(results) == 1

    def test_sarif_includes_rehydrated_plus_new_findings(self, monkeypatch, tmp_path) -> None:
        # The headline integration: prior iteration left 3 findings on
        # disk; new iteration rehydrates them, adds 2 more, SARIF emit
        # at end-of-save reflects all 5.
        _seed_disk_run(tmp_path, "mixed-run", [
            {"id": "vuln-0001", "title": "prior 1", "severity": "high", "cwe": "CWE-639"},
            {"id": "vuln-0002", "title": "prior 2", "severity": "high", "cwe": "CWE-862"},
            {"id": "vuln-0003", "title": "prior 3", "severity": "critical", "cwe": "CWE-290"},
        ])
        monkeypatch.chdir(tmp_path)
        t = Tracer("mixed-run")
        set_global_tracer(t)

        # New findings on top of the 3 rehydrated.
        t.add_vulnerability_report(title="new 4", severity="high")
        t.add_vulnerability_report(title="new 5", severity="medium")

        sarif_path = tmp_path / "strix_runs" / "mixed-run" / "findings.sarif"
        assert sarif_path.exists()
        sarif = json.loads(sarif_path.read_text())
        all_count = (
            len(sarif["runs"][0]["properties"].get("locationlessFindings", []))
            + len(sarif["runs"][0].get("results", []))
        )
        assert all_count == 5
