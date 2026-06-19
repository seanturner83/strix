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


# ---------------------------------------------------------------------------
# Fix C — retract_vulnerability_report (resumable-PR-session fail-closed fix)
# ---------------------------------------------------------------------------
#
# The real-diff canary (run 27842371384) proved that on --resume a FIXED prior
# finding re-emits forever: rehydration is append-only, so even though the
# agent's report correctly declares it dropped, vulnerabilities.csv still
# carries it and the SARIF re-ships it. Under the gate's introduced=head\base
# diff that makes a fixed finding immortal => the PR can never go green after
# the fix (fail-CLOSED). retract_vulnerability_report is the primitive the
# agent calls to drop a confirmed-fixed finding so the cumulative SARIF is
# correct. These tests drive the REAL tracer method + SARIF emit offline.

def _all_sarif_titles(sarif: dict) -> set[str]:
    """Every finding TITLE present in a SARIF (results + locationless).

    Titles are the stable cross-layer identity here — SARIF results key the
    rule on CWE (ruleId=CWE-78), not the internal vuln-NNNN id, so we match on
    the message/title text the emitter carries through verbatim.
    """
    titles = set()
    run = sarif["runs"][0]
    for r in run.get("results", []):
        txt = (r.get("message") or {}).get("text", "")
        if txt:
            titles.add(txt.strip())
    for lf in run["properties"].get("locationlessFindings", []):
        t = lf.get("title") or (lf.get("message") or {}).get("text", "")
        if t:
            titles.add(t.strip())
    return titles


class TestRetract:
    def test_retract_drops_fixed_keeps_present(self, monkeypatch, tmp_path) -> None:
        """The canary shape: resume restores 2 findings, the push FIXED one of
        them. Retract the fixed one -> SARIF emits only the still-present one."""
        _seed_disk_run(tmp_path, "retract-run", [
            {"id": "vuln-0001", "title": "Hardcoded JWT signing key",
             "severity": "critical", "cwe": "CWE-798"},
            {"id": "vuln-0002", "title": "OS command injection via Host",
             "severity": "critical", "cwe": "CWE-78"},
        ])
        monkeypatch.chdir(tmp_path)
        t = Tracer("retract-run")
        set_global_tracer(t)
        assert len(t.vulnerability_reports) == 2  # both rehydrated

        result = t.retract_vulnerability_report("vuln-0001", "key now read from os.Getenv at line 22")
        assert result["success"] and result["retracted"]
        assert result["remaining"] == 1

        # In-memory set reduced; the fixed id is gone.
        ids = {r["id"] for r in t.vulnerability_reports}
        assert ids == {"vuln-0002"}
        # Re-emitted SARIF no longer carries the retracted finding.
        sarif = json.loads((tmp_path / "strix_runs" / "retract-run" / "findings.sarif").read_text())
        titles = _all_sarif_titles(sarif)
        assert "Hardcoded JWT signing key" not in titles, \
            "retracted (fixed) finding must NOT be in SARIF"
        assert "OS command injection via Host" in titles, \
            "still-present finding MUST remain (no fail-open)"

    def test_retract_removes_stale_md_so_next_resume_wont_reload(self, monkeypatch, tmp_path) -> None:
        """The .md is the rehydration source — retract must delete it, else the
        NEXT push reloads the retracted finding from disk and it resurrects."""
        run_dir = _seed_disk_run(tmp_path, "retract-md", [
            {"id": "vuln-0001", "title": "fixed thing", "severity": "high"},
            {"id": "vuln-0002", "title": "live thing", "severity": "high"},
        ])
        monkeypatch.chdir(tmp_path)
        t = Tracer("retract-md")
        set_global_tracer(t)
        t.retract_vulnerability_report("vuln-0001", "resolved")

        assert not (run_dir / "vulnerabilities" / "vuln-0001.md").exists()
        assert (run_dir / "vulnerabilities" / "vuln-0002.md").exists()
        # Simulate the NEXT push: a fresh Tracer rehydrates from the (now
        # reduced) disk state — the retracted finding stays gone.
        t2 = Tracer("retract-md")
        assert {r["id"] for r in t2.vulnerability_reports} == {"vuln-0002"}
        # CSV no longer references vuln-0001 either.
        csv_text = (run_dir / "vulnerabilities.csv").read_text()
        assert "vuln-0001" not in csv_text
        assert "vuln-0002" in csv_text

    def test_retract_unknown_id_is_noop_success(self, monkeypatch, tmp_path) -> None:
        _seed_disk_run(tmp_path, "retract-noop", [
            {"id": "vuln-0001", "title": "only one", "severity": "high"},
        ])
        monkeypatch.chdir(tmp_path)
        t = Tracer("retract-noop")
        set_global_tracer(t)
        result = t.retract_vulnerability_report("vuln-9999", "never existed")
        assert result["success"] and not result["retracted"]
        assert {r["id"] for r in t.vulnerability_reports} == {"vuln-0001"}

    def test_retract_then_new_finding_does_not_reuse_id(self, monkeypatch, tmp_path) -> None:
        """Positional ids must stay stable: after retracting vuln-0002 of 3, a
        new finding should NOT recycle vuln-0002 (would shadow references)."""
        _seed_disk_run(tmp_path, "retract-seq", [
            {"id": "vuln-0001", "title": "a", "severity": "high"},
            {"id": "vuln-0002", "title": "b (will fix)", "severity": "high"},
            {"id": "vuln-0003", "title": "c", "severity": "high"},
        ])
        monkeypatch.chdir(tmp_path)
        t = Tracer("retract-seq")
        set_global_tracer(t)
        t.retract_vulnerability_report("vuln-0002", "fixed")
        # 2 remain (0001, 0003); next add uses len+1 = vuln-0003 → COLLISION risk.
        new_id = t.add_vulnerability_report(title="new after retract", severity="low")
        existing = {r["id"] for r in t.vulnerability_reports}
        # The new id must be unique within the current set (no shadowing).
        assert new_id in existing
        assert len([r for r in t.vulnerability_reports if r["id"] == new_id]) == 1, \
            f"new finding id {new_id} collided with a surviving finding"


# ---------------------------------------------------------------------------
# Groundedness guard — refuse a retraction when the vuln is still present
# ---------------------------------------------------------------------------
#
# The retract primitive trusts the agent's "this is fixed" claim. The guard
# (in reporting_actions) re-verifies it deterministically: recover the prior
# finding's code_locations from events.jsonl, and if the fix_before (vuln-site)
# block is STILL verbatim in the current tree, REFUSE — otherwise a confident-
# but-wrong agent could silently drop a real finding from the gate (fail-open).

def _write_events_finding(events_path: Path, report_id: str, locations: list) -> None:
    """Append a finding.created event with code_locations (mirrors the tracer)."""
    import json as _json
    evt = {"event_type": "finding.created",
           "payload": {"report": {"id": report_id, "code_locations": locations}}}
    with events_path.open("a", encoding="utf-8") as f:
        f.write(_json.dumps(evt) + "\n")


class TestRetractGroundednessGuard:
    def _guard(self):
        from strix.tools.reporting.reporting_actions import (
            _prior_finding_locations,
            _vuln_still_present,
        )
        return _prior_finding_locations, _vuln_still_present

    def test_refuses_when_vuln_site_still_present(self, tmp_path) -> None:
        _prior, _still = self._guard()
        run_dir = tmp_path / "run"; run_dir.mkdir()
        ws = tmp_path / "ws"; (ws / "internal/auth").mkdir(parents=True)
        sink = 'const jwtSigningKey = "supersecret-2026"'
        (ws / "internal/auth/x.go").write_text(f"package auth\n{sink}\n")
        _write_events_finding(run_dir / "events.jsonl", "vuln-0001", [
            {"file": "internal/auth/x.go", "start_line": 2, "end_line": 2,
             "fix_before": sink, "fix_after": "var k = os.Getenv(\"K\")"},
        ])
        locs = _prior(run_dir, "vuln-0001")
        still, detail = _still(locs, workspace_root=str(ws))
        assert still is True, "vuln-site code unchanged → guard must REFUSE retraction"

    def test_allows_when_vuln_site_gone(self, tmp_path) -> None:
        _prior, _still = self._guard()
        run_dir = tmp_path / "run"; run_dir.mkdir()
        ws = tmp_path / "ws"; (ws / "internal/auth").mkdir(parents=True)
        # Current code is the FIXED version — the fix_before block is absent.
        (ws / "internal/auth/x.go").write_text(
            'package auth\nvar jwtSigningKey = os.Getenv("JWT_SIGNING_KEY")\n')
        _write_events_finding(run_dir / "events.jsonl", "vuln-0001", [
            {"file": "internal/auth/x.go", "start_line": 2, "end_line": 2,
             "fix_before": 'const jwtSigningKey = "supersecret-2026"',
             "fix_after": 'var jwtSigningKey = os.Getenv("JWT_SIGNING_KEY")'},
        ])
        locs = _prior(run_dir, "vuln-0001")
        still, _ = _still(locs, workspace_root=str(ws))
        assert still is False, "vuln-site code gone → guard must ALLOW retraction"

    def test_context_only_location_does_not_false_refuse(self, tmp_path) -> None:
        """A finding's context location (snippet, NO fix_before) is often
        unchanged by a fix. The guard must IGNORE it — only fix_before (sink)
        locations count. Otherwise a genuine fix is false-refused (the canary
        bug: CWE-78 sink fixed, but an unchanged helper context line matched)."""
        _prior, _still = self._guard()
        run_dir = tmp_path / "run"; run_dir.mkdir()
        ws = tmp_path / "ws"; (ws / "a").mkdir(parents=True)
        # Sink (fix_before) is GONE; an unchanged context helper REMAINS.
        helper = "func helper() {\n\t_ = x\n}"
        (ws / "a/f.go").write_text(
            f"package a\n_ = exec.Command(\"ping\", \"-c1\", host)\n{helper}\n")
        _write_events_finding(run_dir / "events.jsonl", "vuln-0002", [
            {"file": "a/f.go", "start_line": 2, "end_line": 2,
             "fix_before": '_ = exec.Command("sh", "-c", "ping -c1 "+host)',  # GONE
             "fix_after": '_ = exec.Command("ping", "-c1", host)'},
            {"file": "a/f.go", "start_line": 3, "end_line": 5,
             "snippet": helper, "label": "context helper (unchanged)"},  # PRESENT, no fix_before
        ])
        locs = _prior(run_dir, "vuln-0002")
        still, detail = _still(locs, workspace_root=str(ws))
        assert still is False, \
            f"context-only match must NOT refuse a genuine fix; detail={detail}"

    def test_missing_events_allows_failsafe(self, tmp_path) -> None:
        """No events.jsonl / no recoverable locations → guard can't disprove the
        fix → allow (don't fabricate a block from missing data)."""
        _prior, _still = self._guard()
        run_dir = tmp_path / "run"; run_dir.mkdir()  # no events.jsonl
        assert _prior(run_dir, "vuln-0001") is None
        still, _ = _still([], workspace_root=str(tmp_path))
        assert still is False

    def test_deleted_file_allows_retraction(self, tmp_path) -> None:
        """Vulnerable file deleted entirely → vuln gone → allow."""
        _prior, _still = self._guard()
        run_dir = tmp_path / "run"; run_dir.mkdir()
        ws = tmp_path / "ws"; ws.mkdir()  # file does NOT exist
        _write_events_finding(run_dir / "events.jsonl", "vuln-0003", [
            {"file": "gone/deleted.go", "start_line": 1, "end_line": 1,
             "fix_before": "dangerous()", "fix_after": "safe()"},
        ])
        locs = _prior(run_dir, "vuln-0003")
        still, _ = _still(locs, workspace_root=str(ws))
        assert still is False, "deleted vulnerable file → allow retraction"
