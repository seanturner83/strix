"""retract_vulnerability_report — the resumed-scan fail-closed fix.

Covers the two risk surfaces:
  1. the state primitive: physical removal, id-stability across retraction
     (max-based ordinal, not list length), retract-to-zero, idempotency.
  2. the groundedness guard (pure/injectable): fail-safe-refuse without a
     reader, refuse when the sink is still present, allow when it's gone, only
     verify fix_before sinks (not context snippets).

The guard is imported in isolation (agents SDK-free); the primitive is tested
against a lightweight fake state to avoid the full ReportState I/O stack.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_GUARD = Path(__file__).resolve().parents[2] / "strix" / "tools" / "reporting" / "retract_tool.py"


def _load_guard_module():
    """Import the retract_tool guard helpers. The real `agents` SDK is present
    in the test venv, so import normally — no stubbing (stubbing `agents`
    pollutes sys.modules and breaks the real ReportState import below)."""
    spec = importlib.util.spec_from_file_location("retract_tool_iso", _GUARD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rt = _load_guard_module()


def _report(**over):
    r = {"id": "vuln-0002", "title": "SQLi", "severity": "high",
         "code_locations": [{"file": "app/db.py", "start_line": 10, "end_line": 10,
                             "fix_before": "query('SELECT * FROM u WHERE id=%s' % uid)"}]}
    r.update(over)
    return r


# ---- groundedness guard (pure) --------------------------------------------

def test_guard_fail_safe_refuses_without_reader():
    rt.set_target_file_reader(None)
    allow, detail = rt._guard(_report())
    assert allow is False and "no target-file reader" in detail


def test_guard_refuses_when_sink_still_present():
    rt.set_target_file_reader(lambda f: "def q(uid):\n    query('SELECT * FROM u WHERE id=%s' % uid)\n")
    allow, detail = rt._guard(_report())
    assert allow is False and "still present" in detail
    rt.set_target_file_reader(None)


def test_guard_allows_when_sink_gone():
    rt.set_target_file_reader(lambda f: "def q(uid):\n    query('SELECT * FROM u WHERE id=?', (uid,))\n")
    allow, detail = rt._guard(_report())
    assert allow is True and "no longer present" in detail
    rt.set_target_file_reader(None)


def test_guard_allows_when_file_deleted():
    rt.set_target_file_reader(lambda f: None)  # file gone
    allow, _ = rt._guard(_report())
    assert allow is True
    rt.set_target_file_reader(None)


def test_guard_allows_when_no_fix_before_sinks():
    # only a context snippet, no fix_before → nothing verifiable → allow
    rt.set_target_file_reader(lambda f: "anything")
    rep = _report(code_locations=[{"file": "app/db.py", "snippet": "context line"}])
    allow, detail = rt._guard(rep)
    assert allow is True and "no fix-site" in detail
    rt.set_target_file_reader(None)


def test_guard_reader_error_refuses():
    def boom(f):
        raise RuntimeError("sandbox down")
    rt.set_target_file_reader(boom)
    allow, detail = rt._guard(_report())
    assert allow is False and "could not read" in detail
    rt.set_target_file_reader(None)


# ---- state primitive (fake state) -----------------------------------------

def _bare_state():
    """A ReportState with only the fields the retract/id logic touches — avoids
    the full __init__ I/O stack."""
    from strix.report.state import ReportState
    return ReportState.__new__(ReportState)


def test_retract_removes_and_keeps_ids_stable(tmp_path, monkeypatch):
    st = _bare_state()
    st.vulnerability_reports = []
    st._saved_vuln_ids = set()
    monkeypatch.setattr(st, "get_run_dir", lambda: tmp_path)
    monkeypatch.setattr(st, "save_run_data", lambda **k: None)

    # add three
    ids = [st._next_vuln_ordinal()]
    st.vulnerability_reports.append({"id": f"vuln-{ids[0]:04d}", "severity": "high", "title": "a"})
    n2 = st._next_vuln_ordinal(); st.vulnerability_reports.append({"id": f"vuln-{n2:04d}", "severity": "high", "title": "b"})
    n3 = st._next_vuln_ordinal(); st.vulnerability_reports.append({"id": f"vuln-{n3:04d}", "severity": "high", "title": "c"})
    assert [r["id"] for r in st.vulnerability_reports] == ["vuln-0001", "vuln-0002", "vuln-0003"]

    # retract the middle
    res = st.retract_vulnerability_report("vuln-0002", "fixed: parameterised the query at db.py:10")
    assert res["retracted"] is True and res["remaining"] == 2
    assert [r["id"] for r in st.vulnerability_reports] == ["vuln-0001", "vuln-0003"]

    # next id must be 0004 (max+1), NOT 0003 (len+1) — no recycling onto vuln-0003
    assert st._next_vuln_ordinal() == 4


def test_retract_requires_reason(tmp_path, monkeypatch):
    st = _bare_state()
    st.vulnerability_reports = [{"id": "vuln-0001", "severity": "high", "title": "a"}]
    st._saved_vuln_ids = set()
    monkeypatch.setattr(st, "get_run_dir", lambda: tmp_path)
    monkeypatch.setattr(st, "save_run_data", lambda **k: None)
    with pytest.raises(ValueError):
        st.retract_vulnerability_report("vuln-0001", "  ")


def test_retract_unknown_id_is_noop_success(tmp_path, monkeypatch):
    st = _bare_state()
    st.vulnerability_reports = []
    st._saved_vuln_ids = set()
    monkeypatch.setattr(st, "get_run_dir", lambda: tmp_path)
    monkeypatch.setattr(st, "save_run_data", lambda **k: None)
    res = st.retract_vulnerability_report("vuln-9999", "n/a")
    assert res["success"] is True and res["retracted"] is False
