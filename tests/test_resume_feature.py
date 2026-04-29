"""Unit tests for the resume session feature (no heavy deps required)."""

import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# conversation_log
# ---------------------------------------------------------------------------


def _import_conv_log():
    """Import ConversationLog without triggering strix.telemetry.__init__."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "conversation_log",
        Path(__file__).parents[1] / "strix/telemetry/conversation_log.py",
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[attr-defined]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _import_session_meta():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "session_meta",
        Path(__file__).parents[1] / "strix/telemetry/session_meta.py",
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[attr-defined]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class TestConversationLog:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())
        mod = _import_conv_log()
        self.ConversationLog = mod.ConversationLog
        self.ReplayError = mod.ReplayError
        self.SCHEMA_VERSION = mod.SCHEMA_VERSION

    def test_roundtrip(self):
        log = self.ConversationLog(self.tmp, "test-run")
        scan_config = {"targets": [{"original": "http://example.com"}], "scan_mode": "deep"}
        log.write_session_start(scan_config)
        log.append_message("user", "Hello, find vulns", iteration=1)
        log.append_message("assistant", [{"type": "text", "text": "Starting scan"}], iteration=1)
        log.append_iteration_end(1, {"found": True}, completed=False)
        log.append_message("user", "any XSS?", iteration=2)
        log.append_iteration_end(2, {"found": True}, completed=False)
        log.write_session_end(completed=True, final_result={"vulns": 1})

        result = self.ConversationLog.replay(self.tmp)

        assert len(result.messages) == 3
        assert result.messages[0] == {"role": "user", "content": "Hello, find vulns"}
        assert result.messages[1]["role"] == "assistant"
        assert result.messages[2] == {"role": "user", "content": "any XSS?"}
        assert result.scan_config == scan_config
        assert result.iteration == 2
        assert result.context == {"found": True}
        assert result.completed is True
        assert result.schema_version == self.SCHEMA_VERSION

    def test_thinking_blocks_preserved(self):
        log = self.ConversationLog(self.tmp, "test-run")
        log.write_session_start({})
        log.append_message(
            "assistant",
            "Result",
            iteration=1,
            thinking_blocks=[{"type": "thinking", "thinking": "deep thought"}],
        )

        result = self.ConversationLog.replay(self.tmp)
        msg = result.messages[0]
        assert msg["thinking_blocks"] == [{"type": "thinking", "thinking": "deep thought"}]

    def test_corrupt_lines_skipped(self):
        log_path = self.tmp / "conversation.jsonl"
        log_path.write_text(
            json.dumps({"type": "session_start", "scan_config": {"targets": []}, "schema_version": 1})
            + "\n"
            + "CORRUPTED LINE\n"
            + json.dumps({"type": "message", "role": "user", "content": "hi", "iteration": 1})
            + "\n",
            encoding="utf-8",
        )
        result = self.ConversationLog.replay(self.tmp)
        assert len(result.messages) == 1

    def test_replay_missing_file(self):
        empty_dir = self.tmp / "empty"
        empty_dir.mkdir()
        with pytest.raises(Exception):
            self.ConversationLog.replay(empty_dir)

    def test_replay_empty_file(self):
        (self.tmp / "conversation.jsonl").write_text("", encoding="utf-8")
        with pytest.raises(Exception):
            self.ConversationLog.replay(self.tmp)

    def test_crash_safe_partial_replay(self):
        """Simulates a crash after a few messages — partial data still recoverable."""
        log = self.ConversationLog(self.tmp, "run")
        log.write_session_start({"targets": []})
        log.append_message("user", "start", iteration=1)
        log.append_message("assistant", "ok", iteration=1)
        # No session_end written (simulated crash)

        result = self.ConversationLog.replay(self.tmp)
        assert len(result.messages) == 2
        assert result.completed is False


class TestSessionMeta:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())
        mod = _import_session_meta()
        self.write = mod.write_session_meta
        self.read = mod.read_session_meta
        self.update_status = mod.update_status

    def test_write_and_read(self):
        meta = {"run_name": "abc", "status": "running", "targets": []}
        self.write(self.tmp, meta)
        result = self.read(self.tmp)
        assert result is not None
        assert result["run_name"] == "abc"
        assert result["status"] == "running"
        assert "last_updated" in result

    def test_merge_preserves_user_fields(self):
        self.write(self.tmp, {"title": "My custom title", "tags": ["pentest"]})
        self.write(self.tmp, {"status": "completed"})  # second write should preserve title
        result = self.read(self.tmp)
        assert result["title"] == "My custom title"
        assert result["tags"] == ["pentest"]
        assert result["status"] == "completed"

    def test_update_status(self):
        self.write(self.tmp, {"status": "running"})
        self.update_status(self.tmp, "completed", ended_at="2026-04-26T00:00:00Z")
        result = self.read(self.tmp)
        assert result["status"] == "completed"
        assert result["ended_at"] == "2026-04-26T00:00:00Z"

    def test_missing_file_returns_none(self):
        empty = self.tmp / "noexist"
        empty.mkdir()
        assert self.read(empty) is None

    def test_corrupt_file_returns_none(self):
        (self.tmp / "session_meta.json").write_text("NOT JSON", encoding="utf-8")
        assert self.read(self.tmp) is None

    def test_atomic_write(self):
        """Verify no tmp file left behind after write."""
        self.write(self.tmp, {"status": "running"})
        tmp_files = list(self.tmp.glob("*.tmp"))
        assert len(tmp_files) == 0


# ---------------------------------------------------------------------------
# listing (needs session_meta, no tracer)
# ---------------------------------------------------------------------------


def _make_run_dir(root: Path, name: str, **meta_kw) -> Path:
    """Helper to create a fake run dir with session_meta.json."""
    mod = _import_session_meta()
    run_dir = root / name
    run_dir.mkdir()
    mod.write_session_meta(run_dir, {"run_name": name, "status": "completed", **meta_kw})
    return run_dir


class TestListing:
    def setup_method(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _listing(self):
        import importlib.util
        import types

        root = Path(__file__).parents[1]

        def _load(mod_name: str, rel_path: str) -> types.ModuleType:
            spec = importlib.util.spec_from_file_location(mod_name, root / rel_path)
            mod = importlib.util.module_from_spec(spec)  # type: ignore[attr-defined]
            sys.modules[mod_name] = mod
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            return mod

        # Register stub packages before loading real modules
        for pkg in ("strix", "strix.sessions", "strix.telemetry"):
            sys.modules.setdefault(pkg, types.ModuleType(pkg))

        _load("strix.telemetry.session_meta", "strix/telemetry/session_meta.py")
        return _load("strix.sessions.listing", "strix/sessions/listing.py")

    def test_empty_root(self):
        mod = self._listing()
        rows = mod.list_sessions(runs_root=self.tmp)
        assert rows == []

    def test_returns_session_rows(self):
        _make_run_dir(self.tmp, "run-a")
        _make_run_dir(self.tmp, "run-b")
        mod = self._listing()
        rows = mod.list_sessions(runs_root=self.tmp)
        names = {r.run_name for r in rows}
        assert "run-a" in names
        assert "run-b" in names

    def test_most_recent_requires_conv_log(self):
        run_dir = _make_run_dir(self.tmp, "run-no-log")
        # no conversation.jsonl → has_conversation_log=False
        mod = self._listing()
        result = mod.most_recent(runs_root=self.tmp)
        assert result is None

    def test_most_recent_with_conv_log(self):
        run_dir = _make_run_dir(self.tmp, "run-with-log")
        (run_dir / "conversation.jsonl").write_text("{}", encoding="utf-8")
        mod = self._listing()
        result = mod.most_recent(runs_root=self.tmp)
        assert result is not None
        assert result.run_name == "run-with-log"

    def test_query_filter(self):
        _make_run_dir(self.tmp, "example-com-abc", first_prompt_summary="Focus on XSS")
        _make_run_dir(self.tmp, "github-repo-xyz", first_prompt_summary="Check auth flow")
        mod = self._listing()
        rows = mod.list_sessions(runs_root=self.tmp, query="xss")
        assert len(rows) == 1
        assert rows[0].run_name == "example-com-abc"

    def test_get_session_by_name(self):
        _make_run_dir(self.tmp, "my-scan")
        mod = self._listing()
        row = mod.get_session("my-scan", runs_root=self.tmp)
        assert row is not None
        assert row.run_name == "my-scan"

    def test_get_session_missing(self):
        mod = self._listing()
        assert mod.get_session("nonexistent", runs_root=self.tmp) is None
