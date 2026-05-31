import json
import sys
import types
from pathlib import Path
from typing import Any, ClassVar

import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExportResult

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.agents_graph import agents_graph_actions


def _load_events(events_path: Path) -> list[dict[str, Any]]:
    lines = events_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line]


@pytest.fixture(autouse=True)
def _reset_tracer_globals(monkeypatch) -> None:
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.delenv("TRACELOOP_BASE_URL", raising=False)
    monkeypatch.delenv("TRACELOOP_API_KEY", raising=False)
    monkeypatch.delenv("TRACELOOP_HEADERS", raising=False)


def test_tracer_local_mode_writes_jsonl_with_correlation(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("local-observability")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["https://example.com"], "user_instructions": "focus auth"})
    tracer.log_agent_creation("agent-1", "Root Agent", "scan auth")
    tracer.log_chat_message("starting scan", "user", "agent-1")
    execution_id = tracer.log_tool_execution_start(
        "agent-1",
        "send_request",
        {"url": "https://example.com/login"},
    )
    tracer.update_tool_execution(execution_id, "completed", {"status_code": 200, "body": "ok"})

    events_path = tmp_path / "strix_runs" / "local-observability" / "events.jsonl"
    assert events_path.exists()

    events = _load_events(events_path)
    assert any(event["event_type"] == "tool.execution.updated" for event in events)
    assert not any(event["event_type"] == "traffic.intercepted" for event in events)

    for event in events:
        assert event["run_id"] == "local-observability"
        assert event["trace_id"]
        assert event["span_id"]


def test_tracer_redacts_sensitive_payloads(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("redaction-run")
    set_global_tracer(tracer)
    execution_id = tracer.log_tool_execution_start(
        "agent-1",
        "send_request",
        {
            "url": "https://example.com",
            "api_key": "sk-secret-token-value",
            "authorization": "Bearer super-secret-token",
        },
    )
    tracer.update_tool_execution(
        execution_id,
        "error",
        {"error": "request failed with token sk-secret-token-value"},
    )

    events_path = tmp_path / "strix_runs" / "redaction-run" / "events.jsonl"
    events = _load_events(events_path)
    serialized = json.dumps(events)

    assert "sk-secret-token-value" not in serialized
    assert "super-secret-token" not in serialized
    assert "[REDACTED]" in serialized


def test_tracer_remote_mode_configures_traceloop_export(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    class FakeTraceloop:
        init_calls: ClassVar[list[dict[str, Any]]] = []

        @staticmethod
        def init(**kwargs: Any) -> None:
            FakeTraceloop.init_calls.append(kwargs)

        @staticmethod
        def set_association_properties(properties: dict[str, Any]) -> None:  # noqa: ARG004
            return None

    monkeypatch.setattr(tracer_module, "Traceloop", FakeTraceloop)
    monkeypatch.setenv("TRACELOOP_BASE_URL", "https://otel.example.com")
    monkeypatch.setenv("TRACELOOP_API_KEY", "test-api-key")
    monkeypatch.setenv("TRACELOOP_HEADERS", '{"x-custom":"header"}')

    tracer = Tracer("remote-observability")
    set_global_tracer(tracer)
    tracer.log_chat_message("hello", "user", "agent-1")

    assert tracer._remote_export_enabled is True
    assert FakeTraceloop.init_calls
    init_kwargs = FakeTraceloop.init_calls[-1]
    assert init_kwargs["api_endpoint"] == "https://otel.example.com"
    assert init_kwargs["api_key"] == "test-api-key"
    assert init_kwargs["headers"] == {"x-custom": "header"}
    assert isinstance(init_kwargs["processor"], SimpleSpanProcessor)
    assert "strix.run_id" not in init_kwargs["resource_attributes"]
    assert "strix.run_name" not in init_kwargs["resource_attributes"]

    events_path = tmp_path / "strix_runs" / "remote-observability" / "events.jsonl"
    events = _load_events(events_path)
    run_started = next(event for event in events if event["event_type"] == "run.started")
    assert run_started["payload"]["remote_export_enabled"] is True


def test_tracer_local_mode_avoids_traceloop_remote_endpoint(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    class FakeTraceloop:
        init_calls: ClassVar[list[dict[str, Any]]] = []

        @staticmethod
        def init(**kwargs: Any) -> None:
            FakeTraceloop.init_calls.append(kwargs)

        @staticmethod
        def set_association_properties(properties: dict[str, Any]) -> None:  # noqa: ARG004
            return None

    monkeypatch.setattr(tracer_module, "Traceloop", FakeTraceloop)

    tracer = Tracer("local-traceloop")
    set_global_tracer(tracer)
    tracer.log_chat_message("hello", "user", "agent-1")

    assert FakeTraceloop.init_calls
    init_kwargs = FakeTraceloop.init_calls[-1]
    assert "api_endpoint" not in init_kwargs
    assert "api_key" not in init_kwargs
    assert "headers" not in init_kwargs
    assert isinstance(init_kwargs["processor"], SimpleSpanProcessor)
    assert tracer._remote_export_enabled is False


def test_otlp_fallback_includes_auth_and_custom_headers(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "Traceloop", None)
    monkeypatch.setenv("TRACELOOP_BASE_URL", "https://otel.example.com")
    monkeypatch.setenv("TRACELOOP_API_KEY", "test-api-key")
    monkeypatch.setenv("TRACELOOP_HEADERS", '{"x-custom":"header"}')

    captured: dict[str, Any] = {}

    class FakeOTLPSpanExporter:
        def __init__(self, endpoint: str, headers: dict[str, str] | None = None, **kwargs: Any):
            captured["endpoint"] = endpoint
            captured["headers"] = headers or {}
            captured["kwargs"] = kwargs

        def export(self, spans: Any) -> SpanExportResult:  # noqa: ARG002
            return SpanExportResult.SUCCESS

        def shutdown(self) -> None:
            return None

        def force_flush(self, timeout_millis: int = 30_000) -> bool:  # noqa: ARG002
            return True

    fake_module = types.ModuleType("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    fake_module.OTLPSpanExporter = FakeOTLPSpanExporter
    monkeypatch.setitem(
        sys.modules,
        "opentelemetry.exporter.otlp.proto.http.trace_exporter",
        fake_module,
    )

    tracer = Tracer("otlp-fallback")
    set_global_tracer(tracer)

    assert tracer._remote_export_enabled is True
    assert captured["endpoint"] == "https://otel.example.com/v1/traces"
    assert captured["headers"]["Authorization"] == "Bearer test-api-key"
    assert captured["headers"]["x-custom"] == "header"


def test_traceloop_init_failure_does_not_mark_bootstrapped_on_provider_failure(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.chdir(tmp_path)

    class FakeTraceloop:
        @staticmethod
        def init(**kwargs: Any) -> None:  # noqa: ARG004
            raise RuntimeError("traceloop init failed")

        @staticmethod
        def set_association_properties(properties: dict[str, Any]) -> None:  # noqa: ARG004
            return None

    monkeypatch.setattr(tracer_module, "Traceloop", FakeTraceloop)

    def _raise_provider_error(provider: Any) -> None:
        raise RuntimeError("provider setup failed")

    monkeypatch.setattr(tracer_module.trace, "set_tracer_provider", _raise_provider_error)

    tracer = Tracer("bootstrap-failure")
    set_global_tracer(tracer)

    assert tracer_module._OTEL_BOOTSTRAPPED is False
    assert tracer._remote_export_enabled is False


def test_run_completed_event_emitted_once(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("single-complete")
    set_global_tracer(tracer)
    tracer.save_run_data(mark_complete=True)
    tracer.save_run_data(mark_complete=True)

    events_path = tmp_path / "strix_runs" / "single-complete" / "events.jsonl"
    events = _load_events(events_path)
    run_completed = [event for event in events if event["event_type"] == "run.completed"]
    assert len(run_completed) == 1


def test_events_with_agent_id_include_agent_name(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("agent-name-enrichment")
    set_global_tracer(tracer)
    tracer.log_agent_creation("agent-1", "Root Agent", "scan auth")
    tracer.log_chat_message("hello", "assistant", "agent-1")

    events_path = tmp_path / "strix_runs" / "agent-name-enrichment" / "events.jsonl"
    events = _load_events(events_path)
    chat_event = next(event for event in events if event["event_type"] == "chat.message")

    assert chat_event["actor"]["agent_id"] == "agent-1"
    assert chat_event["actor"]["agent_name"] == "Root Agent"


def test_get_total_llm_stats_includes_completed_subagents(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    class DummyStats:
        def __init__(
            self,
            *,
            input_tokens: int,
            output_tokens: int,
            cached_tokens: int,
            cost: float,
            requests: int,
        ) -> None:
            self.input_tokens = input_tokens
            self.output_tokens = output_tokens
            self.cached_tokens = cached_tokens
            self.cost = cost
            self.requests = requests

    class DummyLLM:
        def __init__(self, stats: DummyStats) -> None:
            self._total_stats = stats

    class DummyAgent:
        def __init__(self, stats: DummyStats) -> None:
            self.llm = DummyLLM(stats)

    tracer = Tracer("cost-rollup")
    set_global_tracer(tracer)

    monkeypatch.setattr(
        agents_graph_actions,
        "_agent_instances",
        {
            "root-agent": DummyAgent(
                DummyStats(
                    input_tokens=1_000,
                    output_tokens=250,
                    cached_tokens=100,
                    cost=0.12345,
                    requests=2,
                )
            )
        },
    )
    monkeypatch.setattr(
        agents_graph_actions,
        "_completed_agent_llm_totals",
        {
            "input_tokens": 2_000,
            "output_tokens": 500,
            "cached_tokens": 400,
            "cost": 0.54321,
            "requests": 3,
        },
    )

    stats = tracer.get_total_llm_stats()

    assert stats["total"] == {
        "input_tokens": 3_000,
        "output_tokens": 750,
        "cached_tokens": 500,
        "cost": 0.6667,
        "requests": 5,
    }
    assert stats["total_tokens"] == 3_750


def test_run_metadata_is_only_on_run_lifecycle_events(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("metadata-scope")
    set_global_tracer(tracer)
    tracer.log_chat_message("hello", "assistant", "agent-1")
    tracer.save_run_data(mark_complete=True)

    events_path = tmp_path / "strix_runs" / "metadata-scope" / "events.jsonl"
    events = _load_events(events_path)

    run_started = next(event for event in events if event["event_type"] == "run.started")
    run_completed = next(event for event in events if event["event_type"] == "run.completed")
    chat_event = next(event for event in events if event["event_type"] == "chat.message")

    assert "run_metadata" in run_started
    assert "run_metadata" in run_completed
    assert "run_metadata" not in chat_event


def test_set_run_name_resets_cached_paths(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer()
    set_global_tracer(tracer)
    old_events_path = tracer.events_file_path

    tracer.set_run_name("renamed-run")
    tracer.log_chat_message("hello", "assistant", "agent-1")

    new_events_path = tracer.events_file_path
    assert new_events_path != old_events_path
    assert new_events_path == tmp_path / "strix_runs" / "renamed-run" / "events.jsonl"

    events = _load_events(new_events_path)
    assert any(event["event_type"] == "run.started" for event in events)
    assert any(event["event_type"] == "chat.message" for event in events)


def test_set_run_name_resets_run_completed_flag(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer()
    set_global_tracer(tracer)

    tracer.save_run_data(mark_complete=True)
    tracer.set_run_name("renamed-complete")
    tracer.save_run_data(mark_complete=True)

    events_path = tmp_path / "strix_runs" / "renamed-complete" / "events.jsonl"
    events = _load_events(events_path)
    run_completed = [event for event in events if event["event_type"] == "run.completed"]

    assert any(event["event_type"] == "run.started" for event in events)
    assert len(run_completed) == 1


def test_set_run_name_updates_traceloop_association_properties(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    class FakeTraceloop:
        associations: ClassVar[list[dict[str, Any]]] = []

        @staticmethod
        def init(**kwargs: Any) -> None:  # noqa: ARG004
            return None

        @staticmethod
        def set_association_properties(properties: dict[str, Any]) -> None:
            FakeTraceloop.associations.append(properties)

    monkeypatch.setattr(tracer_module, "Traceloop", FakeTraceloop)

    tracer = Tracer()
    set_global_tracer(tracer)
    tracer.set_run_name("renamed-run")

    assert FakeTraceloop.associations
    assert FakeTraceloop.associations[-1]["run_id"] == "renamed-run"
    assert FakeTraceloop.associations[-1]["run_name"] == "renamed-run"


def test_events_write_locks_are_scoped_by_events_file(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")

    tracer_one = Tracer("lock-run-a")
    tracer_two = Tracer("lock-run-b")

    lock_a_from_one = tracer_one._get_events_write_lock(tracer_one.events_file_path)
    lock_a_from_two = tracer_two._get_events_write_lock(tracer_one.events_file_path)
    lock_b = tracer_two._get_events_write_lock(tracer_two.events_file_path)

    assert lock_a_from_one is lock_a_from_two
    assert lock_a_from_one is not lock_b


def test_tracer_skips_jsonl_when_telemetry_disabled(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")

    tracer = Tracer("telemetry-disabled")
    set_global_tracer(tracer)
    tracer.log_chat_message("hello", "assistant", "agent-1")
    tracer.save_run_data(mark_complete=True)

    events_path = tmp_path / "strix_runs" / "telemetry-disabled" / "events.jsonl"
    assert not events_path.exists()


def test_tracer_otel_flag_overrides_global_telemetry(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_OTEL_TELEMETRY", "1")

    tracer = Tracer("otel-enabled")
    set_global_tracer(tracer)
    tracer.log_chat_message("hello", "assistant", "agent-1")
    tracer.save_run_data(mark_complete=True)

    events_path = tmp_path / "strix_runs" / "otel-enabled" / "events.jsonl"
    assert events_path.exists()


# ----------------------------------------------------------------------------
# cleanup() idempotency — guards against the dual-write that bit production
# on 2026-05-20 (timeout-killed scan emitted session_end with completed:True
# on second cleanup invocation, masking the failure as success).
# ----------------------------------------------------------------------------
def _read_session_end_events(run_dir: Path) -> list[dict[str, Any]]:
    conv_path = run_dir / "conversation.jsonl"
    if not conv_path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in conv_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("type") == "session_end":
            out.append(entry)
    return out


def _attach_real_conversation_log(tracer: Tracer, run_dir: Path) -> None:
    from strix.telemetry.conversation_log import ConversationLog

    run_dir.mkdir(parents=True, exist_ok=True)
    tracer._conversation_log = ConversationLog(run_dir, tracer.run_name or "test-run")


def test_cleanup_emits_session_end_only_once(monkeypatch, tmp_path) -> None:
    """First cleanup() emits session_end. Second cleanup() must be a no-op."""
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("cleanup-idempotency")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "cleanup-idempotency"
    _attach_real_conversation_log(tracer, run_dir)

    # Simulate a timeout-killed scan: status stays "running", no
    # final_scan_result, then cleanup is invoked twice (signal handler
    # + atexit pattern).
    assert tracer.run_metadata["status"] == "running"
    tracer.cleanup()
    tracer.cleanup()

    events = _read_session_end_events(run_dir)
    assert len(events) == 1, f"expected exactly one session_end, got {len(events)}: {events}"
    assert events[0]["completed"] is False, (
        f"timeout-killed scan must report completed=False, got {events[0]}"
    )


def test_cleanup_preserves_real_completion_flag(monkeypatch, tmp_path) -> None:
    """A genuine completion (final_scan_result populated) reports completed=True
    even with the idempotency guard."""
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("cleanup-real-success")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "cleanup-real-success"
    _attach_real_conversation_log(tracer, run_dir)

    tracer.final_scan_result = "# Executive Summary\n\nAll done."
    tracer.cleanup()

    events = _read_session_end_events(run_dir)
    assert len(events) == 1
    assert events[0]["completed"] is True


def test_cleanup_idempotency_does_not_block_save_run_data(monkeypatch, tmp_path) -> None:
    """cleanup() guard must not interfere with subsequent direct calls
    to save_run_data() — only re-entry into cleanup() itself is blocked."""
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("cleanup-save-after")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "cleanup-save-after"
    _attach_real_conversation_log(tracer, run_dir)

    tracer.cleanup()
    # Direct call after cleanup should still succeed (no exception).
    tracer.save_run_data(mark_complete=True)
    assert tracer.run_metadata["status"] == "completed"


# ----------------------------------------------------------------------------
# SEC-6635: SARIF emit on zero-findings + orchestrator_success completion signal.
#
# Background: prior tracer behaviour skipped SARIF emission entirely when
# vulnerability_reports was empty. GHAS code-scanning needs a Strix-driver
# SARIF (results may be []) to auto-close prior alerts under the same tool
# name on the same ref. Without it, stale alerts persist and block PR merges
# (concrete instance: seedcx/external-api#97 stuck on alerts #294 + #295).
#
# Also: the legacy `completed` heuristic in cleanup() relied on
# `bool(final_scan_result)`, which misses clean zero-findings scans that
# never write an Executive Summary. orchestrator_success is the explicit
# signal the agent loop now sets on clean exit.
# ----------------------------------------------------------------------------
def test_save_run_data_emits_empty_sarif_on_zero_findings(monkeypatch, tmp_path) -> None:
    """A completed scan with zero findings must still emit findings.sarif
    with a Strix driver block + results=[] so GHAS can auto-close stale
    alerts on the same ref."""
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("zero-findings")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "zero-findings"
    _attach_real_conversation_log(tracer, run_dir)

    # No vulnerability_reports added — simulate a clean scan that found
    # nothing. save_run_data(mark_complete=True) is the contract for
    # "this is the final state of the run".
    assert tracer.vulnerability_reports == []
    tracer.save_run_data(mark_complete=True)

    sarif_path = run_dir / "findings.sarif"
    assert sarif_path.exists(), "findings.sarif must be written on completion even with zero findings"
    doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Strix"
    assert doc["runs"][0]["results"] == []


def test_save_run_data_skips_sarif_when_not_mark_complete(monkeypatch, tmp_path) -> None:
    """Periodic save_run_data() calls during a scan (mark_complete=False)
    must not emit SARIF — only the final completion writes it. Otherwise
    a partial mid-scan SARIF could overwrite a populated one on rerun."""
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("periodic-save")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "periodic-save"
    _attach_real_conversation_log(tracer, run_dir)

    tracer.save_run_data(mark_complete=False)
    assert not (run_dir / "findings.sarif").exists()


def test_orchestrator_success_true_overrides_legacy_heuristic(monkeypatch, tmp_path) -> None:
    """A clean zero-findings exit with orchestrator_success=True must
    report completed=True even though final_scan_result is None and
    run_metadata.status was "running" when cleanup ran."""
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("clean-zero-findings")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "clean-zero-findings"
    _attach_real_conversation_log(tracer, run_dir)

    # Agent loop reached clean exit but had nothing to report.
    tracer.mark_orchestrator_success(True)
    assert tracer.final_scan_result is None  # legacy heuristic would say errored
    tracer.cleanup()

    events = _read_session_end_events(run_dir)
    assert len(events) == 1
    assert events[0]["completed"] is True, (
        "orchestrator_success=True must win over the legacy "
        "bool(final_scan_result) heuristic for clean zero-findings exits"
    )


def test_orchestrator_success_false_overrides_legacy_heuristic(monkeypatch, tmp_path) -> None:
    """An explicit orchestrator_success=False must report completed=False
    even if final_scan_result happens to be populated (e.g. partial
    summary written before abort)."""
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("aborted-with-summary")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "aborted-with-summary"
    _attach_real_conversation_log(tracer, run_dir)

    tracer.final_scan_result = "# Partial summary written before abort"
    tracer.mark_orchestrator_success(False)
    tracer.cleanup()

    events = _read_session_end_events(run_dir)
    assert len(events) == 1
    assert events[0]["completed"] is False, (
        "orchestrator_success=False must override truthy final_scan_result"
    )


def test_orchestrator_success_unset_falls_back_to_legacy(monkeypatch, tmp_path) -> None:
    """When the agent loop hasn't set orchestrator_success (older callers,
    ad-hoc Tracer instantiation, etc.), cleanup() falls back to the
    legacy run_metadata.status / final_scan_result heuristic — preserving
    backward compatibility with the existing test_cleanup_* suite."""
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("legacy-unset")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "legacy-unset"
    _attach_real_conversation_log(tracer, run_dir)

    assert tracer.orchestrator_success is None
    tracer.final_scan_result = "# Executive Summary\n\nLegacy success path."
    tracer.cleanup()

    events = _read_session_end_events(run_dir)
    assert len(events) == 1
    assert events[0]["completed"] is True


def test_finalize_session_meta_with_populated_tool_executions(monkeypatch, tmp_path) -> None:
    """Regression: _finalize_session_meta computes iteration_count over
    self.tool_executions.values() — not over per-agent tool_executions
    (which is a list[int] of execution IDs, not dicts). The original
    expression tried `.get("iteration")` on those ints and failed with
    AttributeError; bare `pass` masked it in production. Surfaced once
    the bare-pass was replaced with logger.exception (SEC-6635 dispatch
    on external-api, run 26188539567)."""
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("finalize-iter-count")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "finalize-iter-count"
    _attach_real_conversation_log(tracer, run_dir)

    # Mirror the production shape: agents indexed by int execution IDs
    # into a separate tool_executions dict.
    tracer.agents["agent-1"] = {"name": "subagent", "tool_executions": [1, 2, 3]}
    tracer.tool_executions[1] = {"tool": "read", "iteration": 5}
    tracer.tool_executions[2] = {"tool": "grep", "iteration": 7}
    tracer.tool_executions[3] = {"tool": "edit", "iteration": 11}

    # Must not raise. Side effect: session_meta.json gets written.
    tracer.mark_orchestrator_success(True)
    tracer._finalize_session_meta(True)

    meta = json.loads((run_dir / "session_meta.json").read_text(encoding="utf-8"))
    assert meta["status"] == "completed"
    assert meta["iteration_count"] == 11, (
        f"iteration_count should be the max iteration across tool_executions; "
        f"got {meta['iteration_count']}"
    )


def test_finalize_session_meta_with_no_tool_executions(monkeypatch, tmp_path) -> None:
    """Empty tool_executions (e.g. scan exited before any tool ran) must
    not raise; iteration_count defaults to 0."""
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("finalize-no-tools")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "finalize-no-tools"
    _attach_real_conversation_log(tracer, run_dir)

    assert tracer.tool_executions == {}
    tracer._finalize_session_meta(True)

    meta = json.loads((run_dir / "session_meta.json").read_text(encoding="utf-8"))
    assert meta["iteration_count"] == 0


# ---------------------------------------------------------------------------
# Three-state status classification: completed / partial / errored
#
# Prior behaviour collapsed everything that wasn't completed=True into
# "errored" — losing the distinction between "scan crashed before doing
# anything" and "scan ran out of iteration budget but found CVSS-9.9 stuff".
# The latter is shippable; the former isn't. Tested here to keep that
# semantic stable.
# ---------------------------------------------------------------------------


def test_status_completed_on_clean_orchestrator_success(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    tracer = Tracer("status-completed")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "status-completed"
    _attach_real_conversation_log(tracer, run_dir)

    tracer.add_vulnerability_report(title="finding 1", severity="high")
    tracer._finalize_session_meta(True)

    meta = json.loads((run_dir / "session_meta.json").read_text(encoding="utf-8"))
    assert meta["status"] == "completed"


def test_status_partial_when_findings_but_no_clean_exit(monkeypatch, tmp_path) -> None:
    """Iteration-budget exhaustion / OTel-threading race after findings
    persisted = 'partial'. Findings are real; CI should ingest them."""
    monkeypatch.chdir(tmp_path)
    tracer = Tracer("status-partial-findings")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "status-partial-findings"
    _attach_real_conversation_log(tracer, run_dir)

    tracer.add_vulnerability_report(title="finding 1", severity="critical")
    tracer.add_vulnerability_report(title="finding 2", severity="high")

    tracer._finalize_session_meta(False)

    meta = json.loads((run_dir / "session_meta.json").read_text(encoding="utf-8"))
    assert meta["status"] == "partial"
    assert meta["vulnerability_count"] == 2


def test_status_partial_when_iterations_but_no_findings(monkeypatch, tmp_path) -> None:
    """Forward progress (iterations ran) without findings is still 'partial' —
    distinguishes 'scan ran clean and found nothing real' from 'scan never
    started'. Both deserve different operator responses."""
    monkeypatch.chdir(tmp_path)
    tracer = Tracer("status-partial-iters")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "status-partial-iters"
    _attach_real_conversation_log(tracer, run_dir)

    tracer.tool_executions[1] = {"tool": "grep", "iteration": 3}
    tracer.tool_executions[2] = {"tool": "read", "iteration": 4}

    tracer._finalize_session_meta(False)

    meta = json.loads((run_dir / "session_meta.json").read_text(encoding="utf-8"))
    assert meta["status"] == "partial"
    assert meta["iteration_count"] == 4
    assert meta["vulnerability_count"] == 0


def test_status_errored_when_no_progress_no_findings(monkeypatch, tmp_path) -> None:
    """True failure: orchestrator did not succeed, no tools ran, no findings.
    The only state where 'errored' is the right signal."""
    monkeypatch.chdir(tmp_path)
    tracer = Tracer("status-errored")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "status-errored"
    _attach_real_conversation_log(tracer, run_dir)

    assert tracer.tool_executions == {}
    assert tracer.vulnerability_reports == []

    tracer._finalize_session_meta(False)

    meta = json.loads((run_dir / "session_meta.json").read_text(encoding="utf-8"))
    assert meta["status"] == "errored"
    assert meta["iteration_count"] == 0
    assert meta["vulnerability_count"] == 0


def test_update_scan_final_fields_sets_orchestrator_success(monkeypatch, tmp_path) -> None:
    """The canonical 'scan finished cleanly' hook (update_scan_final_fields)
    must set orchestrator_success=True so cleanup() reports completed=True
    via the new signal, not just the legacy heuristic."""
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("update-final-fields")
    set_global_tracer(tracer)
    run_dir = tmp_path / "strix_runs" / "update-final-fields"
    _attach_real_conversation_log(tracer, run_dir)

    assert tracer.orchestrator_success is None
    tracer.update_scan_final_fields(
        executive_summary="Done.",
        methodology="Read code.",
        technical_analysis="N/A.",
        recommendations="None.",
    )
    assert tracer.orchestrator_success is True
