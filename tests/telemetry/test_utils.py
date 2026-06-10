from unittest.mock import patch

import pytest

from strix.telemetry.utils import (
    _disable_threading_instrumentation,
    prune_otel_span_attributes,
)


def test_prune_otel_span_attributes_drops_high_volume_prompt_content() -> None:
    attributes = {
        "gen_ai.operation.name": "openai.chat",
        "gen_ai.request.model": "gpt-5.2",
        "gen_ai.prompt.0.role": "system",
        "gen_ai.prompt.0.content": "a" * 20_000,
        "gen_ai.completion.0.content": "b" * 10_000,
        "llm.input_messages.0.content": "c" * 5_000,
        "llm.output_messages.0.content": "d" * 5_000,
        "llm.input": "x" * 3_000,
        "llm.output": "y" * 3_000,
    }

    pruned = prune_otel_span_attributes(attributes)

    assert "gen_ai.prompt.0.content" not in pruned
    assert "gen_ai.completion.0.content" not in pruned
    assert "llm.input_messages.0.content" not in pruned
    assert "llm.output_messages.0.content" not in pruned
    assert "llm.input" not in pruned
    assert "llm.output" not in pruned
    assert pruned["gen_ai.operation.name"] == "openai.chat"
    assert pruned["gen_ai.prompt.0.role"] == "system"
    assert pruned["strix.filtered_attributes_count"] == 6


def test_prune_otel_span_attributes_keeps_metadata_when_nothing_is_dropped() -> None:
    attributes = {
        "gen_ai.operation.name": "openai.chat",
        "gen_ai.request.model": "gpt-5.2",
        "gen_ai.prompt.0.role": "user",
    }

    pruned = prune_otel_span_attributes(attributes)

    assert pruned == attributes


# SEC-6848: durable threading-wrap removal regression tests
# -----------------------------------------------------------


def test_disable_threading_instrumentation_calls_uninstrument() -> None:
    # Standard path: ThreadingInstrumentor is importable and
    # uninstrument runs cleanly.
    target = "opentelemetry.instrumentation.threading.ThreadingInstrumentor"
    with patch(target) as ti_cls:
        instance = ti_cls.return_value
        _disable_threading_instrumentation()
        ti_cls.assert_called_once_with()
        instance.uninstrument.assert_called_once_with()


def test_disable_threading_instrumentation_no_op_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If the threading instrumentor package isn't installed at all,
    # the import inside _disable_threading_instrumentation should
    # raise ImportError and the function should silently return.
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def fake_import(name, *args, **kwargs):
        if name == "opentelemetry.instrumentation.threading":
            raise ImportError("synthetic: package not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    # Must not raise.
    _disable_threading_instrumentation()


def test_disable_threading_instrumentation_logs_on_uninstrument_failure() -> None:
    # If uninstrument itself raises (defensive — shouldn't happen in
    # practice), the helper must NOT propagate the exception or the
    # bootstrap aborts and the wrap stays live. Log + continue.
    target = "opentelemetry.instrumentation.threading.ThreadingInstrumentor"
    with patch(target) as ti_cls:
        ti_cls.return_value.uninstrument.side_effect = RuntimeError("boom")
        # Should not raise.
        _disable_threading_instrumentation()
