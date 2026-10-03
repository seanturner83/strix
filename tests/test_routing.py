"""OODA turn routing: tier classification, backends, mode gating, delegation."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from strix.config import models, routing
from strix.config.models import _RoutingModel


if TYPE_CHECKING:
    import pytest


_TOOLS = ["a-tool"]  # non-empty => an agent turn


def _call(name: str) -> dict[str, Any]:
    return {"type": "function_call", "name": name}


def _tier(model_input: Any, tools: Any = _TOOLS) -> str:
    return asyncio.run(routing.classify_turn(model_input, tools))[0]


def test_mechanical_last_tool_is_mechanical_tier() -> None:
    assert _tier([_call("list_coverage")]) == "mechanical"
    assert _tier([_call("get_threat_model")]) == "mechanical"


def test_reasoning_tool_is_reasoning_tier() -> None:
    assert _tier([_call("browser")]) == "reasoning"


def test_uses_the_most_recent_call() -> None:
    conv = [_call("read_file"), {"type": "message"}, _call("python")]
    assert _tier(conv) == "reasoning"


def test_no_tools_is_non_agent_turn() -> None:
    tier, reason = asyncio.run(routing.classify_turn([_call("read_file")], []))
    assert tier == "reasoning"
    assert reason == "non-agent turn"


def test_no_recent_tool_defaults_to_reasoning() -> None:
    assert _tier([{"type": "message"}]) == "reasoning"


def test_mode_and_backend_gating(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_ROUTING", raising=False)
    monkeypatch.delenv("STRIX_ROUTING_BACKEND", raising=False)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert routing.routing_mode() == "off"
    # No explicit backend, no Jev endpoint -> heuristic floor.
    assert routing.routing_backend() == "heuristic"
    # No explicit backend but a Jev endpoint configured -> lean on Jev (S1).
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    assert routing.routing_backend() == "jev"
    # Explicit backend always wins.
    monkeypatch.setenv("STRIX_ROUTING_BACKEND", "heuristic")
    assert routing.routing_backend() == "heuristic"
    monkeypatch.setenv("STRIX_ROUTING", "shadow")
    assert routing.routing_mode() == "shadow"


def test_digest_is_compact_not_the_whole_context() -> None:
    conv = [
        _call("read_file"),
        {"type": "function_call_output", "output": "X" * 5000},
    ]
    d = routing.digest(conv)
    assert d["last_tool"] == "read_file"
    assert 0 < len(d["last_output"]) <= 600  # truncated, not the full 5000


def test_jev_backend_falls_back_to_heuristic_when_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_ROUTING_BACKEND", "jev")

    async def _none(_digest: dict[str, str]) -> None:
        return None

    monkeypatch.setattr("strix.config.jev_routing.jev_classify_tier", _none)
    # Jev unavailable → heuristic decides (mechanical tool → mechanical tier).
    assert _tier([_call("list_coverage")]) == "mechanical"


def test_shadow_model_delegates_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shadow mode must classify but never alter what the inner model returns."""
    monkeypatch.setenv("STRIX_ROUTING", "shadow")
    monkeypatch.delenv("STRIX_ROUTING_BACKEND", raising=False)
    sentinel = object()
    seen: dict[str, Any] = {}

    class _FakeInner:
        async def get_response(self, *_args: Any, **_kwargs: Any) -> Any:
            seen["called"] = True
            return sentinel

    def _factory(_model_id: str, _api_base: str | None) -> Any:
        raise AssertionError("shadow mode must not build a tier model")

    model = _RoutingModel(_FakeInner(), _factory)  # type: ignore[arg-type]
    result = asyncio.run(
        model.get_response(
            None,
            [_call("read_file")],
            None,  # type: ignore[arg-type]
            _TOOLS,  # type: ignore[arg-type]
            None,
            [],
            None,  # type: ignore[arg-type]
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
    )
    assert result is sentinel
    assert seen.get("called") is True


def test_classify_mission_uses_jev_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_ROUTING_BACKEND", "jev")

    async def _jev(_task: str) -> tuple[str, str]:
        return "standard", "jev mission"

    monkeypatch.setattr("strix.config.jev_routing.jev_classify_mission", _jev)
    tier, _ = asyncio.run(routing.classify_mission("recon the /api surface"))
    assert tier == "standard"


def test_classify_mission_defaults_safe_without_jev(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_ROUTING_BACKEND", "heuristic")
    tier, _ = asyncio.run(routing.classify_mission("exploit the SQLi at /login"))
    assert tier == "reasoning"  # heuristic can't read a mission -> safe tier


def test_subagent_routing_off_when_not_live(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_ROUTING", "shadow")  # not live
    assert asyncio.run(models.subagent_model_for_task("any mission")) is None


def test_subagent_routing_builds_tier_model_when_live(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_ROUTING", "live")

    async def _mission(_task: str) -> tuple[str, str]:
        return "mechanical", "test"

    sentinel = object()
    seen: dict[str, Any] = {}

    def _factory(model_id: str, _api_base: str | None) -> Any:
        seen["model_id"] = model_id
        return sentinel

    monkeypatch.setattr("strix.config.routing.classify_mission", _mission)
    monkeypatch.setattr(models, "_tier_model_factory", _factory)
    for t in ("MECHANICAL", "STANDARD", "REASONING"):
        monkeypatch.delenv(f"STRIX_TIER_{t}", raising=False)
    monkeypatch.delenv("STRIX_ROUTE_POLICY", raising=False)

    result = asyncio.run(models.subagent_model_for_task("list the open ports"))
    assert result is sentinel
    assert seen["model_id"] == "claude-code/claude-haiku-4-5"  # mechanical -> haiku


def test_live_mode_routes_to_the_tier_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """Un-pinned live mode serves the turn from the tier's model, not the default."""
    monkeypatch.setenv("STRIX_ROUTING", "live")
    monkeypatch.setenv("STRIX_ROUTING_PIN_ORCHESTRATOR", "0")  # allow per-turn downgrade
    monkeypatch.delenv("STRIX_ROUTING_BACKEND", raising=False)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)  # -> heuristic backend
    for tier in ("MECHANICAL", "STANDARD", "REASONING"):
        monkeypatch.delenv(f"STRIX_TIER_{tier}", raising=False)
    default_sentinel, tier_sentinel = object(), object()
    built: dict[str, Any] = {}

    class _Default:
        async def get_response(self, *_a: Any, **_k: Any) -> Any:
            return default_sentinel

    class _Tier:
        async def get_response(self, *_a: Any, **_k: Any) -> Any:
            return tier_sentinel

    def _factory(model_id: str, _api_base: str | None) -> Any:
        built["model_id"] = model_id
        return _Tier()

    model = _RoutingModel(_Default(), _factory)  # type: ignore[arg-type]
    # A mechanical tool -> mechanical tier -> haiku in the default map.
    result = asyncio.run(
        model.get_response(
            None,
            [_call("list_coverage")],
            None,  # type: ignore[arg-type]
            _TOOLS,  # type: ignore[arg-type]
            None,
            [],
            None,  # type: ignore[arg-type]
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
    )
    assert result is tier_sentinel  # routed to the tier model, not the default
    assert built["model_id"] == "claude-code/claude-haiku-4-5"


def test_pinned_live_serves_default_not_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pinned (default): live mode classifies/logs the plan but serves the default —
    the root/orchestrator is never downgraded to a cheap tier by the per-turn routingr."""
    monkeypatch.setenv("STRIX_ROUTING", "live")
    monkeypatch.delenv("STRIX_ROUTING_PIN_ORCHESTRATOR", raising=False)  # default = pinned
    monkeypatch.delenv("STRIX_ROUTING_BACKEND", raising=False)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    for tier in ("MECHANICAL", "STANDARD", "REASONING"):
        monkeypatch.delenv(f"STRIX_TIER_{tier}", raising=False)
    default_sentinel = object()

    class _Default:
        async def get_response(self, *_a: Any, **_k: Any) -> Any:
            return default_sentinel

    def _factory(_model_id: str, _api_base: str | None) -> Any:
        raise AssertionError("pinned mode must not build or route to a tier model")

    model = _RoutingModel(_Default(), _factory)  # type: ignore[arg-type]
    result = asyncio.run(
        model.get_response(
            None,
            [_call("list_coverage")],  # a mechanical turn that would normally downgrade
            None,  # type: ignore[arg-type]
            _TOOLS,  # type: ignore[arg-type]
            None,
            [],
            None,  # type: ignore[arg-type]
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
    )
    assert result is default_sentinel  # root stayed on its own model


def test_pin_orchestrator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_ROUTING_PIN_ORCHESTRATOR", raising=False)
    assert routing.pin_orchestrator() is True  # pinned by default
    for off in ("0", "false", "no", "off", "OFF"):
        monkeypatch.setenv("STRIX_ROUTING_PIN_ORCHESTRATOR", off)
        assert routing.pin_orchestrator() is False, off


class _FakeResp:
    def __init__(self, tool_names: list[str]) -> None:
        self.output = [SimpleNamespace(type="function_call", name=t) for t in tool_names]


def test_audit_rate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_ROUTING_AUDIT_RATE", raising=False)
    assert routing.audit_rate() == 0.0
    monkeypatch.setenv("STRIX_ROUTING_AUDIT_RATE", "0.05")
    assert routing.audit_rate() == 0.05
    monkeypatch.setenv("STRIX_ROUTING_AUDIT_RATE", "9")  # clamped to 1.0
    assert routing.audit_rate() == 1.0


def test_tool_names_extracts_function_calls() -> None:
    assert models._tool_names(_FakeResp(["shell", "browser"])) == {"shell", "browser"}


def _audit(monkeypatch: pytest.MonkeyPatch, tier: str, rate: str) -> int:
    monkeypatch.setenv("STRIX_ROUTING_AUDIT_RATE", rate)
    calls = {"frontier": 0}

    class _Frontier:
        async def get_response(self, *_a: Any, **_k: Any) -> Any:
            calls["frontier"] += 1
            return _FakeResp(["shell"])

    model = _RoutingModel(object(), lambda _m, _b: _Frontier())  # type: ignore[arg-type]
    asyncio.run(
        model._maybe_audit(
            tier,
            _FakeResp(["shell"]),
            system_instructions=None,
            input=[],
            model_settings=None,  # type: ignore[arg-type]
            tools=[],
            output_schema=None,
            handoffs=[],
            tracing=None,  # type: ignore[arg-type]
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
    )
    return calls["frontier"]


def test_audit_fires_on_downgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _audit(monkeypatch, "mechanical", "1.0") == 1  # frontier ran for comparison


def test_audit_skips_reasoning_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _audit(monkeypatch, "reasoning", "1.0") == 0  # no self-audit of the frontier


def test_audit_rate_zero_never_fires(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _audit(monkeypatch, "mechanical", "0") == 0
