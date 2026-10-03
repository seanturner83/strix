"""A routed sub-agent must actually RUN on its tier model.

Regression: RunConfig.model overrides every agent's model, so binding only
child_agent.model was silently ignored and routed sub-agents ran on the
orchestrator model. spawn_child_agent must hand the child a run_config whose
model IS the routed tier model.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from agents import RunConfig

from strix.core import execution


if TYPE_CHECKING:
    import pytest


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _spawn(monkeypatch: pytest.MonkeyPatch, routed: Any) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    async def _route(_task: str) -> Any:
        return routed

    async def _start(**kw: Any) -> None:
        captured["run_config"] = kw["run_config"]
        captured["agent"] = kw["child_agent"]

    async def _register(*_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr("strix.config.models.subagent_model_for_task", _route)
    monkeypatch.setattr(execution, "_start_child_runner", _start)
    monkeypatch.setattr(execution, "child_initial_input", lambda **_k: "init")

    base = RunConfig(model="orchestrator-default")
    _run(
        execution.spawn_child_agent(
            coordinator=SimpleNamespace(register=_register),
            factory=lambda **_k: SimpleNamespace(model="factory-default"),
            agents_db_path=None,  # type: ignore[arg-type]
            sessions_to_close=[],
            run_config=base,
            max_turns=5,
            interactive=False,
            parent_ctx={"agent_id": "root"},
            name="validator",
            task="validate the SQLi at /login",
            skills=[],
            parent_history=[],
        )
    )
    captured["base"] = base
    return captured


def test_routed_subagent_runs_under_its_tier_model(monkeypatch: pytest.MonkeyPatch) -> None:
    tier_model = object()  # the Model object subagent_model_for_task returns
    got = _spawn(monkeypatch, routed=tier_model)
    # the child runs under a run_config whose model IS the routed tier model,
    # not the orchestrator default that RunConfig.model would otherwise force
    assert got["run_config"].model is tier_model
    assert got["run_config"] is not got["base"]  # a distinct per-child config
    assert got["agent"].model is tier_model


def test_unrouted_subagent_keeps_the_shared_run_config(monkeypatch: pytest.MonkeyPatch) -> None:
    got = _spawn(monkeypatch, routed=None)  # routing off / no model
    assert got["run_config"] is got["base"]  # unchanged
    assert got["run_config"].model == "orchestrator-default"
