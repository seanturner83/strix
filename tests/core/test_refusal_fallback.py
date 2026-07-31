"""Refusal fallback + bounded recovery in the non-interactive execution loop.

When an agent turn yields no actionable (lifecycle) output — the shape a
provider content-filter refusal takes on the Bedrock Converse path, where a
blocked turn arrives as an empty message — the loop should:

  * swap the blocked model for its ``STRIX_LLM_FALLBACK`` mapping and retry the
    same session (prior context carries over), and
  * with no fallback mapped, fail after a small bounded number of recovery
    attempts rather than burning the whole turn budget re-prompting a model
    that will keep refusing (a fable-5 offensive scan burned ~$84 / 262 turns
    this way before the cap, 2026-07-09).
"""

from __future__ import annotations

import pytest
from agents import RunConfig
from agents.exceptions import MaxTurnsExceeded

from strix.core import execution as ex


class _FakeCoordinator:
    def __init__(self) -> None:
        self.status = "running"
        # rebase 1.2->1.4: run_agent_loop also reads coordinator.reserve_stopped
        # (sub-agent budget reserve, #893) — mirror the real coordinator surface.
        self.reserve_stopped = False
        # v1.1 budget gate: run_agent_loop reads coordinator.budget_stopped at
        # the top of every iteration (max_budget_usd feature). The fake must
        # expose it (False = never budget-stopped in these tests).
        self.budget_stopped = False

    async def set_status(self, agent_id: str, status: str) -> None:
        self.status = status

    async def _maybe_snapshot(self) -> None:
        pass


@pytest.fixture
def _stub_loop_helpers(monkeypatch):
    """Neutralise the loop's side-effecting helpers so tests stay hermetic."""

    async def _status(coordinator, agent_id):
        return coordinator.status

    async def _noop(*args, **kwargs):
        return []

    monkeypatch.setattr(ex, "_agent_status", _status)
    monkeypatch.setattr(ex, "_append_noninteractive_tool_required_message", _noop)
    # rebase 1.2->1.4: upstream renamed _notify_parent_on_crash ->
    # _notify_parent_on_terminal(coordinator, agent_id, status) (wake-parent-on-
    # terminal-state refactor, #082d4ae).
    monkeypatch.setattr(ex, "_notify_parent_on_terminal", _noop)


async def _run(coordinator, run_config):
    return await ex._run_noninteractive_until_lifecycle(
        agent=object(),
        coordinator=coordinator,
        agent_id="a1",
        initial_input="go",
        run_config=run_config,
        context={},
        max_turns=500,
        session=None,
        event_sink=None,
        hooks=None,
    )


@pytest.mark.asyncio
async def test_refusal_swaps_to_fallback_and_completes(monkeypatch, _stub_loop_helpers):
    monkeypatch.setenv("STRIX_LLM_FALLBACK", "primary-model=fallback-model")
    coordinator = _FakeCoordinator()
    models: list[str] = []

    async def _cycle(agent, coord, agent_id, *, input_data, run_config, **kwargs):
        model = ex._model_name(run_config.model)
        models.append(model)
        if model == "fallback-model":
            coord.status = "completed"  # the fallback model makes real progress
        return object()  # non-None, non-lifecycle result

    monkeypatch.setattr(ex, "_run_cycle", _cycle)

    await _run(coordinator, RunConfig(model="primary-model"))

    assert models[0] == "primary-model"
    assert "fallback-model" in models
    assert coordinator.status == "completed"
    # primary must not be retried past the recovery cap before swapping.
    assert models.count("primary-model") <= ex._NONINTERACTIVE_RECOVERY_LIMIT


@pytest.mark.asyncio
async def test_no_fallback_fails_within_recovery_cap(monkeypatch, _stub_loop_helpers):
    monkeypatch.delenv("STRIX_LLM_FALLBACK", raising=False)
    coordinator = _FakeCoordinator()
    cycles = 0

    async def _cycle(agent, coord, agent_id, *, input_data, run_config, **kwargs):
        nonlocal cycles
        cycles += 1
        return object()  # always non-lifecycle: status stays "running"

    monkeypatch.setattr(ex, "_run_cycle", _cycle)

    with pytest.raises(MaxTurnsExceeded):
        await _run(coordinator, RunConfig(model="unmapped-model"))

    # bounded by the recovery cap, not max_turns (500).
    assert cycles <= ex._NONINTERACTIVE_RECOVERY_LIMIT + 1
    assert coordinator.status == "crashed"
