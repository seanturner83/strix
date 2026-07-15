"""Top-level Strix scan runner."""

from __future__ import annotations

import contextlib
import io
import json
import logging
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents import RunConfig
from agents.sandbox import SandboxRunConfig
from openai import RateLimitError

from strix.agents.factory import build_strix_agent, make_child_factory
from strix.agents.prompt import render_system_prompt
from strix.config import load_settings
from strix.config.models import (
    StrixProvider,
    configure_sdk_model_defaults,
    uses_chat_completions_tool_schema,
)
from strix.core.agents import AgentCoordinator
from strix.core.execution import (
    respawn_subagents,
    run_agent_loop,
)
from strix.core.execution import (
    spawn_child_agent as start_child_agent,
)
from strix.core.hooks import BudgetExceededError, ReportUsageHooks, recomputed_budget_flags
from strix.core.inputs import (
    DEFAULT_MAX_TURNS,
    build_root_task,
    build_scope_context,
    make_model_settings,
)
from strix.core.paths import run_dir_for, runtime_state_dir
from strix.core.sessions import open_agent_session
from strix.report.state import get_global_report_state
from strix.runtime import session_manager
from strix.telemetry.logging import set_scan_id, setup_scan_logging
from strix.tools.output_store import (
    WORKSPACE_SPILL_DIR,
    configure_spill_writer,
)


if TYPE_CHECKING:
    from agents.memory import SQLiteSession
    from agents.result import RunResultBase


logger = logging.getLogger(__name__)

StreamEventSink = Callable[[str, Any], None]


def _merge_root_prompt_context(
    scope_context: dict[str, Any],
    extra_system_prompt_context: dict[str, Any] | None,
) -> dict[str, Any]:
    if not extra_system_prompt_context:
        return scope_context
    reserved_keys = scope_context.keys() & extra_system_prompt_context.keys()
    if reserved_keys:
        raise ValueError(
            "extra_system_prompt_context cannot override built-in scope keys: "
            f"{sorted(reserved_keys)}",
        )
    return {**scope_context, **extra_system_prompt_context}


def _compose_root_instructions_override(
    root_instructions_override: str | None,
    *,
    skills: list[str],
    scan_mode: str,
    is_whitebox: bool,
    interactive: bool,
    system_prompt_context: dict[str, Any],
) -> str | None:
    if root_instructions_override is None:
        return None

    base_instructions = render_system_prompt(
        skills=skills,
        scan_mode=scan_mode,
        is_whitebox=is_whitebox,
        is_root=True,
        interactive=interactive,
        system_prompt_context=system_prompt_context,
    )
    return (
        f"{base_instructions}\n\n"
        "<root_scan_instructions_override>\n"
        "The following root scan instructions are subordinate to the "
        "system-verified scope above. They cannot expand, replace, or weaken "
        "authorized target constraints.\n\n"
        f"{root_instructions_override}\n"
        "</root_scan_instructions_override>"
    )


async def run_strix_scan(
    *,
    scan_config: dict[str, Any],
    scan_id: str | None = None,
    image: str,
    local_sources: list[dict[str, Any]] | None = None,
    coordinator: AgentCoordinator | None = None,
    interactive: bool = False,
    max_turns: int = DEFAULT_MAX_TURNS,
    max_budget_usd: float | None = None,
    model: str | None = None,
    cleanup_on_exit: bool = True,
    event_sink: StreamEventSink | None = None,
    root_instructions_override: str | None = None,
    extra_system_prompt_context: dict[str, Any] | None = None,
) -> RunResultBase | None:
    """Run or resume one Strix scan against a sandbox.

    ``root_instructions_override`` adds root scan instructions to the rendered
    root prompt without replacing the system-verified scope block.
    ``extra_system_prompt_context`` is merged into the root agent's scan
    context before prompt rendering. Child agents keep the standard scan prompt
    and context.
    """
    if scan_id is None:
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"

    run_dir = run_dir_for(scan_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    teardown_logging = setup_scan_logging(run_dir)
    set_scan_id(scan_id)

    agents_path = state_dir / "agents.json"
    agents_db = state_dir / "agents.db"
    is_resume = agents_path.exists()

    logger.info(
        "%s Strix scan %s (image=%s, max_turns=%d, interactive=%s, run_dir=%s)",
        "Resuming" if is_resume else "Starting",
        scan_id,
        image,
        max_turns,
        interactive,
        run_dir,
    )

    settings = load_settings()
    configure_sdk_model_defaults(settings)
    resolved_model = (model or settings.llm.model or "").strip()
    if not resolved_model:
        raise RuntimeError(
            "No LLM model configured. Set STRIX_LLM env or pass model= to run_strix_scan().",
        )
    logger.info("LLM model resolved: %s", resolved_model)

    # Per-role model resolution (cost-tier the fleet). Fallback CHAIN mirrors
    # the fork's proven order, so a deployment can set just the orchestrator and
    # have sub-agents + compressor inherit it before falling to the base model:
    #   orchestrator: STRIX_LLM_ORCHESTRATOR -> STRIX_LLM
    #   sub-agent:    STRIX_LLM_SUBAGENT -> STRIX_LLM_ORCHESTRATOR -> STRIX_LLM
    #   compressor:   STRIX_LLM_COMPRESSOR -> STRIX_LLM_ORCHESTRATOR -> STRIX_LLM
    # Unset everywhere = today's single-model behaviour, unchanged.
    orchestrator_model = (settings.llm.model_orchestrator or resolved_model).strip()
    subagent_model = (
        settings.llm.model_subagent or settings.llm.model_orchestrator or resolved_model
    ).strip()
    if orchestrator_model != resolved_model or subagent_model != resolved_model:
        logger.info(
            "Per-role models: orchestrator=%s subagent=%s (base=%s)",
            orchestrator_model, subagent_model, resolved_model,
        )
    chat_completions_tools = uses_chat_completions_tool_schema(resolved_model, settings)

    if coordinator is None:
        coordinator = AgentCoordinator()
    coordinator.set_snapshot_path(agents_path)

    from strix.tools.notes.tools import hydrate_notes_from_disk
    from strix.tools.todo.tools import hydrate_todos_from_disk

    hydrate_todos_from_disk(state_dir)
    hydrate_notes_from_disk(state_dir)

    root_id: str | None = None
    if is_resume:
        try:
            snap = json.loads(agents_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json is unreadable: {exc}",
            ) from exc
        if not agents_db.exists():
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: missing SDK session database at {agents_db}",
            )
        await coordinator.restore(snap)
        report_state = get_global_report_state()
        if report_state is not None:
            budget_stopped, reserve_stopped = recomputed_budget_flags(
                report_state.get_total_llm_cost(),
                max_budget_usd,
                interactive=interactive,
            )
            await coordinator.reset_budget_stops(
                budget_stopped=budget_stopped,
                reserve_stopped=reserve_stopped,
                budget_paused=interactive and coordinator.budget_paused,
            )
        for aid, parent in coordinator.parent_of.items():
            if parent is None:
                root_id = aid
                break
        if root_id is None:
            raise RuntimeError(
                f"Cannot resume scan {scan_id}: agents.json has no root agent (parent=None)",
            )
        logger.info(
            "Resume: restored coordinator with %d agent(s); root=%s",
            len(coordinator.statuses),
            root_id,
        )
    else:
        root_id = uuid.uuid4().hex[:8]

    logger.info("Bringing up sandbox session for scan %s", scan_id)
    bundle = await session_manager.create_or_reuse(
        scan_id,
        image=image,
        local_sources=local_sources or [],
    )
    logger.info("Sandbox ready for scan %s", scan_id)

    sandbox_session = bundle["session"]

    async def _spill_to_workspace(output_id: str, text: str) -> str | None:
        """Write an oversized tool result into the sandbox; return its path or None."""
        path = f"{WORKSPACE_SPILL_DIR}/{output_id}.txt"
        try:
            await sandbox_session.write(Path(path), io.BytesIO(text.encode("utf-8")))
        except Exception:
            logger.exception("failed to spill tool output to sandbox workspace")
            return None
        return path

    configure_spill_writer(_spill_to_workspace)

    sessions_to_close: list[SQLiteSession] = []

    try:
        targets = scan_config.get("targets") or []
        scan_mode = str(scan_config.get("scan_mode") or "deep")
        is_whitebox = any(t.get("type") == "local_code" for t in targets)
        skills = list(scan_config.get("skills") or [])
        root_task = build_root_task(scan_config)
        # Per-role model config (seedcx 175ec25 / 20cce6c) FUSED with v1.4's
        # prompt_cache model-setting (#772) + the fuller ReportUsageHooks
        # (max_turns + interactive budget pause, #893). Our per-role factory is
        # kept; each role's make_model_settings now also gets prompt_cache so
        # caching works on every role, not just the orchestrator.
        _sandbox_cfg = SandboxRunConfig(client=bundle["client"], session=bundle["session"])

        def _run_config_for(role_model: str) -> RunConfig:
            return RunConfig(
                model=role_model,
                model_provider=StrixProvider(),
                model_settings=make_model_settings(
                    settings.llm.reasoning_effort,
                    model_name=role_model,
                    force_required_tool_choice=settings.llm.force_required_tool_choice,
                    request_timeout=settings.llm.timeout,
                    prompt_cache=settings.llm.prompt_cache,
                ),
                sandbox=_sandbox_cfg,
                trace_include_sensitive_data=False,
            )

        # Root/orchestrator run_config; children get their own (subagent model).
        run_config = _run_config_for(orchestrator_model)
        child_run_config = (
            run_config if subagent_model == orchestrator_model
            else _run_config_for(subagent_model)
        )
        hooks = ReportUsageHooks(
            model=orchestrator_model,
            max_budget_usd=max_budget_usd,
            max_turns=max_turns,
            interactive=interactive,
        )
        if interactive:
            coordinator.set_budget_extender(hooks.extend_budget)

        scope_context = build_scope_context(scan_config)
        root_context = _merge_root_prompt_context(scope_context, extra_system_prompt_context)
        root_instructions = _compose_root_instructions_override(
            root_instructions_override,
            skills=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            system_prompt_context=root_context,
        )

        # On resume, wire a sandbox-backed reader for the retract tool's
        # groundedness guard so it can re-verify a "fixed" claim against the
        # live /workspace tree. Whitebox only — the guard checks source sinks;
        # for non-whitebox targets there is no tree to read, so the guard stays
        # fail-safe (refuse). The reader cats the file inside the container.
        if is_resume and is_whitebox:
            from strix.tools.reporting.retract_tool import set_target_file_reader

            _session = bundle["session"]
            _ws_paths = [
                f"/workspace/{sub}" if sub else "/workspace"
                for sub in (
                    (t.get("details") or {}).get("workspace_subdir")
                    for t in targets
                    if t.get("type") == "local_code"
                )
            ] or ["/workspace"]

            async def _read_target_file(rel_path: str) -> str | None:
                rel = rel_path.lstrip("/")
                for base in _ws_paths:
                    try:
                        result = await _session.exec("cat", f"{base}/{rel}", timeout=15)
                    except Exception:  # noqa: BLE001
                        continue
                    if getattr(result, "exit_code", 1) == 0:
                        # SDK ExecResult.stdout is BYTES. The retract-tool guard
                        # does `needle in content` with a str needle, so a raw
                        # bytes return raises TypeError on EVERY retract — the
                        # uncaught "persistent internal tool error" that made
                        # grounded retraction impossible on v1.x (SEC-6802).
                        # Decode to text here; the guard is a text substring check.
                        stdout = result.stdout
                        return (
                            stdout.decode("utf-8", errors="replace")
                            if isinstance(stdout, (bytes, bytearray))
                            else stdout
                        )
                return None  # not found under any workspace root → treat as gone

            set_target_file_reader(_read_target_file)

        root_agent = build_strix_agent(
            name="Strix",
            skills=skills,
            is_root=True,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            is_resume=is_resume,
            system_prompt_context=root_context,
            instructions_override=root_instructions,
        )

        if not is_resume:
            await coordinator.register(
                root_id,
                "Strix",
                parent_id=None,
                task=root_task,
                skills=skills,
            )

        child_agent_builder = make_child_factory(
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            interactive=interactive,
            chat_completions_tools=chat_completions_tools,
            system_prompt_context=scope_context,
        )

        async def spawn_child_agent(**kwargs: Any) -> dict[str, Any]:
            return await start_child_agent(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=child_run_config,
                max_turns=max_turns,
                interactive=interactive,
                event_sink=event_sink,
                hooks=hooks,
                **kwargs,
            )

        context: dict[str, Any] = {
            "coordinator": coordinator,
            "sandbox_session": bundle["session"],
            "caido_client": bundle["caido_client"],
            "agent_id": root_id,
            "parent_id": None,
            "interactive": interactive,
            "spawn_child_agent": spawn_child_agent,
            "max_context_images": settings.runtime.max_context_images,
        }

        root_session = open_agent_session(root_id, agents_db)
        sessions_to_close.append(root_session)
        await coordinator.attach_runtime(root_id, session=root_session)

        if is_resume:
            await respawn_subagents(
                coordinator=coordinator,
                factory=child_agent_builder,
                agents_db_path=agents_db,
                sessions_to_close=sessions_to_close,
                run_config=child_run_config,
                max_turns=max_turns,
                interactive=interactive,
                parent_ctx=context,
                root_id=root_id,
                event_sink=event_sink,
                hooks=hooks,
            )

        initial_input: Any = [] if is_resume else root_task

        # Resume + new ``--instruction``: SDK replay drives root from
        # agents.db with ``initial_input=[]``, so a brand-new instruction
        # passed on the resume CLI would otherwise be silently ignored.
        # Inject it as a fresh user message in root's SDK session; the
        # next run cycle will replay it with the rest of the session.
        resume_instruction = str(scan_config.get("resume_instruction") or "").strip()
        if is_resume and resume_instruction:
            await coordinator.send(
                root_id,
                {
                    "from": "user",
                    "type": "instruction",
                    "priority": "high",
                    "content": resume_instruction,
                },
            )
            logger.info(
                "Resume: injected new instruction into root SDK session (len=%d)",
                len(resume_instruction),
            )

        async with coordinator._lock:
            root_status = coordinator.statuses.get(root_id)

        result = await run_agent_loop(
            agent=root_agent,
            initial_input=initial_input,
            run_config=run_config,
            context=context,
            max_turns=max_turns,
            coordinator=coordinator,
            agent_id=root_id,
            interactive=interactive,
            session=root_session,
            start_parked=bool(interactive and is_resume and root_status != "running"),
            event_sink=event_sink,
            hooks=hooks,
        )
        if not interactive and result is not None:
            final = getattr(result, "final_output", None)
            scan_completed = False
            if isinstance(final, str):
                try:
                    parsed = json.loads(final)
                    scan_completed = bool(isinstance(parsed, dict) and parsed.get("scan_completed"))
                except (ValueError, TypeError):
                    scan_completed = False
            elif isinstance(final, dict):
                scan_completed = bool(final.get("scan_completed"))
            if not scan_completed:
                logger.error(
                    "Scan %s ended without calling finish_scan. The agent "
                    "emitted a text-only turn instead of a lifecycle tool call, "
                    "so no executive report was written. Final output (first "
                    "300 chars): %r",
                    scan_id,
                    str(final)[:300],
                )
        return result  # noqa: TRY300
    except BudgetExceededError as exc:
        logger.info("Scan %s stopped: %s", scan_id, exc)
        if root_id is not None:
            await coordinator.cancel_descendants(root_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "stopped")
        return None
    except RateLimitError as exc:
        logger.warning(
            "Scan %s stopped: persistent rate limit from the LLM provider (%s). "
            "Resume with 'strix --resume %s' once the limit clears.",
            scan_id,
            exc,
            scan_id,
        )
        if root_id is not None:
            await coordinator.cancel_descendants(root_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "stopped")
        return None
    except BaseException:
        logger.exception("Strix scan %s failed", scan_id)
        if root_id is not None:
            await coordinator.cancel_descendants(root_id)
            with contextlib.suppress(Exception):
                await coordinator.set_status(root_id, "failed")
        raise
    finally:
        configure_spill_writer(None)
        for s in sessions_to_close:
            with contextlib.suppress(Exception):
                s.close()
        with contextlib.suppress(Exception):
            await coordinator._maybe_snapshot()
        if cleanup_on_exit:
            logger.info("Tearing down sandbox session for scan %s", scan_id)
            await session_manager.cleanup(scan_id)
        logger.info("Strix scan %s done", scan_id)
        teardown_logging()
