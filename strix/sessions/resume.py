from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from strix.agents.state import AgentState


class ResumeError(Exception):
    pass


@dataclass
class ResumeBundle:
    run_name: str
    run_dir: Path
    agent_state: "AgentState"
    scan_config: dict[str, Any]
    meta: dict[str, Any]
    mode: Literal["continue", "reopen"]


def load_resume_bundle(
    run_name: str, runs_root: Path | None = None
) -> ResumeBundle:
    """Load a past session from conversation.jsonl and reconstruct AgentState."""
    from strix.agents.state import AgentState
    from strix.sessions.listing import get_session
    from strix.telemetry.conversation_log import ConversationLog, ReplayError

    row = get_session(run_name, runs_root)
    if row is None:
        raise ResumeError(f"Session '{run_name}' not found in strix_runs/")
    if not row.has_conversation_log:
        raise ResumeError(
            f"Session '{run_name}' has no conversation log and cannot be resumed. "
            "Only sessions created with Strix ≥ the resume feature can be resumed."
        )

    try:
        result = ConversationLog.replay(row.run_dir)
    except ReplayError as exc:
        raise ResumeError(str(exc)) from exc

    mode: Literal["continue", "reopen"] = "reopen" if result.completed else "continue"

    state = AgentState(
        messages=result.messages,
        iteration=result.iteration,
        context=result.context,
        completed=False,
        stop_requested=False,
    )

    if mode == "reopen":
        state.add_message(
            "user",
            "The previous scan session has been reopened. Please summarize the key "
            "findings so far and ask what to investigate or test next.",
        )

    return ResumeBundle(
        run_name=row.run_name,
        run_dir=row.run_dir,
        agent_state=state,
        scan_config=result.scan_config,
        meta=row.meta,
        mode=mode,
    )


def apply_resume_to_args(args: argparse.Namespace, bundle: ResumeBundle) -> None:
    """Populate *args* from a ResumeBundle so main() can proceed normally."""
    args.run_name = bundle.run_name
    args.resumed_state = bundle.agent_state
    args.resume_mode = bundle.mode
    args.resume_bundle = bundle

    # Only override targets/instruction if not explicitly set by the user
    if not getattr(args, "target", None):
        args.targets_info = bundle.scan_config.get("targets", [])
    if not getattr(args, "instruction", None):
        args.instruction = bundle.scan_config.get("user_instructions") or None

    scan_mode = bundle.scan_config.get("scan_mode")
    if scan_mode and not getattr(args, "_scan_mode_explicit", False):
        args.scan_mode = scan_mode


def merge_into_agent_config(
    agent_config: dict[str, Any], bundle: ResumeBundle
) -> dict[str, Any]:
    """Inject the restored AgentState into agent_config."""
    agent_config["state"] = bundle.agent_state
    return agent_config
