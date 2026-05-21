import asyncio
import uuid
from typing import Any

from strix.tools.registry import register_tool


@register_tool
def terminal_execute(
    command: str,
    is_input: bool = False,
    timeout: float | None = None,
    terminal_id: str | None = None,
    no_enter: bool = False,
) -> dict[str, Any]:
    from .terminal_manager import get_terminal_manager

    manager = get_terminal_manager()

    try:
        return manager.execute_command(
            command=command,
            is_input=is_input,
            timeout=timeout,
            terminal_id=terminal_id,
            no_enter=no_enter,
        )
    except (ValueError, RuntimeError) as e:
        return {
            "error": str(e),
            "command": command,
            "terminal_id": terminal_id or "default",
            "content": "",
            "status": "error",
            "exit_code": None,
            "working_dir": None,
        }


def _run_one_in_fresh_session(command: str, timeout: float | None) -> dict[str, Any]:
    """Run one command in a fresh ephemeral tmux session, then close it.

    Sessions are uniquified by uuid so concurrent callers don't collide
    inside the manager's per-agent dict.
    """
    from .terminal_manager import get_terminal_manager

    manager = get_terminal_manager()
    terminal_id = f"batch-{uuid.uuid4().hex[:12]}"
    try:
        result = manager.execute_command(
            command=command,
            timeout=timeout,
            terminal_id=terminal_id,
        )
    finally:
        try:
            manager.close_session(terminal_id)
        except Exception:  # noqa: BLE001
            pass
    return result


@register_tool(parallel_safe=True)
async def batch_terminal_execute(
    commands: list[dict[str, Any]],
) -> dict[str, Any]:
    """Run multiple shell commands concurrently, each in its own ephemeral session.

    Each entry in `commands` is a dict with keys: command (required, str),
    timeout (optional, seconds, default 300). Each command runs in a fresh
    /workspace-rooted tmux session that is closed after completion — there is
    no shared state between batched commands. Use this for independent slow
    operations: running multiple SAST scanners (semgrep + gitleaks +
    trufflehog), running scanners with different rule packs, running git
    metadata sweeps in parallel.

    Do NOT use this for sequenced commands where one needs to see the cwd or
    env vars set by another — use plain terminal_execute for those.
    """
    if not commands:
        return {"error": "commands must be a non-empty list"}

    if not isinstance(commands, list):
        return {"error": f"commands must be a list, got {type(commands).__name__}"}

    for i, entry in enumerate(commands):
        if not isinstance(entry, dict):
            return {"error": f"commands[{i}] must be a dict"}
        if "command" not in entry or not isinstance(entry["command"], str):
            return {"error": f"commands[{i}] missing required string key 'command'"}

    results = await asyncio.gather(
        *[
            asyncio.to_thread(
                _run_one_in_fresh_session,
                entry["command"],
                entry.get("timeout", 300.0),
            )
            for entry in commands
        ],
        return_exceptions=True,
    )

    out: list[dict[str, Any]] = []
    for entry, result in zip(commands, results, strict=True):
        item = {"command": entry["command"]}
        if isinstance(result, BaseException):
            item["error"] = f"{type(result).__name__}: {result!s}"
        elif isinstance(result, dict):
            item.update(result)
        else:
            item["content"] = str(result)
        out.append(item)
    return {"results": out, "count": len(commands)}
