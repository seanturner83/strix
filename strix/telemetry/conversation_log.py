import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


@dataclass
class ReplayResult:
    messages: list[dict[str, Any]]
    scan_config: dict[str, Any]
    iteration: int
    context: dict[str, Any]
    completed: bool
    final_result: dict[str, Any] | None
    schema_version: int


class ReplayError(Exception):
    pass


class ConversationLog:
    """Append-only JSONL log of every LLM message in a scan session.

    Writes each entry synchronously under a lock so any crash leaves
    all previously-written messages intact.
    """

    def __init__(self, run_dir: Path, run_name: str) -> None:
        self._path = run_dir / "conversation.jsonl"
        self._run_name = run_name
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Write helpers
    # ------------------------------------------------------------------

    def _append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line)

    def write_session_start(self, scan_config: dict[str, Any]) -> None:
        self._append(
            {
                "type": "session_start",
                "schema_version": SCHEMA_VERSION,
                "run_name": self._run_name,
                "scan_config": scan_config,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

    def append_message(
        self,
        role: str,
        content: Any,
        *,
        iteration: int,
        thinking_blocks: list[dict[str, Any]] | None = None,
    ) -> None:
        record: dict[str, Any] = {
            "type": "message",
            "role": role,
            "content": content,
            "iteration": iteration,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        if thinking_blocks:
            record["thinking_blocks"] = thinking_blocks
        self._append(record)

    def append_iteration_end(
        self, iteration: int, context: dict[str, Any], completed: bool
    ) -> None:
        self._append(
            {
                "type": "iteration_end",
                "iteration": iteration,
                "context": context,
                "completed": completed,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

    def write_session_end(
        self, completed: bool, final_result: dict[str, Any] | None = None
    ) -> None:
        self._append(
            {
                "type": "session_end",
                "completed": completed,
                "final_result": final_result,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    @classmethod
    def replay(cls, run_dir: Path) -> ReplayResult:
        """Reconstruct AgentState fields by replaying conversation.jsonl."""
        path = run_dir / "conversation.jsonl"
        if not path.exists():
            raise ReplayError(f"No conversation log found at {path}")

        messages: list[dict[str, Any]] = []
        scan_config: dict[str, Any] = {}
        iteration = 0
        context: dict[str, Any] = {}
        completed = False
        final_result: dict[str, Any] | None = None
        schema_version = SCHEMA_VERSION

        try:
            with path.open(encoding="utf-8") as fh:
                for raw_line in fh:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        entry = json.loads(raw_line)
                    except json.JSONDecodeError:
                        continue  # skip corrupt line, keep partial state

                    entry_type = entry.get("type")

                    if entry_type == "session_start":
                        scan_config = entry.get("scan_config", {})
                        schema_version = entry.get("schema_version", SCHEMA_VERSION)

                    elif entry_type == "message":
                        msg: dict[str, Any] = {
                            "role": entry["role"],
                            "content": entry["content"],
                        }
                        if "thinking_blocks" in entry:
                            msg["thinking_blocks"] = entry["thinking_blocks"]
                        messages.append(msg)

                    elif entry_type == "iteration_end":
                        iteration = entry.get("iteration", iteration)
                        context = entry.get("context", context)
                        completed = entry.get("completed", completed)

                    elif entry_type == "session_end":
                        completed = entry.get("completed", completed)
                        final_result = entry.get("final_result")

        except OSError as e:
            raise ReplayError(f"Failed to read conversation log: {e}") from e

        if not scan_config and not messages:
            raise ReplayError("Conversation log is empty or unreadable")

        return ReplayResult(
            messages=messages,
            scan_config=scan_config,
            iteration=iteration,
            context=context,
            completed=completed,
            final_result=final_result,
            schema_version=schema_version,
        )
