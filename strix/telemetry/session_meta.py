import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def write_session_meta(run_dir: Path, meta: dict[str, Any]) -> None:
    """Atomically merge *meta* into session_meta.json, preserving user fields."""
    path = run_dir / "session_meta.json"
    existing = _read_raw(path) or {}

    merged = {**existing, **meta}
    # Always preserve user-editable fields from existing file
    merged["title"] = existing.get("title", merged.get("title"))
    merged["tags"] = existing.get("tags", merged.get("tags", []))
    merged["last_updated"] = datetime.now(UTC).isoformat()

    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def read_session_meta(run_dir: Path) -> dict[str, Any] | None:
    return _read_raw(run_dir / "session_meta.json")


def update_status(
    run_dir: Path, status: str, *, ended_at: str | None = None
) -> None:
    update: dict[str, Any] = {"status": status}
    if ended_at is not None:
        update["ended_at"] = ended_at
    write_session_meta(run_dir, update)


def _read_raw(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
