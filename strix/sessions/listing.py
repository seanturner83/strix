from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class SessionRow:
    run_name: str
    run_dir: Path
    meta: dict[str, Any]
    has_conversation_log: bool
    last_updated_dt: datetime


def list_sessions(
    runs_root: Path | None = None,
    *,
    query: str | None = None,
    limit: int | None = None,
) -> list[SessionRow]:
    """Return scan sessions sorted by last_updated descending."""
    root = runs_root or (Path.cwd() / "strix_runs")
    if not root.is_dir():
        return []

    rows: list[SessionRow] = []
    for run_dir in root.iterdir():
        if not run_dir.is_dir():
            continue
        row = _load_row(run_dir)
        if row is None:
            continue
        rows.append(row)

    rows.sort(key=lambda r: r.last_updated_dt, reverse=True)

    if query:
        q = query.lower()
        rows = [r for r in rows if _matches(r, q)]

    if limit is not None:
        rows = rows[:limit]

    return rows


def most_recent(runs_root: Path | None = None) -> SessionRow | None:
    """Return the most recently updated session that has a conversation log."""
    for row in list_sessions(runs_root):
        if row.has_conversation_log:
            return row
    return None


def get_session(run_name: str, runs_root: Path | None = None) -> SessionRow | None:
    root = runs_root or (Path.cwd() / "strix_runs")
    run_dir = root / run_name
    if not run_dir.is_dir():
        return None
    return _load_row(run_dir)


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _load_row(run_dir: Path) -> SessionRow | None:
    from strix.telemetry.session_meta import read_session_meta

    meta = read_session_meta(run_dir)
    if meta is None:
        meta = _synthesize_meta_from_legacy(run_dir)

    has_conv_log = (run_dir / "conversation.jsonl").exists()
    last_updated_dt = _parse_dt(meta.get("last_updated")) or _mtime(run_dir)

    return SessionRow(
        run_name=run_dir.name,
        run_dir=run_dir,
        meta=meta,
        has_conversation_log=has_conv_log,
        last_updated_dt=last_updated_dt,
    )


def _synthesize_meta_from_legacy(run_dir: Path) -> dict[str, Any]:
    """Best-effort metadata for runs created before session_meta.json existed."""
    vuln_count = 0
    vuln_dir = run_dir / "vulnerabilities"
    if vuln_dir.is_dir():
        vuln_count = sum(1 for f in vuln_dir.iterdir() if f.suffix == ".md")

    mtime = _mtime(run_dir)
    return {
        "schema_version": 0,
        "run_name": run_dir.name,
        "created_at": mtime.isoformat(),
        "last_updated": mtime.isoformat(),
        "status": "unknown",
        "targets": [],
        "first_prompt_summary": "",
        "vulnerability_count": vuln_count,
        "has_conversation_log": (run_dir / "conversation.jsonl").exists(),
    }


def _matches(row: SessionRow, q: str) -> bool:
    haystack = " ".join(
        [
            row.run_name,
            row.meta.get("first_prompt_summary", ""),
            row.meta.get("title") or "",
            " ".join(row.meta.get("tags", [])),
            " ".join(
                t.get("original", "") if isinstance(t, dict) else str(t)
                for t in row.meta.get("targets", [])
            ),
        ]
    ).lower()
    return q in haystack


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError:
        return None


def _mtime(path: Path) -> datetime:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    except OSError:
        return datetime.now(UTC)
