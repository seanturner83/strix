from __future__ import annotations

import sys
from typing import Any

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from strix.sessions.listing import SessionRow, list_sessions


def print_session_table(
    rows: list[SessionRow], console: Console | None = None
) -> None:
    con = console or Console()
    if not rows:
        con.print("[dim]No sessions found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold white", box=None, padding=(0, 1))
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Run", style="bold cyan", min_width=20)
    table.add_column("Status", width=10)
    table.add_column("Mode", width=9)
    table.add_column("Targets", min_width=24)
    table.add_column("Iter", width=6, justify="right")
    table.add_column("Vulns", width=5, justify="right")
    table.add_column("Updated", width=16)

    for idx, row in enumerate(rows, 1):
        meta = row.meta
        status = meta.get("status", "unknown")
        status_style = {
            "running": "yellow",
            "completed": "green",
            "errored": "red",
        }.get(status, "dim")

        targets_raw = meta.get("targets", [])
        target_str = ", ".join(
            t.get("original", str(t)) if isinstance(t, dict) else str(t)
            for t in targets_raw[:2]
        )
        if len(targets_raw) > 2:
            target_str += f" +{len(targets_raw) - 2}"

        updated = _relative_time(row.last_updated_dt)

        table.add_row(
            str(idx),
            row.run_name,
            Text(status, style=status_style),
            meta.get("scan_mode", ""),
            target_str or "[dim]unknown[/dim]",
            str(meta.get("iteration_count", "?")),
            str(meta.get("vulnerability_count", "?")),
            updated,
        )

    con.print(table)


def pick_session_cli(query: str | None = None) -> SessionRow | None:
    """Interactive CLI session picker. Returns None if user cancels."""
    if not sys.stdin.isatty():
        raise RuntimeError(
            "Cannot run interactive session picker without a TTY. "
            "Use --resume <run_name> or --continue instead."
        )

    console = Console()
    rows = [r for r in list_sessions(query=query) if r.has_conversation_log]

    if not rows:
        console.print(
            "\n[yellow]No resumable sessions found.[/yellow] "
            "Run a scan first, then use --resume to continue it.\n"
        )
        return None

    console.print()
    print_session_table(rows, console)
    console.print()

    while True:
        choice = Prompt.ask(
            "[bold]Select session[/bold] [dim](# or run name, q to quit)[/dim]",
            console=console,
        ).strip()

        if choice.lower() in ("q", "quit", ""):
            return None

        # Numeric index
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(rows):
                return rows[idx]
            console.print(f"[red]Invalid number. Enter 1–{len(rows)}.[/red]")
            continue

        # Run name
        match = next((r for r in rows if r.run_name == choice), None)
        if match:
            return match

        console.print("[red]Session not found. Try the number or exact run name.[/red]")


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _relative_time(dt: Any) -> str:
    from datetime import UTC, datetime

    try:
        now = datetime.now(UTC)
        delta = now - dt
        secs = int(delta.total_seconds())
        if secs < 60:
            return "just now"
        if secs < 3600:
            return f"{secs // 60}m ago"
        if secs < 86400:
            return f"{secs // 3600}h ago"
        return f"{secs // 86400}d ago"
    except Exception:
        return ""
