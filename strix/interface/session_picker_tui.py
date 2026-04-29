from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Label, Static

from strix.sessions.listing import SessionRow, list_sessions


class SessionPickerScreen(ModalScreen[SessionRow | None]):
    """Interactive session picker modal for the TUI.

    Dismissed with the selected SessionRow, or None if cancelled.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("enter", "resume_selected", "Resume", show=True),
        Binding("/", "focus_search", "Search", show=True),
    ]

    DEFAULT_CSS = """
    SessionPickerScreen {
        align: center middle;
    }
    #picker-container {
        width: 90;
        height: auto;
        max-height: 40;
        background: $surface;
        border: solid $primary;
        padding: 1 2;
    }
    #picker-title {
        text-style: bold;
        color: $primary;
        margin-bottom: 1;
    }
    #session-search {
        margin-bottom: 1;
    }
    #session-table {
        height: 20;
        margin-bottom: 1;
    }
    #empty-state {
        color: $text-muted;
        margin: 2 0;
    }
    #picker-buttons {
        layout: horizontal;
        height: auto;
        align: right middle;
    }
    #resume-btn {
        margin-right: 1;
    }
    """

    def __init__(self, initial_query: str | None = None) -> None:
        super().__init__()
        self._initial_query = initial_query or ""
        self._rows: list[SessionRow] = []

    def compose(self) -> ComposeResult:
        with self.app.focused if False else self:  # noqa: SIM210
            pass
        from textual.containers import Container, Horizontal

        with Container(id="picker-container"):
            yield Label("Resume a session", id="picker-title")
            yield Input(
                placeholder="Search sessions…",
                value=self._initial_query,
                id="session-search",
            )
            yield DataTable(id="session-table", show_cursor=True, zebra_stripes=True)
            yield Static("", id="empty-state")
            with Horizontal(id="picker-buttons"):
                yield Button("Resume", id="resume-btn", variant="primary")
                yield Button("Cancel", id="cancel-btn", variant="default")

    def on_mount(self) -> None:
        table = self.query_one("#session-table", DataTable)
        table.add_columns("Run", "Status", "Targets", "Iter", "Vulns", "Updated")
        self._refresh_table(self._initial_query)

    def on_input_changed(self, event: Input.Changed) -> None:
        self._refresh_table(event.value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._dismiss_selected(event.row_key.value)  # type: ignore[arg-type]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.dismiss(None)
        elif event.button.id == "resume-btn":
            table = self.query_one("#session-table", DataTable)
            if table.cursor_row is not None and self._rows:
                row = self._rows[table.cursor_row]
                self.dismiss(row)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_resume_selected(self) -> None:
        table = self.query_one("#session-table", DataTable)
        if self._rows:
            row = self._rows[table.cursor_row or 0]
            self.dismiss(row)

    def action_focus_search(self) -> None:
        self.query_one("#session-search", Input).focus()

    # ------------------------------------------------------------------

    def _refresh_table(self, query: str) -> None:
        from datetime import UTC, datetime

        rows = [r for r in list_sessions(query=query or None) if r.has_conversation_log]
        self._rows = rows

        table = self.query_one("#session-table", DataTable)
        empty = self.query_one("#empty-state", Static)
        table.clear()

        if not rows:
            empty.update("No resumable sessions yet. Run a scan first.")
            empty.display = True
            table.display = False
            return

        empty.display = False
        table.display = True

        now = datetime.now(UTC)
        for row in rows:
            meta = row.meta
            targets_raw = meta.get("targets", [])
            target_str = ", ".join(
                t.get("original", str(t)) if isinstance(t, dict) else str(t)
                for t in targets_raw[:2]
            )
            if len(targets_raw) > 2:
                target_str += f" +{len(targets_raw) - 2}"

            delta = now - row.last_updated_dt
            secs = int(delta.total_seconds())
            if secs < 60:
                updated = "just now"
            elif secs < 3600:
                updated = f"{secs // 60}m ago"
            elif secs < 86400:
                updated = f"{secs // 3600}h ago"
            else:
                updated = f"{secs // 86400}d ago"

            table.add_row(
                row.run_name,
                meta.get("status", "?"),
                target_str or "unknown",
                str(meta.get("iteration_count", "?")),
                str(meta.get("vulnerability_count", "?")),
                updated,
                key=row.run_name,
            )

    def _dismiss_selected(self, run_name: str) -> None:
        match = next((r for r in self._rows if r.run_name == run_name), None)
        self.dismiss(match)
