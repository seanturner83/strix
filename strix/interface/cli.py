import atexit
import os
import signal
import sys
import threading
import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from strix.agents.StrixAgent import StrixAgent
from strix.llm import memory_compressor
from strix.llm.config import LLMConfig
from strix.telemetry.tracer import Tracer, set_global_tracer

from .utils import (
    build_live_stats_text,
    format_vulnerability_report,
)


async def run_cli(args: Any) -> None:  # noqa: PLR0915
    console = Console()

    start_text = Text()
    start_text.append("Penetration test initiated", style="bold #22c55e")

    target_text = Text()
    target_text.append("Target", style="dim")
    target_text.append("  ")
    if len(args.targets_info) == 1:
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append(f"{len(args.targets_info)} targets", style="bold white")
        for target_info in args.targets_info:
            target_text.append("\n        ")
            target_text.append(target_info["original"], style="white")

    results_text = Text()
    results_text.append("Output", style="dim")
    results_text.append("  ")
    results_text.append(f"strix_runs/{args.run_name}", style="#60a5fa")

    note_text = Text()
    note_text.append("\n\n", style="dim")
    note_text.append("Vulnerabilities will be displayed in real-time.", style="dim")

    startup_panel = Panel(
        Text.assemble(
            start_text,
            "\n\n",
            target_text,
            "\n",
            results_text,
            note_text,
        ),
        title="[bold white]STRIX",
        title_align="left",
        border_style="#22c55e",
        padding=(1, 2),
    )

    is_resume = getattr(args, "resumed_state", None) is not None
    if not is_resume:
        console.print("\n")
        console.print(startup_panel)
        console.print()

    scan_mode = getattr(args, "scan_mode", "deep")

    scan_config = {
        "scan_id": args.run_name,
        "targets": args.targets_info,
        "user_instructions": args.instruction or "",
        "run_name": args.run_name,
        "scan_mode": scan_mode,
        "diff_scope": getattr(args, "diff_scope", {"active": False}),
    }

    llm_config_kwargs: dict[str, Any] = {
        "scan_mode": scan_mode,
        "is_whitebox": bool(getattr(args, "local_sources", [])),
        "role": "orchestrator",
    }
    if getattr(args, "tool_mode", None):
        llm_config_kwargs["tool_mode"] = args.tool_mode
    llm_config = LLMConfig(**llm_config_kwargs)
    # Orchestrator-side cap on LLM tool-call iterations per agent session.
    # Default 100 — observed median seedcx scan converges in ~25-30 turns,
    # p90 well below 80. The previous default (300) gave generous depth
    # for app-code scans that legitimately need it but also let the
    # grind-without-converging shape burn an entire 50-min wall-clock
    # sub-session before terminating. Concrete instance: seedcx/composite-
    # actions#1142 iter 1 was on iteration=26 when the outer 50-min cap
    # hit, with $5 burned + 1.9M tokens + 0 vulnerabilities found.
    #
    # STRIX_MAX_ITERATIONS env-var override lets the orchestrator drop
    # tighter on repos known to grind (workflow YAML / IaC / helm) and
    # raise on repos that legitimately need deep exploration. Defaults
    # are deliberately central — per-repo policy lives in strix-pr-
    # dispatch.yml's resolve step.
    try:
        _env_max_iter = int(os.environ.get("STRIX_MAX_ITERATIONS", "").strip() or "100")
        if _env_max_iter < 1:
            raise ValueError("STRIX_MAX_ITERATIONS must be >= 1")
    except ValueError as exc:
        raise SystemExit(f"strix: invalid STRIX_MAX_ITERATIONS env var: {exc}") from exc
    agent_config = {
        "llm_config": llm_config,
        "max_iterations": _env_max_iter,
    }

    if getattr(args, "local_sources", None):
        agent_config["local_sources"] = args.local_sources

    if is_resume:
        from strix.sessions import merge_into_agent_config

        merge_into_agent_config(agent_config, args.resume_bundle)

    tracer = Tracer(args.run_name)
    tracer.set_scan_config(scan_config)

    def display_vulnerability(report: dict[str, Any]) -> None:
        report_id = report.get("id", "unknown")

        vuln_text = format_vulnerability_report(report)

        vuln_panel = Panel(
            vuln_text,
            title=f"[bold red]{report_id.upper()}",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        console.print(vuln_panel)
        console.print()

    tracer.vulnerability_found_callback = display_vulnerability

    def cleanup_on_exit() -> None:
        from strix.runtime import cleanup_runtime

        tracer.cleanup()
        cleanup_runtime()

    def signal_handler(_signum: int, _frame: Any) -> None:
        # Tell the memory compressor to skip its next call so an
        # in-flight or about-to-start ThreadPoolExecutor.submit doesn't
        # race Python's interpreter-shutdown (cpython
        # concurrent/futures/thread.py flips _shutdown=True at atexit,
        # and litellm's logging-callback subsystem does its own
        # pool.submit internally — both layers race the SIGTERM-driven
        # sys.exit below). Without this, the compressor's outer except
        # logs a noisy traceback ("Failed to summarize messages") that
        # obscures the real cause (workflow iter-cap timeout) and the
        # iter-loop's resume hook frequently doesn't fire.
        memory_compressor.mark_shutting_down()
        tracer.cleanup()
        sys.exit(1)

    atexit.register(cleanup_on_exit)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal_handler)

    set_global_tracer(tracer)

    def create_live_status() -> Panel:
        status_text = Text()
        status_text.append("Penetration test in progress", style="bold #22c55e")
        status_text.append("\n\n")

        stats_text = build_live_stats_text(tracer, agent_config)
        if stats_text:
            status_text.append(stats_text)

        return Panel(
            status_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="#22c55e",
            padding=(1, 2),
        )

    try:
        console.print()

        with Live(
            create_live_status(), console=console, refresh_per_second=2, transient=False
        ) as live:
            stop_updates = threading.Event()

            def update_status() -> None:
                while not stop_updates.is_set():
                    try:
                        live.update(create_live_status())
                        time.sleep(2)
                    except Exception:  # noqa: BLE001
                        break

            update_thread = threading.Thread(target=update_status, daemon=True)
            update_thread.start()

            try:
                agent = StrixAgent(agent_config)
                result = await agent.execute_scan(scan_config)

                if isinstance(result, dict) and not result.get("success", True):
                    error_msg = result.get("error", "Unknown error")
                    error_details = result.get("details")
                    console.print()
                    console.print(f"[bold red]Penetration test failed:[/] {error_msg}")
                    if error_details:
                        console.print(f"[dim]{error_details}[/]")
                    console.print()
                    sys.exit(1)
            finally:
                stop_updates.set()
                update_thread.join(timeout=1)

    except Exception as e:
        console.print(f"[bold red]Error during penetration test:[/] {e}")
        raise

    if tracer.final_scan_result:
        console.print()

        final_report_text = Text()
        final_report_text.append("Penetration test summary", style="bold #60a5fa")

        final_report_panel = Panel(
            Text.assemble(
                final_report_text,
                "\n\n",
                tracer.final_scan_result,
            ),
            title="[bold white]STRIX",
            title_align="left",
            border_style="#60a5fa",
            padding=(1, 2),
        )

        console.print(final_report_panel)
        console.print()
