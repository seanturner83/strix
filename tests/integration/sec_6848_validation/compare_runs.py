"""SEC-6848 W4.2: baseline-vs-experiment run comparison.

Consumes two Strix run artefact directories (each containing
conversation.jsonl, events.jsonl, vulnerabilities/*.md,
vulnerabilities.csv, session_meta.json) and emits a delta report.

Usage:
    python -m tests.integration.sec_6848_validation.compare_runs \
        --baseline /path/to/run_26717626470/.../target_9e8a \
        --experiment /path/to/new_run/.../target_xxxx \
        --output /path/to/report.md

What's measured (from the artefact alone — token telemetry is in
Bedrock CloudWatch and not pulled here):

  * Tool-call histogram per run; side-by-side diff with delta column.
    Specifically tracks the code_graph_* family separately so the
    "did the LLM actually use the new tools" question has a clean
    answer.
  * Iteration count (max(iteration) in conversation.jsonl).
  * Wall time (events.jsonl run.started → run.completed).
  * Finding-title set diff (baseline only / experiment only / shared).
  * Finding-count delta.

Output is markdown to --output (or stdout if omitted). A companion JSON
dump goes to --json-output for downstream tooling.

Not shipped to prod runtime; lives under tests/integration/ for
hand-invocation during the W4 validation.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


FUNCTION_RE = re.compile(r"<function=([a-zA-Z_][a-zA-Z0-9_]*)>")
CODE_GRAPH_PREFIX = "code_graph_"
# Shell-grep proxies: terminal_execute commands that are really structural
# searches. We use this to estimate "would code_graph have replaced this?"
# It's a heuristic — a curl over an HTTP target also goes through
# terminal_execute and we don't want to count those.
SHELL_GREP_RE = re.compile(
    r"\b(grep|rg|ripgrep|ast-grep|sg|find\s+.*-name|semgrep)\b",
    re.IGNORECASE,
)


@dataclass
class RunMetrics:
    run_dir: Path
    tool_calls: Counter = field(default_factory=Counter)
    iterations: int = 0
    wall_time_seconds: float | None = None
    finding_titles: list[str] = field(default_factory=list)
    finding_severity: Counter = field(default_factory=Counter)
    shell_grep_calls: int = 0
    code_graph_calls: int = 0
    code_graph_not_available_responses: int = 0


def _parse_conversation(run_dir: Path, metrics: RunMetrics) -> None:
    conv = run_dir / "conversation.jsonl"
    if not conv.exists():
        return
    with conv.open(encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            iteration = entry.get("iteration") or 0
            if isinstance(iteration, int):
                metrics.iterations = max(metrics.iterations, iteration)

            if entry.get("role") != "assistant":
                # Tool result outputs are user-role; scan for the
                # "code graph not available" string as a degraded-path
                # diagnostic.
                content = entry.get("content")
                if isinstance(content, str) and "code graph not available" in content:
                    metrics.code_graph_not_available_responses += 1
                continue

            content = entry.get("content")
            if not isinstance(content, str):
                continue

            # Tool-call extraction.
            for match in FUNCTION_RE.finditer(content):
                tool = match.group(1)
                metrics.tool_calls[tool] += 1
                if tool.startswith(CODE_GRAPH_PREFIX):
                    metrics.code_graph_calls += 1

            # Shell-grep heuristic — look for grep-shaped commands
            # inside terminal_execute / batch_terminal_execute. We only
            # count occurrences where the grep pattern co-occurs with a
            # function call to one of the shell tools (otherwise we'd
            # pick up references in prose).
            if "<function=terminal_execute>" in content or "<function=batch_terminal_execute>" in content:
                for match in SHELL_GREP_RE.finditer(content):
                    metrics.shell_grep_calls += 1


def _parse_events(run_dir: Path, metrics: RunMetrics) -> None:
    events = run_dir / "events.jsonl"
    if not events.exists():
        return
    start: datetime | None = None
    end: datetime | None = None
    with events.open(encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = entry.get("timestamp")
            event_type = entry.get("event_type")
            if not ts or not event_type:
                continue
            if event_type == "run.started" and start is None:
                start = _parse_ts(ts)
            elif event_type == "run.completed":
                end = _parse_ts(ts)
    if start is not None and end is not None:
        metrics.wall_time_seconds = (end - start).total_seconds()


def _parse_findings(run_dir: Path, metrics: RunMetrics) -> None:
    csv_path = run_dir / "vulnerabilities.csv"
    if not csv_path.exists():
        return
    with csv_path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            title = (row.get("title") or "").strip()
            if title:
                metrics.finding_titles.append(title)
            severity = (row.get("severity") or "").strip().upper()
            if severity:
                metrics.finding_severity[severity] += 1


def _parse_ts(ts: str) -> datetime | None:
    try:
        # SCIP/Strix uses ISO-8601 with Z or +offset.
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def collect_metrics(run_dir: Path) -> RunMetrics:
    metrics = RunMetrics(run_dir=run_dir)
    _parse_conversation(run_dir, metrics)
    _parse_events(run_dir, metrics)
    _parse_findings(run_dir, metrics)
    return metrics


def _fmt_int_delta(baseline: int, experiment: int) -> str:
    delta = experiment - baseline
    if delta == 0:
        return "—"
    sign = "+" if delta > 0 else ""
    pct = ""
    if baseline > 0:
        pct = f" ({sign}{(delta / baseline) * 100:.0f}%)"
    return f"{sign}{delta}{pct}"


def _render_tool_table(baseline: RunMetrics, experiment: RunMetrics) -> list[str]:
    rows: list[str] = ["| Tool | Baseline | Experiment | Δ |", "|---|---:|---:|---:|"]
    all_tools = sorted(set(baseline.tool_calls) | set(experiment.tool_calls))
    for tool in all_tools:
        b = baseline.tool_calls.get(tool, 0)
        e = experiment.tool_calls.get(tool, 0)
        if b == 0 and e == 0:
            continue
        rows.append(f"| `{tool}` | {b} | {e} | {_fmt_int_delta(b, e)} |")
    return rows


def _render_findings(baseline: RunMetrics, experiment: RunMetrics) -> list[str]:
    bset = set(baseline.finding_titles)
    eset = set(experiment.finding_titles)
    shared = bset & eset
    baseline_only = bset - eset
    experiment_only = eset - bset
    out: list[str] = []
    out.append(f"- Findings shared:      **{len(shared)}**")
    out.append(f"- Baseline only (missed by experiment): **{len(baseline_only)}**")
    out.append(f"- Experiment only (new in experiment):  **{len(experiment_only)}**")
    if baseline_only:
        out.append("\n### Findings missed by experiment (REGRESSION RISK)")
        for t in sorted(baseline_only):
            out.append(f"- {t}")
    if experiment_only:
        out.append("\n### New findings in experiment")
        for t in sorted(experiment_only):
            out.append(f"- {t}")
    return out


def render_report(baseline: RunMetrics, experiment: RunMetrics) -> str:
    lines: list[str] = []
    lines.append("# SEC-6848 W4 — code-graph validation delta report")
    lines.append("")
    lines.append(f"- Baseline run:   `{baseline.run_dir}`")
    lines.append(f"- Experiment run: `{experiment.run_dir}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Baseline | Experiment | Δ |")
    lines.append("|---|---:|---:|---:|")
    lines.append(f"| Iterations | {baseline.iterations} | {experiment.iterations} | {_fmt_int_delta(baseline.iterations, experiment.iterations)} |")
    if baseline.wall_time_seconds is not None and experiment.wall_time_seconds is not None:
        lines.append(
            f"| Wall time (s) | {baseline.wall_time_seconds:.0f} | {experiment.wall_time_seconds:.0f} | {_fmt_int_delta(int(baseline.wall_time_seconds), int(experiment.wall_time_seconds))} |"
        )
    lines.append(f"| Findings | {len(baseline.finding_titles)} | {len(experiment.finding_titles)} | {_fmt_int_delta(len(baseline.finding_titles), len(experiment.finding_titles))} |")
    lines.append(f"| `code_graph_*` calls | {baseline.code_graph_calls} | {experiment.code_graph_calls} | {_fmt_int_delta(baseline.code_graph_calls, experiment.code_graph_calls)} |")
    lines.append(f"| Shell-grep proxies (grep/rg/sg/semgrep/find) | {baseline.shell_grep_calls} | {experiment.shell_grep_calls} | {_fmt_int_delta(baseline.shell_grep_calls, experiment.shell_grep_calls)} |")
    lines.append(f"| 'code graph not available' responses | {baseline.code_graph_not_available_responses} | {experiment.code_graph_not_available_responses} | {_fmt_int_delta(baseline.code_graph_not_available_responses, experiment.code_graph_not_available_responses)} |")
    lines.append("")

    lines.append("## Decision (per W4 plan)")
    lines.append("")
    if not baseline.finding_titles:
        lines.append("- Baseline has 0 findings — comparison is degenerate; pick a real baseline.")
    else:
        parity = len(set(baseline.finding_titles) & set(experiment.finding_titles))
        parity_pct = parity / len(set(baseline.finding_titles)) * 100
        lines.append(f"- Finding parity: **{parity}/{len(set(baseline.finding_titles))} ({parity_pct:.0f}%)**")
    if experiment.code_graph_calls == 0:
        lines.append("- `code_graph_*` calls = 0 — code-graph integration did not activate. Diagnose before promoting.")
    elif experiment.code_graph_not_available_responses > 0:
        lines.append(f"- `code graph not available` fired **{experiment.code_graph_not_available_responses}x** — degraded path. Check sandbox image build.")
    else:
        lines.append(f"- `code_graph_*` fired **{experiment.code_graph_calls}x** with no degraded-path responses — integration live.")
    lines.append("")

    lines.append("## Tool-call histogram")
    lines.append("")
    lines.extend(_render_tool_table(baseline, experiment))
    lines.append("")

    lines.append("## Severity distribution")
    lines.append("")
    sev_levels = sorted(set(baseline.finding_severity) | set(experiment.finding_severity))
    if sev_levels:
        lines.append("| Severity | Baseline | Experiment |")
        lines.append("|---|---:|---:|")
        for sev in sev_levels:
            lines.append(f"| {sev} | {baseline.finding_severity.get(sev, 0)} | {experiment.finding_severity.get(sev, 0)} |")
    lines.append("")

    lines.append("## Finding-set diff")
    lines.append("")
    lines.extend(_render_findings(baseline, experiment))
    return "\n".join(lines)


def metrics_to_dict(m: RunMetrics) -> dict:
    return {
        "run_dir": str(m.run_dir),
        "iterations": m.iterations,
        "wall_time_seconds": m.wall_time_seconds,
        "finding_count": len(m.finding_titles),
        "finding_titles": sorted(m.finding_titles),
        "finding_severity": dict(m.finding_severity),
        "tool_calls": dict(m.tool_calls),
        "code_graph_calls": m.code_graph_calls,
        "shell_grep_calls": m.shell_grep_calls,
        "code_graph_not_available_responses": m.code_graph_not_available_responses,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", required=True, type=Path)
    p.add_argument("--experiment", required=True, type=Path)
    p.add_argument("--output", type=Path, default=None,
                   help="Markdown report path; stdout if omitted.")
    p.add_argument("--json-output", type=Path, default=None,
                   help="Optional JSON dump of metrics.")
    args = p.parse_args(argv)

    baseline = collect_metrics(args.baseline)
    experiment = collect_metrics(args.experiment)
    report = render_report(baseline, experiment)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    if args.json_output:
        args.json_output.write_text(
            json.dumps(
                {"baseline": metrics_to_dict(baseline), "experiment": metrics_to_dict(experiment)},
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"JSON written to {args.json_output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
