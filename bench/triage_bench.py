#!/usr/bin/env python3
"""Triage routing benchmark harness.

Runs a matrix of routing configs against one target and collects each run's
`run.json` — findings (quality), triage.frontier_offload_pct (cost proxy),
triage.audit.agreement_pct (safety proxy), tokens, and wall-clock — into one
comparison table. Vary ONE knob per config so the differences are legible.

Usage:  uv run python bench/triage_bench.py [--target PATH] [--max-turns N]

Needs: Docker (DOCKER_HOST), a Claude Code subscription (claude -p), and — for
the Jev tiers — a Jevstiller/TypeSafe endpoint (TYPESAFE_API_KEY/_BASE_URL in
the environment). Each config inherits the base env and overrides its knob.
"""
# ruff: noqa: T201 - a CLI harness; print is the output

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
RUNS = REPO / "strix_runs"
STRIX = REPO / ".venv" / "bin" / "strix"

# Base env every config inherits. The subscription path (claude -p) + a Jev
# endpoint for triage; idle watchdog off for slow local tiers.
BASE_ENV = {
    "STRIX_LLM": "claude-code/claude-opus-4-8",
    "STRIX_CLAUDE_CODE_MAX_PROCS": "4",
    "LLM_STREAM_IDLE_TIMEOUT": "0",
    "LLM_TIMEOUT": "1800",
    "STRIX_TIER_REASONING": "opus",
    "STRIX_TIER_STANDARD": "haiku",
    "STRIX_TIER_MECHANICAL": "haiku",
    "STRIX_TRIAGE_AUDIT_RATE": "0.2",
}

# One knob varied per config. Cheap/routed configs FIRST so a quota window that
# blows on the heavy all-opus baseline (last) still leaves the routed data.
CONFIGS: list[dict[str, dict[str, str]]] = [
    {
        "name": "route-floor-0.3",
        "env": {"STRIX_TRIAGE": "live", "STRIX_TRIAGE_MIN_CONFIDENCE": "0.3"},
    },
    {
        "name": "route-floor-0.5",
        "env": {"STRIX_TRIAGE": "live", "STRIX_TRIAGE_MIN_CONFIDENCE": "0.5"},
    },
    {"name": "baseline-opus", "env": {"STRIX_TRIAGE": "off"}},
]


def _run_dirs() -> set[str]:
    return {p.name for p in RUNS.iterdir()} if RUNS.exists() else set()


def run_one(cfg: dict[str, dict[str, str]], target: str, max_turns: int) -> dict[str, object]:
    env = {**os.environ, **BASE_ENV, **cfg["env"]}
    env.pop("LLM_API_KEY", None)
    env.pop("ANTHROPIC_API_KEY", None)
    before = _run_dirs()
    t0 = time.time()
    subprocess.run(  # noqa: S603 - trusted local binary, fixed argv
        [
            str(STRIX), "-n", "-m", "quick", "-t", target,
            "--max-turns", str(max_turns),
            "--instruction", "White-box review; focus on OWASP Top 10.",
        ],
        env=env,
        capture_output=True,
        check=False,
    )
    wall = time.time() - t0
    new = _run_dirs() - before
    if not new:
        return {"name": cfg["name"], "error": "no run dir produced", "wall_s": round(wall)}
    run_dir = RUNS / sorted(new)[-1]
    return _parse(cfg["name"], run_dir, wall)


def _parse(name: str, run_dir: Path, wall: float) -> dict[str, object]:
    rec = json.loads((run_dir / "run.json").read_text())
    vulns_dir = run_dir / "vulnerabilities"
    findings = len(list(vulns_dir.glob("*.md"))) if vulns_dir.exists() else 0
    lu = rec.get("llm_usage") or {}
    tri = rec.get("triage") or {}
    audit = tri.get("audit") or {}
    return {
        "name": name,
        "status": rec.get("status"),
        "findings": findings,
        "offload_pct": tri.get("frontier_offload_pct"),
        "audit_pct": audit.get("agreement_pct"),
        "requests": lu.get("requests"),
        "in_tok": lu.get("input_tokens"),
        "wall_s": round(wall),
        "run": run_dir.name,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=str(Path.home() / "strix-lab/targets/vuln-flask"))
    ap.add_argument("--max-turns", type=int, default=12)
    args = ap.parse_args()

    results = [run_one(c, args.target, args.max_turns) for c in CONFIGS]

    cols = [
        "name", "status", "findings", "offload_pct", "audit_pct", "requests", "in_tok", "wall_s"
    ]
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in results)) for c in cols}
    line = "  ".join(c.ljust(widths[c]) for c in cols)
    print("\n" + line)
    print("  ".join("-" * widths[c] for c in cols))
    for r in results:
        print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))
    print()
    (REPO / "bench" / "last_results.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
