"""Per-run routing telemetry — route distribution, audit agreement, offload.

Accumulated as the scan runs (``_RoutingModel`` records each routing decision and
each audit result) and embedded into ``run.json`` under ``routing`` at save time,
so the routing wins are measurable — the feedback loop benchmarking needs.

Process-global (one scan per process for the CLI); ``reset()`` clears it.
"""

from __future__ import annotations

from collections import Counter
from typing import Any


_stats: dict[str, Any] = {
    "routed": Counter(),  # tier -> turns actually served by that tier (live)
    "shadow": Counter(),  # tier -> turns the plan would route (shadow)
    "models": Counter(),  # model id -> turns served (live)
    "audit_n": 0,
    "audit_agreed": 0,
}


def record_route(tier: str, model_id: str, *, live: bool) -> None:
    if live:
        _stats["routed"][tier] += 1
        _stats["models"][model_id] += 1
    else:
        _stats["shadow"][tier] += 1


def record_audit(*, agreed: bool) -> None:
    _stats["audit_n"] += 1
    if agreed:
        _stats["audit_agreed"] += 1


def has_data() -> bool:
    return bool(_stats["routed"] or _stats["shadow"] or _stats["audit_n"])


def snapshot() -> dict[str, Any]:
    """A JSON-friendly view for run.json / an end-of-scan summary."""
    routed = _stats["routed"]
    snap: dict[str, Any] = {}
    if routed:
        snap["routed"] = dict(routed)
        snap["models"] = dict(_stats["models"])
        total = sum(routed.values())
        # Fraction of live turns kept OFF the frontier (reasoning) tier.
        snap["frontier_offload_pct"] = round(100 * (total - routed.get("reasoning", 0)) / total, 1)
    if _stats["shadow"]:
        snap["planned"] = dict(_stats["shadow"])
    if _stats["audit_n"]:
        snap["audit"] = {
            "n": _stats["audit_n"],
            "agreed": _stats["audit_agreed"],
            "agreement_pct": round(100 * _stats["audit_agreed"] / _stats["audit_n"], 1),
        }
    return snap


def reset() -> None:
    _stats["routed"] = Counter()
    _stats["shadow"] = Counter()
    _stats["models"] = Counter()
    _stats["audit_n"] = 0
    _stats["audit_agreed"] = 0
