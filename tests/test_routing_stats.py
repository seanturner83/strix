"""Per-run routing telemetry accumulation and snapshot."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.config import routing_stats


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def _fresh() -> Iterator[None]:
    routing_stats.reset()
    yield
    routing_stats.reset()


def test_empty_has_no_data(_fresh: None) -> None:
    assert routing_stats.has_data() is False
    assert routing_stats.snapshot() == {}


def test_route_distribution_and_offload(_fresh: None) -> None:
    routing_stats.record_route("standard", "haiku", live=True)
    routing_stats.record_route("standard", "haiku", live=True)
    routing_stats.record_route("reasoning", "opus", live=True)
    snap = routing_stats.snapshot()
    assert snap["routed"] == {"standard": 2, "reasoning": 1}
    assert snap["models"] == {"haiku": 2, "opus": 1}
    assert snap["frontier_offload_pct"] == 66.7  # 2 of 3 kept off the frontier


def test_shadow_routes_are_planned_not_routed(_fresh: None) -> None:
    routing_stats.record_route("standard", "haiku", live=False)
    snap = routing_stats.snapshot()
    assert snap["planned"] == {"standard": 1}
    assert "routed" not in snap  # shadow doesn't count as served


def test_audit_agreement(_fresh: None) -> None:
    for agreed in (True, True, True, False):
        routing_stats.record_audit(agreed=agreed)
    assert routing_stats.snapshot()["audit"] == {"n": 4, "agreed": 3, "agreement_pct": 75.0}
