"""Capability/cost model map and the routing resolver.

The triage classifier returns a *capability tier*; this maps it to a concrete
model. Routing has two axes:

- **capability** — can the model do this turn/mission? (tier -> required rank)
- **cost regime** — where does the spend land? Three regimes with different
  economics: ``subscription`` (claude-code: $0 but quota/session-capped, poor
  cache), ``api`` (metered $/token, cache works), ``local`` (free, unlimited,
  hardware-bound).

``tier_model`` resolves a tier to ``(model_id, api_base)`` by, in order:
1. an explicit ``STRIX_TIER_<TIER>`` override (fleet name or raw ``provider/model``);
2. a ``STRIX_ROUTE_POLICY`` (subscription|api|local) — pick the cheapest model in
   that regime that is capable enough, so "optimise for the subscription / the
   API bill / local compute" is one setting;
3. the default map (frontier reasoning -> opus, standard -> sonnet, mechanical
   -> haiku).

The claude-code entries are 4.x: the 5.5 models trip the AUP safeguard on the
pentest prompt. Costs are *relative*, for ordering within a regime, not billing.
"""

from __future__ import annotations

import logging
import os


logger = logging.getLogger(__name__)

# Capability ranks, low -> high. A model serves a tier when its rank >= the
# tier's required rank.
_CAP_RANK = {"low": 0, "med": 1, "high": 2}
_TIER_REQUIRED = {"mechanical": "low", "standard": "med", "reasoning": "high"}

# The fleet: name -> entry. ``cost`` is relative (lower = cheaper) within ``regime``.
_FLEET: dict[str, dict[str, object]] = {
    # subscription regime (claude-code, 4.x)
    "opus": {"model": "claude-code/claude-opus-4-8", "api_base": None,
             "cap": "high", "regime": "subscription", "cost": 9.0},
    "sonnet": {"model": "claude-code/claude-sonnet-4-6", "api_base": None,
               "cap": "high", "regime": "subscription", "cost": 3.0},
    "haiku": {"model": "claude-code/claude-haiku-4-5", "api_base": None,
              "cap": "med", "regime": "subscription", "cost": 1.0},
    # metered API regime (caching works)
    "api-opus": {"model": "anthropic/claude-opus-4-8", "api_base": None,
                 "cap": "high", "regime": "api", "cost": 15.0},
    "api-sonnet": {"model": "anthropic/claude-sonnet-4-6", "api_base": None,
                   "cap": "high", "regime": "api", "cost": 3.0},
    "api-haiku": {"model": "anthropic/claude-haiku-4-5", "api_base": None,
                  "cap": "med", "regime": "api", "cost": 0.8},
    # local regime (free, unlimited, hardware-bound)
    "local-big": {"model": "qwen3.8-27b-ud-iq2xxs-q8head", "api_base": "http://localhost:1234/v1",
                  "cap": "med", "regime": "local", "cost": 0.0},
    "local-small": {"model": "minicpm5-1b", "api_base": "http://localhost:1234/v1",
                    "cap": "low", "regime": "local", "cost": 0.0},
}

_DEFAULT_TIER_MAP = {"reasoning": "opus", "standard": "sonnet", "mechanical": "haiku"}


def fleet() -> dict[str, tuple[str, str | None]]:
    """The fleet as name -> (model_id, api_base)."""
    return {name: (str(e["model"]), e["api_base"]) for name, e in _FLEET.items()}  # type: ignore[misc]


def route_policy() -> str | None:
    """``subscription`` | ``api`` | ``local`` from STRIX_ROUTE_POLICY, else None."""
    policy = os.environ.get("STRIX_ROUTE_POLICY", "").strip().lower()
    return policy if policy in ("subscription", "api", "local") else None


def _entry_model(entry: dict[str, object]) -> tuple[str, str | None]:
    return str(entry["model"]), entry["api_base"]  # type: ignore[return-value]


def _pick_by_policy(tier: str, policy: str) -> tuple[str, str | None] | None:
    """Cheapest model in ``policy``'s regime that is capable enough for ``tier``.

    Falls back to the most capable model in the regime if none clears the bar
    (staying in-regime respects the policy's intent, e.g. air-gap for local).
    """
    required = _CAP_RANK[_TIER_REQUIRED.get(tier, "high")]
    in_regime = [e for e in _FLEET.values() if e["regime"] == policy]
    if not in_regime:
        return None
    capable = [e for e in in_regime if _CAP_RANK[str(e["cap"])] >= required]
    if capable:
        return _entry_model(min(capable, key=lambda e: float(e["cost"])))  # type: ignore[arg-type]
    best = max(in_regime, key=lambda e: _CAP_RANK[str(e["cap"])])
    logger.warning(
        "no %s model meets tier=%s; using most-capable in regime (%s)", policy, tier, best["model"]
    )
    return _entry_model(best)


def tier_model(tier: str) -> tuple[str, str | None]:
    """Resolve a capability tier to ``(model_id, api_base)`` — override, then
    policy, then the default map. Unknown tier -> reasoning (safe default)."""
    override = os.environ.get(f"STRIX_TIER_{tier.upper()}", "").strip()
    if override:
        if override in _FLEET:
            return _entry_model(_FLEET[override])
        return override, None  # raw provider/model id
    policy = route_policy()
    if policy:
        picked = _pick_by_policy(tier, policy)
        if picked:
            return picked
    choice = _DEFAULT_TIER_MAP.get(tier) or _DEFAULT_TIER_MAP["reasoning"]
    return _entry_model(_FLEET[choice])
