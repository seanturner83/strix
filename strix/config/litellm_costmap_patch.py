"""Register Claude-5-family models in litellm's cost map so prompt caching fires.

WHY (regression the v1.2->v1.4 rebase surfaced): upstream #772 added a
``bedrock_route_supports_prompt_caching`` gate in strix/core/inputs.py — cache
breakpoints are now injected ONLY when litellm's model map marks the model
``supports_prompt_caching``. litellm 1.90.1's bundled map does NOT yet list
``claude-sonnet-5`` / ``claude-opus-5`` (fable-5 and opus-4-8 ARE listed), so on
the rebased tree those two models run with NO caching at all — a silent cost
regression versus the 1.2 fork, whose make_model_settings cached for ANY Claude
model with no map gate.

Bedrock DOES cache sonnet-5/opus-5 (same Converse cachePoint mechanism as every
other Claude); litellm's map is simply behind. Registering them (with
``supports_prompt_caching=True`` + pricing) both lets the #772 guard pass — so
caching is injected — and gives correct cost accounting.

SCOPE: register only models litellm doesn't already know as cache-capable (never
clobber a good bundled entry — fable-5/opus-4-8 are left alone). Idempotent,
import-once, fail-open (a registration error must never break a scan). Pricing is
per-Mtoken; cache-write = 1.25x input, cache-read = 0.1x input (Anthropic's
standard ratios). Update _PRICES when Bedrock 5-family pricing is confirmed.

This is the fork-internal, prod-path equivalent of the VLB harness's external
costmap_shim.py (which only fixed ad-hoc local runs via PYTHONPATH).
"""

from __future__ import annotations

import logging


logger = logging.getLogger(__name__)

_PATCHED = [False]

# model-family stem -> (input $/Mtok, output $/Mtok). Only the ones litellm 1.90.1
# is missing that we want to run WITH caching. 5-family matched to 4.x tiers
# (sonnet-5 = sonnet-4-6 = $3/$15; opus-5 = opus-4-8 = $5/$25) pending confirmed
# Bedrock 5 pricing. fable-5 + opus-4-8 intentionally omitted — already mapped.
_PRICES: dict[str, tuple[float, float]] = {
    "sonnet-5": (3.0, 15.0),
    "opus-5": (5.0, 25.0),
}

# Every id-variant litellm might key the model under (route prefix + region/
# provider dotted segments), so the guard's name-candidate walk resolves any form.
_ID_TEMPLATES = [
    "claude-{m}",
    "anthropic.claude-{m}",
    "us.anthropic.claude-{m}",
    "global.anthropic.claude-{m}",
    "bedrock/us.anthropic.claude-{m}",
    "bedrock/global.anthropic.claude-{m}",
    "bedrock/converse/us.anthropic.claude-{m}",
    "bedrock/converse/global.anthropic.claude-{m}",
]


def _entry(in_mtok: float, out_mtok: float) -> dict[str, object]:
    inp = in_mtok / 1_000_000
    out = out_mtok / 1_000_000
    return {
        "litellm_provider": "bedrock",
        "mode": "chat",
        "input_cost_per_token": inp,
        "output_cost_per_token": out,
        "cache_creation_input_token_cost": inp * 1.25,
        "cache_read_input_token_cost": inp * 0.1,
        "supports_prompt_caching": True,
        "supports_function_calling": True,
    }


def apply() -> None:
    if _PATCHED[0]:
        return
    try:
        import litellm
    except ImportError as exc:  # pragma: no cover — litellm is a hard dep
        logger.warning("costmap-patch skipped (no litellm): %r", exc)
        return

    registered: list[str] = []
    for stem, (in_mtok, out_mtok) in _PRICES.items():
        entry = _entry(in_mtok, out_mtok)
        for tmpl in _ID_TEMPLATES:
            key = tmpl.format(m=stem)
            # Don't clobber a model litellm already knows as cache-capable.
            existing = litellm.model_cost.get(key)
            if existing and existing.get("supports_prompt_caching"):
                continue
            try:
                litellm.register_model({key: entry})
                registered.append(key)
            except Exception:  # noqa: BLE001 — one bad key must not abort registration
                logger.debug("costmap-patch: register failed for %s", key, exc_info=True)
    _PATCHED[0] = True
    if registered:
        logger.info(
            "Registered %d Claude-5 cost-map entries for prompt caching (%s)",
            len(registered), ", ".join(sorted(_PRICES)),
        )
