"""Claude-5 cost-map registration — the rebase-regression fix.

v1.4's #772 gate injects prompt caching only for models litellm marks
supports_prompt_caching. litellm 1.90.1 doesn't map sonnet-5/opus-5, so without
this patch they run UNCACHED (regression vs the 1.2 fork). These lock in that the
patch makes the #772 guard pass for the 5-family AND doesn't clobber already-
mapped models.
"""

from __future__ import annotations

import litellm

from strix.config.litellm_costmap_patch import _PATCHED, _PRICES, apply
from strix.config.models import bedrock_route_supports_prompt_caching
from strix.core.inputs import make_model_settings


def _reset():
    _PATCHED[0] = False


def test_registers_sonnet5_and_opus5_as_cache_capable():
    _reset()
    apply()
    for stem in ("sonnet-5", "opus-5"):
        m = f"bedrock/global.anthropic.claude-{stem}"
        assert bedrock_route_supports_prompt_caching(m), f"{stem} should be cache-capable"


def test_cache_injected_end_to_end_for_5_family():
    _reset()
    apply()
    for stem in ("sonnet-5", "opus-5"):
        for route in ("bedrock/converse/us.anthropic.claude-{}",
                      "bedrock/global.anthropic.claude-{}"):
            m = route.format(stem)
            ms = make_model_settings(
                None, model_name=m, force_required_tool_choice=False,
                request_timeout=300, prompt_cache=True,
            )
            assert "cache_control_injection_points" in (ms.extra_args or {}), m


def test_pricing_matches_4x_tiers():
    _reset()
    apply()
    # litellm.register_model stores under the route-prefix-stripped key
    # (bedrock/... -> global.anthropic.claude-...); the guard's candidate walk
    # strips prefixes to match, so any variant resolves.
    sonnet = litellm.model_cost.get("global.anthropic.claude-sonnet-5", {})
    opus = litellm.model_cost.get("global.anthropic.claude-opus-5", {})
    assert sonnet.get("input_cost_per_token") == 3.0 / 1_000_000
    assert sonnet.get("output_cost_per_token") == 15.0 / 1_000_000
    assert opus.get("input_cost_per_token") == 5.0 / 1_000_000
    # standard cache ratios
    assert sonnet.get("cache_read_input_token_cost") == (3.0 / 1_000_000) * 0.1
    assert sonnet.get("cache_creation_input_token_cost") == (3.0 / 1_000_000) * 1.25


def test_does_not_clobber_already_mapped_models():
    # fable-5 + opus-4-8 are already in litellm's map; the patch must leave their
    # (authoritative) pricing untouched and is not even in _PRICES.
    assert "fable-5" not in _PRICES
    assert "opus-4-8" not in _PRICES
    _reset()
    key = "global.anthropic.claude-opus-4-8"  # litellm's bundled key form
    before = dict(litellm.model_cost.get(key, {}))
    apply()
    after = litellm.model_cost.get(key, {})
    assert before.get("input_cost_per_token") == after.get("input_cost_per_token")
    assert before.get("input_cost_per_token") is not None  # sanity: the key exists


def test_idempotent():
    _reset()
    apply()
    apply()  # second call is a no-op (guard); must not raise or double-register
    assert _PATCHED[0] is True
