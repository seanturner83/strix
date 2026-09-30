"""Known-good model fleet and the capability-tier → model map.

The triage classifier (``triage.classify_turn``) returns a *capability tier*;
this maps each tier to a concrete model so routing can spend the cheapest model
that can serve the turn. Two layers:

- **The fleet** — models verified to work for Strix. The ``claude-code`` entries
  are all 4.x on purpose: the 5.5 models trip Claude Code's AUP safeguard on the
  pentest prompt, the 4.x ones do not.
- **The tier map** — which fleet model serves each capability tier. Overridable
  per tier with ``STRIX_TIER_<TIER>`` (a fleet name like ``sonnet`` or a raw
  ``provider/model`` id), so you can retune without code.
"""

from __future__ import annotations

import os


# Known-good fleet: name -> (STRIX_LLM-style model id, api_base or None).
# api_base is set for local/OpenAI-compatible endpoints; None routes normally.
_FLEET: dict[str, tuple[str, str | None]] = {
    "opus": ("claude-code/claude-opus-4-8", None),
    "sonnet": ("claude-code/claude-sonnet-4-6", None),
    "haiku": ("claude-code/claude-haiku-4-5", None),
    "local-big": ("qwen3.8-27b-ud-iq2xxs-q8head", "http://localhost:1234/v1"),
    "local-small": ("minicpm5-1b", "http://localhost:1234/v1"),
}

# Default capability-tier -> fleet model. Frontier reasoning gets opus; ordinary
# steps get sonnet; mechanical follow-ups get haiku (swap to local-* for $0).
_DEFAULT_TIER_MAP: dict[str, str] = {
    "reasoning": "opus",
    "standard": "sonnet",
    "mechanical": "haiku",
}


def fleet() -> dict[str, tuple[str, str | None]]:
    """The known-good model fleet (name -> (model_id, api_base))."""
    return dict(_FLEET)


def tier_model(tier: str) -> tuple[str, str | None]:
    """Resolve a capability tier to ``(model_id, api_base)``.

    ``STRIX_TIER_<TIER>`` overrides the default; its value is a fleet name or a
    raw ``provider/model`` id. An unknown tier falls back to the ``reasoning``
    tier (the safe, most-capable default).
    """
    override = os.environ.get(f"STRIX_TIER_{tier.upper()}", "").strip()
    choice = override or _DEFAULT_TIER_MAP.get(tier) or _DEFAULT_TIER_MAP["reasoning"]
    if choice in _FLEET:
        return _FLEET[choice]
    # A raw model id (not a fleet name): route it normally, no api_base.
    return choice, None
