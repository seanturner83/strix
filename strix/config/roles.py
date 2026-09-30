"""Per-role model routing — the System-2 / System-1.5 split.

The orchestrator (the root reasoning loop and its acts) can run on one backend
while bulk, off-critical-path work routes elsewhere. Each role falls back to the
main ``STRIX_LLM`` so an unset role changes nothing.

Deliberate design note: ``subagent`` and ``compressor`` fall back through the
*orchestrator* model, never to a cheap default. Compaction especially is
quality-critical — a weak summariser drops decision-relevant state (tested
endpoints, working creds, open leads) — so a cheaper compressor is strictly
opt-in, and the guidance is "capable, not cheapest."
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.config import load_settings


if TYPE_CHECKING:
    from strix.config.settings import LlmSettings


_VALID_ROLES = ("orchestrator", "subagent", "compressor")


def resolve_role_model(
    role: str | None, llm: LlmSettings | None = None
) -> tuple[str | None, str | None]:
    """Return ``(model, api_base)`` for ``role``, falling back to ``STRIX_LLM``.

    Pass ``llm`` when the caller already holds the loaded settings so there is a
    single source of truth (and test monkeypatching of the caller's settings is
    honoured); otherwise the current settings are loaded.

    Chains:
      - orchestrator: STRIX_LLM_ORCHESTRATOR -> STRIX_LLM
      - subagent:     STRIX_LLM_SUBAGENT -> STRIX_LLM_ORCHESTRATOR -> STRIX_LLM
      - compressor:   STRIX_LLM_COMPRESSOR -> STRIX_LLM_ORCHESTRATOR -> STRIX_LLM
    """
    if llm is None:
        llm = load_settings().llm

    # getattr keeps this robust to any settings-like object (e.g. a test mock)
    # that predates the per-role fields: a missing field just falls through.
    def _role(name: str) -> tuple[str | None, str | None]:
        return getattr(llm, f"{name}_model", None), getattr(llm, f"{name}_api_base", None)

    chains: dict[str, list[tuple[str | None, str | None]]] = {
        "orchestrator": [_role("orchestrator")],
        "subagent": [_role("subagent"), _role("orchestrator")],
        "compressor": [_role("compressor"), _role("orchestrator")],
    }
    for model, api_base in chains.get(role or "", []):
        if model:
            return model, api_base
    return getattr(llm, "model", None), getattr(llm, "api_base", None)
