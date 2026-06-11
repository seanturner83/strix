import logging
import warnings

import litellm

from .config import LLMConfig
from .llm import LLM, LLMRequestFailedError


__all__ = [
    "LLM",
    "LLMConfig",
    "LLMRequestFailedError",
]

litellm._logging._disable_debugging()
logging.getLogger("asyncio").setLevel(logging.CRITICAL)
logging.getLogger("asyncio").propagate = False
warnings.filterwarnings("ignore", category=RuntimeWarning, module="asyncio")


# Forward-compat hedge for BerriAI/litellm#20326. LiteLLM gates Bedrock
# 1h-TTL cache forwarding on a hard-coded model-name allowlist
# (`is_claude_4_5_on_bedrock`). 1.88.1 added `opus-4-7` to the list; it
# does NOT yet include `opus-4-8` or any future Opus tier we'd jump to.
# This patch extends the allowlist for our 4.x models so a future model
# bump doesn't silently disable 1h caching mid-flight. No-op for current
# 4.7 (the upstream allowlist already covers it). Drop when LiteLLM
# tracks the trailing edge.
try:
    from litellm.llms.bedrock import common_utils as _bedrock_utils
    import sys as _sys

    _orig_is_claude_4_5 = _bedrock_utils.is_claude_4_5_on_bedrock

    def _patched_is_claude_4_5_on_bedrock(model: str) -> bool:
        if _orig_is_claude_4_5(model):
            return True
        m = model.lower()
        return any(pat in m for pat in (
            "opus-4-8", "opus_4_8", "opus-4.8", "opus_4.8",
        ))

    _bedrock_utils.is_claude_4_5_on_bedrock = _patched_is_claude_4_5_on_bedrock
    # Stomp module-local bindings of any litellm submodule that already
    # imported the function — `from foo import bar` binds at import time.
    for _mod_name, _mod in list(_sys.modules.items()):
        if _mod is None or not _mod_name.startswith("litellm."):
            continue
        if getattr(_mod, "is_claude_4_5_on_bedrock", None) is _orig_is_claude_4_5:
            _mod.is_claude_4_5_on_bedrock = _patched_is_claude_4_5_on_bedrock
except Exception:  # noqa: BLE001
    # Best-effort. If LiteLLM reshapes the module the patch becomes
    # unavailable and we fall back to upstream behavior, which is
    # currently sufficient for opus-4-7. Silent on failure to avoid
    # noisy startup on models that don't need this anyway.
    pass
