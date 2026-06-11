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


# Workaround for BerriAI/litellm#20326: LiteLLM gates Bedrock 1h-TTL
# cache forwarding on a hard-coded model-name allowlist that misses
# Opus 4.7 and 4.8. Bedrock's API itself accepts 1h TTL on all Claude 4.x
# models that support caching (Anthropic launched this Jan 2026), but
# LiteLLM's `is_claude_4_5_on_bedrock` returns False for `opus-4-7` /
# `opus-4-8`, so the `ttl: 1h` field gets silently dropped from the
# cachePoint block before the request leaves LiteLLM. This monkey-patch
# extends the allowlist to cover our actual models. Drop when upstream
# resolves the issue.
try:
    from litellm.llms.bedrock import common_utils as _bedrock_utils

    _orig_is_claude_4_5 = _bedrock_utils.is_claude_4_5_on_bedrock

    def _patched_is_claude_4_5_on_bedrock(model: str) -> bool:
        if _orig_is_claude_4_5(model):
            return True
        m = model.lower()
        return any(pat in m for pat in (
            "opus-4-7", "opus_4_7", "opus-4.7", "opus_4.7",
            "opus-4-8", "opus_4_8", "opus-4.8", "opus_4.8",
        ))

    _bedrock_utils.is_claude_4_5_on_bedrock = _patched_is_claude_4_5_on_bedrock

    # ALSO patch the imported reference inside converse_transformation —
    # `from foo import bar` binds at import time, so updating the module
    # source isn't enough; the imported binding inside transformer must
    # be replaced too.
    try:
        from litellm.llms.bedrock.chat import converse_transformation as _conv_xform
        _conv_xform.is_claude_4_5_on_bedrock = _patched_is_claude_4_5_on_bedrock
    except Exception:  # noqa: BLE001
        pass
except Exception:  # noqa: BLE001
    # Upstream LiteLLM may eventually fix the function or reshape the
    # module — in either case we don't want a startup crash.
    pass
