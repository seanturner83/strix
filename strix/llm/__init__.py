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
    import sys
    from litellm.llms.bedrock import common_utils as _bedrock_utils

    _orig_is_claude_4_5 = _bedrock_utils.is_claude_4_5_on_bedrock

    def _patched_is_claude_4_5_on_bedrock(model: str) -> bool:
        if _orig_is_claude_4_5(model):
            return True
        m = model.lower()
        result = any(pat in m for pat in (
            "opus-4-7", "opus_4_7", "opus-4.7", "opus_4.7",
            "opus-4-8", "opus_4_8", "opus-4.8", "opus_4.8",
        ))
        # Loud signal so we can verify the patch is firing. Will spam
        # but easy to grep for. Remove once verified.
        print(f"[STRIX-CACHE-PATCH] is_claude_4_5_on_bedrock({model!r}) = {result}",
              file=sys.stderr, flush=True)
        return result

    _bedrock_utils.is_claude_4_5_on_bedrock = _patched_is_claude_4_5_on_bedrock

    # Patch every module that has already done a `from common_utils import
    # is_claude_4_5_on_bedrock`, since those module-local bindings won't
    # update when we replace the source. We reach over every loaded module
    # and stomp the binding in place if present.
    _patched_modules = []
    for _mod_name, _mod in list(sys.modules.items()):
        if _mod is None or not _mod_name.startswith("litellm."):
            continue
        if getattr(_mod, "is_claude_4_5_on_bedrock", None) is _orig_is_claude_4_5:
            _mod.is_claude_4_5_on_bedrock = _patched_is_claude_4_5_on_bedrock
            _patched_modules.append(_mod_name)

    print(f"[STRIX-CACHE-PATCH] patched modules: {_patched_modules}",
          file=sys.stderr, flush=True)
except Exception as _exc:  # noqa: BLE001
    import sys as _sys
    print(f"[STRIX-CACHE-PATCH] FAILED to install: {_exc!r}",
          file=_sys.stderr, flush=True)
