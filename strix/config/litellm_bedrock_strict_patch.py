"""Strip `strict` from Bedrock Converse toolSpec (litellm 1.90.2 compat).

WHY: litellm's `_bedrock_tools_pt` copies the OpenAI-style `strict` field
straight into the Bedrock `toolSpec`, producing:

    {"toolSpec": {"name", "description", "inputSchema", "strict": true}}

Bedrock's Converse tool schema allows ONLY {name, description, inputSchema};
any extra key → HTTP 400. (Bedrock reports it as `tools.0.custom.strict:
Extra inputs are not permitted` — "custom" is Bedrock's internal label for the
tool, not a nested field.) litellm gates strict-tool support on
`get_bedrock_base_model(model).startswith("anthropic")` → it KEEPS strict for
Claude, wrongly believing the Converse endpoint honours it. So every
tool-calling scan against bedrock/*.anthropic.claude-* 400s at warm-up. The
openai-agents SDK (Strix v1) stamps strict on every FunctionTool via
ensure_strict_json_schema, so it fires universally.

Fix: wrap the converse transform to delete `strict` from every produced
toolSpec (both stream + non-stream go through transform_request). Idempotent,
import-once, fail-open. Upstream candidate: litellm's supports_strict_tools
must be False for the Converse endpoint — Converse never accepts toolSpec.strict.
"""

from __future__ import annotations

import logging


logger = logging.getLogger(__name__)

# Single-element list rather than a module global + `global` statement, so the
# idempotency guard mutates in place without tripping PLW0603.
_PATCHED = [False]


def _strip_strict_from_toolconfig(req: object) -> None:
    """Delete `strict` from every toolSpec in a transformed converse request."""
    if not isinstance(req, dict):
        return
    tc = req.get("toolConfig")
    tools = tc.get("tools") if isinstance(tc, dict) else req.get("tools")
    if not isinstance(tools, list):
        return
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        tool.pop("strict", None)  # top-level, just in case
        spec = tool.get("toolSpec")
        if isinstance(spec, dict):
            spec.pop("strict", None)  # the real leak site
        tool.pop("custom", None)  # Anthropic `custom` (litellm #22847)


def apply() -> None:
    if _PATCHED[0]:
        return
    try:
        from litellm.llms.bedrock.chat.converse_transformation import AmazonConverseConfig
    except ImportError as exc:  # litellm layout changed — fail open, don't break scans
        logger.warning("bedrock strict-patch skipped (litellm layout): %r", exc)
        return

    # THE seam: both the sync `completion` and the async path build the converse
    # body via _transform_request_helper — NOT the public transform_request /
    # _async_transform_request (those are never called on the sync completion path;
    # verified by instrumentation 2026-07-02, and confirmed the strip works here).
    # Patching the helper strips before json.dumps / Content-Length, every call.
    _orig = getattr(AmazonConverseConfig, "_transform_request_helper", None)
    if _orig is None:
        logger.warning(
            "bedrock strict-patch: _transform_request_helper absent — litellm layout changed"
        )
        return

    def _patched(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        req = _orig(self, *args, **kwargs)
        try:
            _strip_strict_from_toolconfig(req)
        except Exception:  # noqa: BLE001 — fail-open: a strip error must never break a scan
            logger.debug("strict strip: unexpected request shape", exc_info=True)
        return req

    # Deliberate monkeypatch of a private litellm method; dynamic assignment is
    # the whole point of this shim, so the method-assign warning is expected.
    AmazonConverseConfig._transform_request_helper = _patched  # type: ignore[method-assign]
    _PATCHED[0] = True
    logger.info(
        "Applied Bedrock toolSpec.strict strip patch (litellm compat, _transform_request_helper)"
    )
