import concurrent.futures
import logging
import time
from collections.abc import Callable
from typing import Any

import litellm
from pydantic import ValidationError

from strix.config.config import Config, resolve_llm_config


_TRANSIENT_HTTP_CODES = frozenset({429, 500, 502, 503, 504})
_TRANSIENT_MESSAGE_MARKERS = (
    "serviceunavailable",
    "throttl",
    "ratelimit",
    "rate limit",
    "toomanyrequests",
    "too many requests",
)


def _is_transient_bedrock_error(exc: BaseException) -> bool:
    """Heuristic: Bedrock capacity / throttling errors that warrant a retry.

    Compressor calls go through litellm's sync path (not the orchestrator's
    streaming path), so we can't reuse `LLM._should_retry`. Match by status
    code first; fall back to message-substring checks for cases where the
    status code isn't surfaced on the exception (we've seen both shapes).
    """
    code = getattr(exc, "status_code", None) or getattr(
        getattr(exc, "response", None), "status_code", None
    )
    if code in _TRANSIENT_HTTP_CODES:
        return True
    msg = str(exc).lower()
    return any(marker in msg for marker in _TRANSIENT_MESSAGE_MARKERS)


UsageCallback = Callable[[Any, str], None]


logger = logging.getLogger(__name__)


def _is_known_bedrock_content_filtered_bug(exc: BaseException) -> bool:
    """Detect the known LiteLLM ↔ Bedrock Converse enum mismatch.

    Bedrock's Converse API returns `stopReason: "content_filtered"` when
    Anthropic guardrails trip. LiteLLM 1.81.x (and upstream main as of
    2026-05-21) only accepts `"content_filter"` (no `d`) in its
    `OpenAIChatCompletionFinishReason` Literal, so the response fails
    Pydantic validation. LiteLLM then wraps the ValidationError as
    `litellm.exceptions.APIConnectionError` before it propagates to our
    `_summarize_messages` call site — see strix-targeted-rescan run
    26242905324 (cc-apps infra scan) where the wrapping caused this
    detector to miss in production despite passing in unit tests that
    raised ValidationError directly.

    Detector is exception-type-agnostic: inspects str(exc) for the
    `finish_reason` + `literal_error` + `content_filtered` signature.
    Catches both the bare Pydantic form (rare — only in tests / direct
    construction) and the LiteLLM-wrapped form (the actual prod shape).
    Other ValidationErrors / APIConnectionErrors stay loud.
    """
    # Fast path: bare Pydantic ValidationError exposes structured .errors().
    if isinstance(exc, ValidationError):
        for err in exc.errors():
            if (
                err.get("type") == "literal_error"
                and err.get("loc") == ("finish_reason",)
                and err.get("input") == "content_filtered"
            ):
                return True
        return False
    # Wrapped form (LiteLLM APIConnectionError or any other re-raise that
    # preserves the original Pydantic message): match on the signature
    # substring. All three tokens must appear so we don't match unrelated
    # APIConnectionErrors that happen to mention one of these words.
    msg = str(exc)
    return (
        "literal_error" in msg
        and "finish_reason" in msg
        and "content_filtered" in msg
    )


DEFAULT_MAX_TOTAL_TOKENS = 100_000
DEFAULT_MIN_RECENT_MESSAGES = 15
DEFAULT_MAX_TOOL_OUTPUT_CHARS = 0  # 0 = no truncation (backwards compatible)

TOOL_TRUNCATION_NOTICE = (
    "\n\n[Output truncated: showing first {head_len} and last {tail_len} characters "
    "of {original_len}-character output (limit: {max_len}). "
    "The middle portion has been permanently removed.]"
)

SUMMARY_PROMPT_TEMPLATE = """You are an agent performing context
condensation for a security agent. Your job is to compress scan data while preserving
ALL operationally critical information for continuing the security assessment.

CRITICAL ELEMENTS TO PRESERVE:
- Discovered vulnerabilities and potential attack vectors
- Scan results and tool outputs (compressed but maintaining key findings)
- Access credentials, tokens, or authentication details found
- System architecture insights and potential weak points
- Progress made in the assessment
- Failed attempts and dead ends (to avoid duplication)
- Any decisions made about the testing approach

COMPRESSION GUIDELINES:
- Preserve exact technical details (URLs, paths, parameters, payloads)
- Summarize verbose tool outputs while keeping critical findings
- Maintain version numbers, specific technologies identified
- Keep exact error messages that might indicate vulnerabilities
- Compress repetitive or similar findings into consolidated form

Remember: Another security agent will use this summary to continue the assessment.
They must be able to pick up exactly where you left off without losing any
operational advantage or context needed to find vulnerabilities.

CONVERSATION SEGMENT TO SUMMARIZE:
{conversation}

Provide a technically precise summary that preserves all operational security context while
keeping the summary concise and to the point."""


def _count_tokens(text: str, model: str) -> int:
    try:
        count = litellm.token_counter(model=model, text=text)
        return int(count)
    except Exception:
        logger.exception("Failed to count tokens")
        return len(text) // 4  # Rough estimate


def get_message_tokens(msg: dict[str, Any], model: str) -> int:
    content = msg.get("content", "")
    if isinstance(content, str):
        return _count_tokens(content, model)
    if isinstance(content, list):
        return sum(
            _count_tokens(item.get("text", ""), model)
            for item in content
            if isinstance(item, dict) and item.get("type") == "text"
        )
    return 0


def _extract_message_text(msg: dict[str, Any]) -> str:
    content = msg.get("content", "")
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(item.get("text", ""))
                elif item.get("type") == "image_url":
                    parts.append("[IMAGE]")
        return " ".join(parts)

    return str(content)


def _summarize_messages(
    messages: list[dict[str, Any]],
    model: str,
    timeout: int = 30,
    on_usage: UsageCallback | None = None,
) -> dict[str, Any]:
    if not messages:
        empty_summary = "<context_summary message_count='0'>{text}</context_summary>"
        return {
            "role": "user",
            "content": empty_summary.format(text="No messages to summarize"),
        }

    formatted = []
    for msg in messages:
        role = msg.get("role", "unknown")
        text = _extract_message_text(msg)
        formatted.append(f"{role}: {text}")

    conversation = "\n".join(formatted)
    prompt = SUMMARY_PROMPT_TEMPLATE.format(conversation=conversation)

    _, api_key, api_base = resolve_llm_config(role="compressor")

    try:
        completion_args: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "timeout": timeout,
        }
        if api_key:
            completion_args["api_key"] = api_key
        if api_base:
            completion_args["api_base"] = api_base

        # Wall-clock timeout guard. litellm.completion's `timeout` kwarg does
        # not reliably propagate to the underlying httpx client in the Bedrock
        # sync path (we see "Connection timed out after None seconds" even
        # though we passed an int). Wrapping in a ThreadPoolExecutor gives us
        # a hard wall-clock bail regardless of what litellm does internally.
        # The abandoned future's HTTP call continues in the background thread
        # until the AWS SDK gives up, but we return to the caller promptly
        # and the fallback path logs the failure and returns messages[0].
        #
        # Retry on transient Bedrock errors (503/429/throttling). Without
        # this, a single capacity blip during a Sonnet-as-compressor run
        # silently drops the chunk to messages[0], losing 9/10 messages of
        # context. Budget: 4 attempts, 2s/4s/8s backoff (~14s ceiling).
        # Wall-clock TimeoutError isn't retried (would compound the budget).
        max_attempts = 4
        last_exc: BaseException | None = None
        response = None
        for attempt in range(max_attempts):
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(litellm.completion, **completion_args)
                    try:
                        response = future.result(timeout=timeout)
                    except concurrent.futures.TimeoutError as exc:
                        raise TimeoutError(
                            f"memory_compressor: litellm.completion exceeded "
                            f"{timeout}s wall-clock budget"
                        ) from exc
                break
            except TimeoutError:
                raise
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt < max_attempts - 1 and _is_transient_bedrock_error(exc):
                    wait = min(30, 2 * (2 ** attempt))
                    logger.info(
                        "Compressor transient %s on attempt %d/%d; retrying in %ds",
                        type(exc).__name__,
                        attempt + 1,
                        max_attempts,
                        wait,
                    )
                    time.sleep(wait)
                    continue
                raise
        else:
            if last_exc is not None:
                raise last_exc
        assert response is not None  # noqa: S101 (loop guarantees on success)

        if on_usage is not None:
            try:
                on_usage(response, model)
            except Exception:  # noqa: BLE001
                logger.exception("Compressor usage callback failed")
        summary = response.choices[0].message.content or ""
        if not summary.strip():
            return messages[0]
        summary_msg = "<context_summary message_count='{count}'>{text}</context_summary>"
        return {
            "role": "user",
            "content": summary_msg.format(count=len(messages), text=summary),
        }
    except Exception as exc:
        # The known LiteLLM ↔ Bedrock Converse content_filtered enum mismatch
        # can surface in two shapes:
        #   - Direct pydantic.ValidationError (rare; mostly in tests)
        #   - litellm.exceptions.APIConnectionError wrapping the ValidationError
        #     message (the actual production shape — observed on
        #     strix-targeted-rescan run 26242905324 / cc-apps infra scan)
        # The detector inspects either form and returns True only for the
        # exact signature. Anything else falls through to the loud log.
        if _is_known_bedrock_content_filtered_bug(exc):
            logger.info(
                "Skipping memory compression this round: Bedrock returned "
                "stopReason=content_filtered, which LiteLLM's finish_reason "
                "Literal doesn't accept. Known issue, scan continues."
            )
            return messages[0]
        logger.exception("Failed to summarize messages")
        return messages[0]


def _truncate_tool_output(text: str, max_chars: int) -> str:
    """Truncate large tool outputs while preserving the beginning and end.

    Keeps the first 60% and last 40% of the allowed length so that both
    the command/header and the tail of the output (often containing summaries
    or error messages) are preserved.
    """
    if max_chars <= 0 or len(text) <= max_chars:
        return text

    head_len = int(max_chars * 0.6)
    tail_len = max_chars - head_len
    notice = TOOL_TRUNCATION_NOTICE.format(
        original_len=len(text), max_len=max_chars, head_len=head_len, tail_len=tail_len
    )
    return text[:head_len] + notice + text[-tail_len:]


def _handle_images(messages: list[dict[str, Any]], max_images: int) -> None:
    image_count = 0
    for msg in reversed(messages):
        content = msg.get("content", [])
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "image_url":
                    if image_count >= max_images:
                        item.update(
                            {
                                "type": "text",
                                "text": "[Previously attached image removed to preserve context]",
                            }
                        )
                    else:
                        image_count += 1


class MemoryCompressor:
    def __init__(
        self,
        max_images: int = 3,
        model_name: str | None = None,
        timeout: int | None = None,
        on_usage: UsageCallback | None = None,
    ):
        self.max_images = max_images
        if model_name is None:
            resolved, _, _ = resolve_llm_config(role="compressor")
            self.model_name = resolved
        else:
            self.model_name = model_name
        self.timeout = timeout or int(Config.get("strix_memory_compressor_timeout") or "120")
        self.on_usage = on_usage

        self.max_total_tokens = int(
            Config.get("strix_max_context_tokens") or str(DEFAULT_MAX_TOTAL_TOKENS)
        )
        self.min_recent_messages = int(
            Config.get("strix_min_recent_messages") or str(DEFAULT_MIN_RECENT_MESSAGES)
        )
        self.max_tool_output_chars = int(
            Config.get("strix_max_tool_output_chars") or str(DEFAULT_MAX_TOOL_OUTPUT_CHARS)
        )

        self.max_total_tokens = int(
            Config.get("strix_max_context_tokens") or str(DEFAULT_MAX_TOTAL_TOKENS)
        )
        self.min_recent_messages = int(
            Config.get("strix_min_recent_messages") or str(DEFAULT_MIN_RECENT_MESSAGES)
        )
        self.max_tool_output_chars = int(
            Config.get("strix_max_tool_output_chars") or str(DEFAULT_MAX_TOOL_OUTPUT_CHARS)
        )

        if not self.model_name:
            raise ValueError("STRIX_LLM environment variable must be set and not empty")

    def truncate_tool_outputs(self, messages: list[dict[str, Any]]) -> None:
        """Truncate large tool output messages in-place.

        This prevents oversized tool results (nmap scans, file contents, etc.)
        from accumulating in the conversation history and being resent on every
        subsequent LLM call. Applied at ingestion time before the history grows.

        Only truncates tool-role messages and tool_result content blocks to
        avoid corrupting system prompts or user/assistant messages.
        """
        if self.max_tool_output_chars <= 0:
            return

        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")

            # Direct tool-role messages (string content)
            if role == "tool" and isinstance(content, str) and len(content) > self.max_tool_output_chars:
                msg["content"] = _truncate_tool_output(content, self.max_tool_output_chars)
            # Anthropic-style: tool_result blocks embedded in user messages
            elif isinstance(content, list):
                for item in content:
                    if not isinstance(item, dict):
                        continue
                    if (
                        item.get("type") == "tool_result"
                        and isinstance(item.get("content"), str)
                        and len(item["content"]) > self.max_tool_output_chars
                    ):
                        item["content"] = _truncate_tool_output(
                            item["content"], self.max_tool_output_chars
                        )
                    elif (
                        item.get("type") == "tool_result"
                        and isinstance(item.get("content"), list)
                    ):
                        for sub in item["content"]:
                            if (
                                isinstance(sub, dict)
                                and sub.get("type") == "text"
                                and len(sub.get("text", "")) > self.max_tool_output_chars
                            ):
                                sub["text"] = _truncate_tool_output(
                                    sub["text"], self.max_tool_output_chars
                                )

    def compress_history(
        self,
        messages: list[dict[str, Any]],
        reserved_tokens: int = 0,
    ) -> list[dict[str, Any]]:
        """Compress conversation history to stay within token limits.

        Args:
            messages: Conversation history messages to compress.
            reserved_tokens: Tokens already reserved for system prompt and
                other framing messages outside the conversation history.
                Subtracted from the budget before checking limits.

        Strategy:
        1. Truncate oversized tool outputs first
        2. Handle image limits
        3. Keep all system messages
        4. Keep minimum recent messages
        5. Summarize older messages when total tokens exceed limit

        The compression preserves:
        - All system messages unchanged
        - Most recent messages intact
        - Critical security context in summaries
        - Recent images for visual context
        - Technical details and findings
        """
        if not messages:
            return messages

        self.truncate_tool_outputs(messages)
        _handle_images(messages, self.max_images)

        system_msgs = []
        regular_msgs = []
        for msg in messages:
            if msg.get("role") == "system":
                system_msgs.append(msg)
            else:
                regular_msgs.append(msg)

        recent_msgs = regular_msgs[-self.min_recent_messages:]
        old_msgs = regular_msgs[:-self.min_recent_messages]

        # Type assertion since we ensure model_name is not None in __init__
        model_name: str = self.model_name  # type: ignore[assignment]

        total_tokens = reserved_tokens + sum(
            get_message_tokens(msg, model_name) for msg in system_msgs + regular_msgs
        )

        if total_tokens <= self.max_total_tokens * 0.9:
            return messages

        compressed = []
        chunk_size = 10
        for i in range(0, len(old_msgs), chunk_size):
            chunk = old_msgs[i : i + chunk_size]
            summary = _summarize_messages(
                chunk, model_name, self.timeout, on_usage=self.on_usage
            )
            if summary:
                compressed.append(summary)

        return system_msgs + compressed + recent_msgs
