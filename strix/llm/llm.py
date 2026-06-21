import asyncio
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import litellm
from jinja2 import Environment, FileSystemLoader, select_autoescape
from litellm import acompletion, completion_cost, stream_chunk_builder, supports_reasoning
from litellm.utils import supports_prompt_caching, supports_vision

from strix.config import Config
from strix.llm.config import LLMConfig
from strix.llm.memory_compressor import MemoryCompressor, get_message_tokens
from strix.llm.utils import (
    _truncate_to_first_function,
    fix_incomplete_tool_call,
    normalize_tool_format,
    parse_tool_invocations,
)
from strix.skills import load_skills
from strix.tools import get_tools_prompt
from strix.utils.resource_paths import get_strix_resource_path


litellm.drop_params = True
litellm.modify_params = True

_THINKING_BLOCK_RE = re.compile(r"<think(?:ing)?[^>]*>.*?</think(?:ing)?>", re.DOTALL)
_THINKING_BLOCK_OR_OPEN_RE = re.compile(
    r"<think(?:ing)?[^>]*>.*?(?:</think(?:ing)?>|\Z)", re.DOTALL
)


def _find_end_tag_outside_thinking(content: str, end_tag: str) -> int:
    thinking_spans = [(m.start(), m.end()) for m in _THINKING_BLOCK_OR_OPEN_RE.finditer(content)]
    start = 0
    while (idx := content.find(end_tag, start)) != -1:
        if not any(s <= idx < e for s, e in thinking_spans):
            return idx
        start = idx + 1
    return -1


_TOOL_RESULT_PATTERN = re.compile(
    r"(<tool_result>\s*<tool_name>[^<]*</tool_name>\s*<result>)(.*?)(</result>\s*</tool_result>)",
    re.DOTALL,
)


class LLMRequestFailedError(Exception):
    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details


@dataclass
class LLMResponse:
    content: str
    tool_invocations: list[dict[str, Any]] | None = None
    thinking_blocks: list[dict[str, Any]] | None = None


@dataclass
class RequestStats:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cost: float = 0.0
    requests: int = 0

    def to_dict(self) -> dict[str, int | float]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "cost": round(self.cost, 4),
            "requests": self.requests,
        }


class LLM:
    # max_iterations threshold above which we use the 1-hour cache TTL instead
    # of the default 5-minute. We use max_iterations as a SCOPE proxy, not a
    # literal turn prediction: the 1h cache-write premium (1.25× input on the
    # write) only pays off on long, gappy scans where the cached preamble goes
    # untouched >5min between turns. Gap analysis (SEC-7045, 2026-06-21) showed
    # two clean cohorts:
    #   - PR / diff scans  (strix-pr-dispatch, dynamic cap, ceiling 40): median
    #     ~8 turns, span minutes, turns every ~38s — 5m cache never expires
    #     between touches, so 1h just burns the write premium. → want 5m.
    #   - Full-scope scans (weekly-merges / weekly-infra / targeted-rescan /
    #     advisory-merges / DAST — set NO STRIX_MAX_ITERATIONS, so CLI default
    #     100): median 68 turns, ~49min span, 66% have a >5min gap. → want 1h.
    # INVARIANT this threshold relies on (verified 2026-06-21): PR-dispatch is
    # the ONLY caller that sets max_iterations, capped ≤40 (app curve
    # clamp(10,40,…); infra clamp(8,30,…)); every full-scope caller leaves it
    # unset → 100. The gate is `max_iterations >= THRESHOLD`. At 40 the only PR
    # scans that still get 1h are the MAX-size app PRs that hit the 40 ceiling
    # exactly (7+ human-authored files) — a small, genuinely-large slice that
    # plausibly DOES run long enough to want 1h, so catching them is acceptable;
    # everything else (the bulk: ≤6-file app, all infra ≤30) drops to 5m. Full
    # scans (100) stay 1h. **If you raise the PR app ceiling past 40, or set an
    # explicit low cap on a full-scope scan, this proxy mis-sorts — re-key on
    # scope_mode then (see SEC-7045).**
    # (Was 20, set 2026-06-11 against the OLD higher PR caps; stranded when the
    # cap-curve was lowered to 40/30, which left ~all scans ≥20 → always-1h.)
    _CACHE_TTL_1H_THRESHOLD = 40

    def __init__(self, config: LLMConfig, agent_name: str | None = None,
                 max_iterations: int | None = None):
        self.config = config
        self.agent_name = agent_name
        self.agent_id: str | None = None
        self.max_iterations = max_iterations
        self._active_skills: list[str] = list(config.skills or [])
        self._system_prompt_context: dict[str, Any] = dict(
            getattr(config, "system_prompt_context", {}) or {}
        )
        self._total_stats = RequestStats()
        self.memory_compressor = MemoryCompressor(
            model_name=None
            if Config.get("strix_llm_compressor")
            else config.litellm_model,
            on_usage=self._update_compressor_stats,
        )
        self.system_prompt = self._load_system_prompt(agent_name)

        reasoning = Config.get("strix_reasoning_effort")
        if reasoning:
            self._reasoning_effort = reasoning
        elif config.reasoning_effort:
            self._reasoning_effort = config.reasoning_effort
        elif config.scan_mode == "quick":
            self._reasoning_effort = "medium"
        else:
            self._reasoning_effort = "high"

    def _load_system_prompt(self, agent_name: str | None) -> str:
        if not agent_name:
            return ""

        try:
            prompt_dir = get_strix_resource_path("agents", agent_name)
            skills_dir = get_strix_resource_path("skills")
            env = Environment(
                loader=FileSystemLoader([prompt_dir, skills_dir]),
                autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
            )

            skills_to_load = self._get_skills_to_load()
            skill_content = load_skills(skills_to_load)
            env.globals["get_skill"] = lambda name: skill_content.get(name, "")

            # SEC-6848: when scanning local source only, skip tools that
            # presume a running HTTP target (browser/proxy/web_search). Saves
            # ~28k chars (~7k tokens) of system prompt per turn — the bulk of
            # which is the proxy + browser + reporting XML schemas. The cache-
            # creation pass + every uncached-input increment benefits.
            exclude_dynamic_target = bool(self.config.is_whitebox)
            tools_prompt_renderer = (
                (lambda: get_tools_prompt(exclude_dynamic_target=True))
                if exclude_dynamic_target
                else get_tools_prompt
            )

            result = env.get_template("system_prompt.jinja").render(
                get_tools_prompt=tools_prompt_renderer,
                loaded_skill_names=list(skill_content.keys()),
                interactive=self.config.interactive,
                tool_mode=self.config.tool_mode,
                system_prompt_context=self._system_prompt_context,
                **skill_content,
            )
            return str(result)
        except Exception:  # noqa: BLE001
            return ""

    def _get_skills_to_load(self) -> list[str]:
        ordered_skills = [*self._active_skills]
        ordered_skills.append(f"scan_modes/{self.config.scan_mode}")
        if self.config.is_whitebox:
            ordered_skills.append("coordination/source_aware_whitebox")
            ordered_skills.append("custom/source_aware_sast")

        deduped: list[str] = []
        seen: set[str] = set()
        for skill_name in ordered_skills:
            if skill_name not in seen:
                deduped.append(skill_name)
                seen.add(skill_name)

        return deduped

    def add_skills(self, skill_names: list[str]) -> list[str]:
        added: list[str] = []
        for skill_name in skill_names:
            if not skill_name or skill_name in self._active_skills:
                continue
            self._active_skills.append(skill_name)
            added.append(skill_name)

        if not added:
            return []

        updated_prompt = self._load_system_prompt(self.agent_name)
        if updated_prompt:
            self.system_prompt = updated_prompt

        return added

    def set_agent_identity(self, agent_name: str | None, agent_id: str | None) -> None:
        if agent_name:
            self.agent_name = agent_name
        if agent_id:
            self.agent_id = agent_id

    def set_system_prompt_context(self, context: dict[str, Any] | None) -> None:
        self._system_prompt_context = dict(context or {})
        updated_prompt = self._load_system_prompt(self.agent_name)
        if updated_prompt:
            self.system_prompt = updated_prompt

    async def generate(
        self, conversation_history: list[dict[str, Any]]
    ) -> AsyncIterator[LLMResponse]:
        messages = self._prepare_messages(conversation_history)
        # Default 12 retries (was 8). SEC-6994: Opus 4.8 throws SUSTAINED
        # Bedrock internalServerException windows that outlast the old
        # budget — observed 2026-06-13 on docker-actions-runner#62 (7 reqs)
        # and zh-global-infrastructure (16 reqs), both dying at iteration 0
        # with the 5xx-retry fix present. The retry ENGAGED (not the old
        # shadow bug) but the transient won. Raising count + the backoff
        # floor below widens the window the retries span. Configurable via
        # STRIX_LLM_MAX_RETRIES.
        max_retries = int(Config.get("strix_llm_max_retries") or "12")
        # Minimum per-retry backoff (seconds). The pure exp curve (2,4,8,16…)
        # fires the first ~6 attempts within ~14s — useless against a
        # multi-MINUTE outage, which is the actual 4.8 failure shape. A floor
        # spaces early retries across real time so the budget spans minutes,
        # not seconds. Default 15s; STRIX_LLM_RETRY_FLOOR_S to tune. Adds
        # ~15s latency to a fast-clearing transient — negligible against a
        # scan that runs minutes-to-hours, worth it to ride out sustained
        # windows. With 12 retries + 15s floor: ~14.5min cumulative wait.
        retry_floor_s = int(Config.get("strix_llm_retry_floor_s") or "15")

        bad_request_retried = False
        transient_thinking_retries = 0
        max_transient_thinking_retries = 6

        for attempt in range(max_retries + 1):
            try:
                async for response in self._stream(messages):
                    yield response
                return  # noqa: TRY300
            except Exception as e:  # noqa: BLE001
                # Transient thinking-block 400s (Bedrock-specific) — retry in an
                # inner loop with exponential backoff. Does not consume the outer
                # max_retries budget. If the inner budget is exhausted or `e`
                # changes to a non-transient error, fall through.
                while (
                    self._is_transient_thinking_error(e)
                    and transient_thinking_retries < max_transient_thinking_retries
                ):
                    transient_thinking_retries += 1
                    await asyncio.sleep(min(240, 5 * (2 ** (transient_thinking_retries - 1))))
                    try:
                        async for response in self._stream(messages):
                            yield response
                        return  # noqa: TRY300
                    except Exception as e2:  # noqa: BLE001
                        e = e2

                # Generic bad-request handling: retry once bare, then try
                # truncating oversized tool_result blocks if the feature flag
                # is set.
                if self._is_bad_request(e):
                    if not bad_request_retried:
                        bad_request_retried = True
                        if attempt >= max_retries:
                            self._raise_error(e)
                        await asyncio.sleep(2)
                        continue
                    truncate_enabled = Config.get("strix_truncate_on_oversize") or ""
                    if (
                        truncate_enabled.lower() in ("1", "true", "yes")
                        and self._truncate_large_tool_results(messages)
                    ):
                        if attempt >= max_retries:
                            self._raise_error(e)
                        # Pace the provider — matches the 2s sleep on the bare-retry
                        # path so a throttled provider isn't hit back-to-back after the
                        # original 400.
                        await asyncio.sleep(2)
                        continue
                if attempt >= max_retries or not self._should_retry(e):
                    self._raise_error(e)
                await asyncio.sleep(self._retry_backoff(attempt, retry_floor_s))

    async def _stream(self, messages: list[dict[str, Any]]) -> AsyncIterator[LLMResponse]:
        accumulated = ""
        chunks: list[Any] = []
        done_streaming = 0

        self._total_stats.requests += 1
        timeout = self.config.timeout
        response = await asyncio.wait_for(
            acompletion(**self._build_completion_args(messages), stream=True),
            timeout=timeout,
        )

        async_iter = response.__aiter__()
        while True:
            try:
                chunk = await asyncio.wait_for(async_iter.__anext__(), timeout=timeout)
            except StopAsyncIteration:
                break
            chunks.append(chunk)
            if done_streaming:
                done_streaming += 1
                if getattr(chunk, "usage", None) or done_streaming > 5:
                    break
                continue
            delta = self._get_chunk_content(chunk)
            if delta:
                accumulated += delta
                # In both modes, stop streaming as soon as the first tool call closes.
                # Parallel mode achieves concurrency via batch_* tools (which take a
                # list parameter), NOT via multiple <function> blocks in one message.
                # Sandbox tool-server semantics serialise concurrent same-agent calls
                # anyway (per-agent task cancellation), so multi-block emission was
                # at best no-op and at worst encouraged tool floods.
                check_content = _THINKING_BLOCK_OR_OPEN_RE.sub("", accumulated)
                if "</function>" in check_content or "</invoke>" in check_content:
                    end_tag = (
                        "</function>" if "</function>" in check_content else "</invoke>"
                    )
                    pos = _find_end_tag_outside_thinking(accumulated, end_tag)
                    accumulated = accumulated[: pos + len(end_tag)]
                    yield LLMResponse(content=accumulated)
                    done_streaming = 1
                    continue
                yield LLMResponse(content=accumulated)

        if chunks:
            self._update_usage_stats(stream_chunk_builder(chunks))

        accumulated = _THINKING_BLOCK_RE.sub("", accumulated)
        accumulated = normalize_tool_format(accumulated)
        accumulated = fix_incomplete_tool_call(_truncate_to_first_function(accumulated))

        yield LLMResponse(
            content=accumulated,
            tool_invocations=parse_tool_invocations(accumulated),
            thinking_blocks=self._extract_thinking(chunks),
        )

    def _prepare_messages(self, conversation_history: list[dict[str, Any]]) -> list[dict[str, Any]]:
        messages = [{"role": "system", "content": self.system_prompt}]

        if self.agent_name:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"\n\n<agent_identity>\n"
                        f"<meta>Internal metadata: do not echo or reference.</meta>\n"
                        f"<agent_name>{self.agent_name}</agent_name>\n"
                        f"<agent_id>{self.agent_id}</agent_id>\n"
                        f"</agent_identity>\n\n"
                    ),
                }
            )

        reserved_tokens = sum(
            get_message_tokens(msg, self.config.litellm_model) for msg in messages
        )
        compressed = list(
            self.memory_compressor.compress_history(conversation_history, reserved_tokens)
        )
        conversation_history.clear()
        conversation_history.extend(compressed)
        messages.extend(compressed)

        if messages[-1].get("role") == "assistant" and not self.config.interactive:
            messages.append({"role": "user", "content": "<meta>Continue the task.</meta>"})

        if self._is_anthropic() and self.config.enable_prompt_caching:
            messages = self._add_cache_control(messages)

        return messages

    def _build_completion_args(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        if not self._supports_vision():
            messages = self._strip_images(messages)

        args: dict[str, Any] = {
            "model": self.config.litellm_model,
            "messages": messages,
            "timeout": self.config.timeout,
            "stream_options": {"include_usage": True},
        }

        if self.config.api_key:
            args["api_key"] = self.config.api_key
        if self.config.api_base:
            args["api_base"] = self.config.api_base
        if self._supports_reasoning():
            # Opus 4.7+ dropped `thinking.type.enabled` in favour of adaptive
            # thinking controlled by `output_config.effort`. LiteLLM 1.81.x
            # only remaps `reasoning_effort` -> `output_config.effort` for
            # `opus-4-5`, so for 4.7+ we pass `output_config` directly to
            # bypass the faulty gate and stop LiteLLM from injecting the
            # deprecated `thinking` block.
            if self._uses_adaptive_thinking():
                args["output_config"] = {"effort": self._reasoning_effort}
                args["thinking"] = {"type": "adaptive"}
            else:
                args["reasoning_effort"] = self._reasoning_effort

        return args

    def _uses_adaptive_thinking(self) -> bool:
        """Claude Opus 4.7+ requires `thinking.type=adaptive` + `output_config.effort`.

        Earlier Opus/Sonnet models still accept the legacy `thinking.type=enabled`
        schema that LiteLLM's default translation of `reasoning_effort` produces.
        """
        model = (self.config.litellm_model or "").lower()
        # Match both the litellm bedrock id (bedrock/us.anthropic.claude-opus-4-7)
        # and anthropic-direct ids (anthropic/claude-opus-4-7-...).
        return "opus-4-7" in model or "opus_4_7" in model

    def _get_chunk_content(self, chunk: Any) -> str:
        if chunk.choices and hasattr(chunk.choices[0], "delta"):
            return getattr(chunk.choices[0].delta, "content", "") or ""
        return ""

    def _extract_thinking(self, chunks: list[Any]) -> list[dict[str, Any]] | None:
        if not chunks or not self._supports_reasoning():
            return None
        try:
            resp = stream_chunk_builder(chunks)
            if resp.choices and hasattr(resp.choices[0].message, "thinking_blocks"):
                blocks: list[dict[str, Any]] = resp.choices[0].message.thinking_blocks
                return blocks
        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass
        return None

    def _update_usage_stats(self, response: Any) -> None:
        try:
            if hasattr(response, "usage") and response.usage:
                input_tokens = getattr(response.usage, "prompt_tokens", 0) or 0
                output_tokens = getattr(response.usage, "completion_tokens", 0) or 0

                cached_tokens = 0
                if hasattr(response.usage, "prompt_tokens_details"):
                    prompt_details = response.usage.prompt_tokens_details
                    if hasattr(prompt_details, "cached_tokens"):
                        cached_tokens = prompt_details.cached_tokens or 0

                cost = self._extract_cost(response)
            else:
                input_tokens = 0
                output_tokens = 0
                cached_tokens = 0
                cost = 0.0

            self._total_stats.input_tokens += input_tokens
            self._total_stats.output_tokens += output_tokens
            self._total_stats.cached_tokens += cached_tokens
            self._total_stats.cost += cost

        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass

    def _extract_cost(self, response: Any, model: str | None = None) -> float:
        if hasattr(response, "usage") and response.usage:
            direct_cost = getattr(response.usage, "cost", None)
            if direct_cost is not None:
                return float(direct_cost)
        try:
            if hasattr(response, "_hidden_params"):
                response._hidden_params.pop("custom_llm_provider", None)
            return completion_cost(
                response, model=model or self.config.canonical_model
            ) or 0.0
        except Exception:  # noqa: BLE001
            return 0.0

    @staticmethod
    def _retry_backoff(attempt: int, floor_s: int = 15, cap_s: int = 120) -> int:
        """Per-retry backoff (seconds): exponential, floored, capped.

        SEC-6994: the pure exp curve (2,4,8,16,32,64…) fires the first ~6
        attempts within ~14s, which is useless against the sustained
        multi-MINUTE Bedrock internalServerException windows Opus 4.8
        throws. The floor spaces early retries across real time so the
        budget actually spans minutes. With floor=15, cap=120 over 12
        retries: 15,15,15,16,32,64,120,120,120,120,120,120 ≈ 14.6min.
        """
        return min(cap_s, max(floor_s, 2 * (2 ** attempt)))

    @staticmethod
    def _truncate_large_tool_results(
        messages: list[dict[str, Any]],
        threshold_chars: int = 2000,
        truncate_to_chars: int = 1000,
    ) -> bool:
        """Truncate large tool_result XML blocks to recover from BadRequestError.

        Scans all messages for tool_result blocks whose body exceeds threshold_chars
        and shrinks them to truncate_to_chars. Called repeatedly on each 400 until it
        returns False (nothing left to truncate).

        threshold_chars and truncate_to_chars are independent: the threshold decides
        which blocks qualify for truncation, and truncate_to_chars is the size of the
        retained prefix. They are not the same value to allow aggressive shrinking of
        blocks that are well over the threshold without re-processing blocks that are
        already acceptable.
        """
        truncated_any = False

        def _truncate_match(m: re.Match) -> str:
            nonlocal truncated_any
            prefix, body, suffix = m.group(1), m.group(2), m.group(3)
            if len(body) <= threshold_chars:
                return m.group(0)
            truncated_any = True
            kept = body[:truncate_to_chars]
            return (
                f"{prefix}{kept}\n\n... [content truncated from {len(body)} to {len(kept)} chars "
                f"due to request size limit — file requires manual review] ...{suffix}"
            )

        for msg in reversed(messages):
            content = msg.get("content")

            if isinstance(content, list):
                for block in content:
                    if (
                        block.get("type") == "text"
                        and isinstance(block.get("text"), str)
                        and "<tool_result>" in block["text"]
                    ):
                        block["text"] = _TOOL_RESULT_PATTERN.sub(_truncate_match, block["text"])
            elif isinstance(content, str) and "<tool_result>" in content:
                msg["content"] = _TOOL_RESULT_PATTERN.sub(_truncate_match, content)

        return truncated_any

    def _is_bad_request(self, e: Exception) -> bool:
        # SEC-6994 follow-up: a Bedrock 5xx-class server error
        # (internalServerException etc.) is mis-mapped by LiteLLM to
        # BadRequestError(400). Those must NOT be treated as bad requests —
        # otherwise the retry loop routes them through the one-shot
        # bad-request handler (bad_request_retried) and they only ever get a
        # single bare retry, never reaching _should_retry's marker check that
        # grants the full max_retries budget. Exclude them here so they fall
        # through to the _should_retry path. (The original SEC-6994 patch
        # added the markers to _should_retry but that branch was shadowed by
        # this 400 check, which runs first in the loop — observed
        # daily-settlement weekly run 27454948115 + jurisdiction-command#152:
        # 2 internalServerException occurrences then death, not 8 retries.)
        msg = str(e)
        if any(marker in msg for marker in self._BEDROCK_TRANSIENT_BODY_MARKERS):
            return False
        code = getattr(e, "status_code", None) or getattr(
            getattr(e, "response", None), "status_code", None
        )
        return code == 400

    @staticmethod
    def _is_transient_thinking_error(e: Exception) -> bool:
        """Detect Bedrock's transient 'thinking blocks cannot be modified' 400.

        Observed on claude-sonnet-4-6 with adaptive thinking: Bedrock occasionally
        rejects a well-formed payload with this error, and the identical payload
        succeeds on replay. Treat it as transient rather than a structural issue.
        """
        code = getattr(e, "status_code", None) or getattr(
            getattr(e, "response", None), "status_code", None
        )
        if code != 400:
            return False
        message = str(e).lower()
        return "thinking" in message and "cannot be modified" in message

    def _update_compressor_stats(self, response: Any, model: str) -> None:
        """Usage callback for MemoryCompressor.

        Compressor calls hit a different model than the orchestrator (when
        STRIX_LLM_COMPRESSOR is set), so cost must be priced against that
        model. Token counts accumulate into the same _total_stats so they
        appear in the run summary.
        """
        try:
            if hasattr(response, "usage") and response.usage:
                input_tokens = getattr(response.usage, "prompt_tokens", 0) or 0
                output_tokens = getattr(response.usage, "completion_tokens", 0) or 0

                cached_tokens = 0
                if hasattr(response.usage, "prompt_tokens_details"):
                    prompt_details = response.usage.prompt_tokens_details
                    if hasattr(prompt_details, "cached_tokens"):
                        cached_tokens = prompt_details.cached_tokens or 0

                cost = self._extract_cost(response, model=model)
            else:
                input_tokens = 0
                output_tokens = 0
                cached_tokens = 0
                cost = 0.0

            self._total_stats.input_tokens += input_tokens
            self._total_stats.output_tokens += output_tokens
            self._total_stats.cached_tokens += cached_tokens
            self._total_stats.cost += cost
        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass

    # SEC-6994: Bedrock 5xx-class error markers that LiteLLM sometimes
    # mis-maps to BadRequestError(400). Observed 2026-06-12 on opus-4-8
    # rollout: a transient `BedrockException - internalServerException`
    # ("The system encountered an unexpected error during processing.
    # Try your request again.") came through as litellm.BadRequestError,
    # so the status-code-driven _should_retry returned False on a 400
    # and the agent died on first turn instead of retrying. The Bedrock
    # message is a 5xx-class server error; retrying is the correct
    # behavior. Match by string body since the LiteLLM exception class
    # mapping is not reliable for these cases.
    _BEDROCK_TRANSIENT_BODY_MARKERS = (
        "internalServerException",
        "ServiceUnavailableException",
        "ThrottlingException",
        "ModelTimeoutException",
        "ModelStreamErrorException",
    )

    def _should_retry(self, e: Exception) -> bool:
        # Bedrock body-string fallback first: catches the LiteLLM mis-mapping
        # case where a 5xx-class server error is wrapped as BadRequestError.
        msg = str(e)
        if any(marker in msg for marker in self._BEDROCK_TRANSIENT_BODY_MARKERS):
            return True
        code = getattr(e, "status_code", None) or getattr(
            getattr(e, "response", None), "status_code", None
        )
        return code is None or litellm._should_retry(code)

    def _raise_error(self, e: Exception) -> None:
        from strix.telemetry import posthog

        posthog.error("llm_error", type(e).__name__)
        raise LLMRequestFailedError(f"LLM request failed: {type(e).__name__}", str(e)) from e

    def _is_anthropic(self) -> bool:
        if not self.config.model_name:
            return False
        return any(p in self.config.model_name.lower() for p in ["anthropic/", "claude"])

    def _supports_vision(self) -> bool:
        try:
            return bool(supports_vision(model=self.config.canonical_model))
        except Exception:  # noqa: BLE001
            return False

    def _supports_reasoning(self) -> bool:
        try:
            return bool(supports_reasoning(model=self.config.canonical_model))
        except Exception:  # noqa: BLE001
            return False

    def _strip_images(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, list):
                text_parts = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text_parts.append(item.get("text", ""))
                    elif isinstance(item, dict) and item.get("type") == "image_url":
                        text_parts.append("[Image removed - model doesn't support vision]")
                result.append({**msg, "content": "\n".join(text_parts)})
            else:
                result.append(msg)
        return result

    def _cache_control(self) -> dict[str, str]:
        """Return the cache_control object to apply to stable prompt
        segments. Defaults to 5-minute ephemeral cache. For long-budget
        scans (max_iterations >= _CACHE_TTL_1H_THRESHOLD) we extend to
        the 1-hour TTL so iterations spaced > 5min apart still hit cache
        instead of paying full input-rate to reload the prelude.

        Override unconditionally with STRIX_CACHE_TTL=1h or 5m.
        """
        override = Config.get("strix_cache_ttl")
        if override in ("1h", "5m"):
            ttl = override
        elif self.max_iterations and self.max_iterations >= self._CACHE_TTL_1H_THRESHOLD:
            ttl = "1h"
        else:
            ttl = "5m"

        out: dict[str, str] = {"type": "ephemeral"}
        if ttl != "5m":
            # Bedrock and Anthropic accept "ttl": "1h"; "5m" is the
            # default and emitting it explicitly is a noop. Keep the
            # default form short to minimise diff from upstream.
            out["ttl"] = ttl
        return out

    def _add_cache_control(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Add cache_control breakpoints to stable message segments.

        Caches the system prompt and the agent identity message since these
        are identical across every iteration within an agent's lifetime.
        Cache hits cost ~90% less than re-processing on Anthropic models.
        """
        if not messages or not supports_prompt_caching(self.config.canonical_model):
            return messages

        cache_control = self._cache_control()
        result = list(messages)

        # Cache breakpoint 1: system prompt (unchanged across all iterations)
        if result[0].get("role") == "system":
            content = result[0]["content"]
            result[0] = {
                **result[0],
                "content": [
                    {"type": "text", "text": content, "cache_control": cache_control}
                ]
                if isinstance(content, str)
                else content,
            }

        # Cache breakpoint 2: agent identity message (stable per-agent).
        # Reuse the resolved cache_control so the configured TTL (e.g. 1h
        # for long scans) flows through to this breakpoint as well — earlier
        # versions hardcoded {"type": "ephemeral"} here and silently fell
        # back to the 5-minute default, partially defeating the 1h-TTL
        # extension applied to the system prompt above.
        if len(result) > 1 and "<agent_identity>" in str(result[1].get("content", "")):
            content = result[1]["content"]
            if isinstance(content, str):
                result[1] = {
                    **result[1],
                    "content": [
                        {"type": "text", "text": content, "cache_control": cache_control}
                    ],
                }
            elif isinstance(content, list) and content:
                # Content is already a list — add cache_control to the last item
                last = content[-1]
                if isinstance(last, dict):
                    last["cache_control"] = cache_control

        return result
