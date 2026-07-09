"""Strix application settings — pydantic-settings powered."""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh"]

_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
)


class LlmSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="STRIX_LLM")
    # Per-role model overrides. Each falls back to `model` when unset, so the
    # default single-model behaviour is unchanged. Lets a deployment cost-tier
    # the fleet: a cheaper model for the many sub-agents / the memory compressor
    # while the orchestrator keeps the strong model. All must use the same
    # provider as `model` (LiteLLM routes them the same way).
    model_orchestrator: str | None = Field(default=None, alias="STRIX_LLM_ORCHESTRATOR")
    model_subagent: str | None = Field(default=None, alias="STRIX_LLM_SUBAGENT")
    # Dedup role: the finding-deduplication check (report/dedupe.py) is a bounded
    # JSON classification — "does this candidate duplicate an existing finding?"
    # — that fires on EVERY reported finding and needs no deep pentest reasoning.
    # A genuine cheap-model candidate (unlike reporting, which is <0.4% of scan
    # tokens, or a compressor, which has nothing to attach to). Falls back to the
    # base model when unset.
    model_dedup: str | None = Field(default=None, alias="STRIX_LLM_DEDUP")
    # Refusal fallback map: "primary=fallback,primary2=fallback2". When an agent
    # turn is blocked by the provider's content filter (Bedrock Converse
    # stopReason=content_filtered — Mythos-class models like Claude Fable 5 refuse
    # a materially higher share of offensive-security prompts), the run swaps the
    # blocked model for its mapped fallback and retries the SAME session (prior
    # context carries over), rather than burning the recovery budget re-prompting
    # a model that will keep refusing. No fallback mapped for the blocked model →
    # the agent fails cleanly. Ports the triager's STRIX_TRIAGE_L2_FALLBACK_MODELS
    # pattern. Empty/unset → today's behaviour (no fallback). NOTE: the Bedrock
    # `fallback-credit-2026-06-01` token-credit beta is NOT wired — the credit
    # token is only returned via the raw invoke_model API, and Strix runs through
    # Converse, which does not surface it (verified 2026-07-09).
    model_fallback: str | None = Field(default=None, alias="STRIX_LLM_FALLBACK")
    # NOTE: no compressor role. The fork had STRIX_LLM_COMPRESSOR for its own
    # memory-compressor module; v1 uses a plain SQLiteSession (no compaction),
    # and the SDK's compaction session is OpenAI-Responses-specific — inert on
    # the Bedrock/Claude path. An inert setting would be misleading, so it's
    # omitted until/unless a real compaction path is adopted.
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("LLM_API_KEY", "OPENAI_API_KEY"),
    )
    api_base: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LLM_API_BASE",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
        ),
    )
    reasoning_effort: ReasoningEffort = Field(default="high", alias="STRIX_REASONING_EFFORT")
    # Explicit output-token ceiling. Leave unset (None) to let make_model_settings
    # decide: Anthropic/Claude models get a sensible default (they need one on
    # Bedrock Converse — adaptive-thinking models otherwise send no maxTokens and
    # truncate long tool calls), every other provider keeps its own default so
    # local users on smaller-ceiling models (gpt/ollama/gemini) aren't forced past
    # their limit. Any value set here is clamped to the model's known ceiling.
    max_tokens: int | None = Field(default=None, alias="STRIX_MAX_TOKENS")
    timeout: int = Field(default=300, alias="LLM_TIMEOUT")

    def fallback_map(self) -> dict[str, str]:
        """Parse ``model_fallback`` into {primary_model: fallback_model}.

        Format: ``"primary1=fallback1,primary2=fallback2"``. Malformed / empty
        entries are skipped; unset returns an empty map (no fallback). Mirrors
        the triager's ``_build_fallback_map``.
        """
        spec = (self.model_fallback or "").strip()
        if not spec:
            return {}
        out: dict[str, str] = {}
        for raw_pair in spec.split(","):
            pair = raw_pair.strip()
            if not pair or "=" not in pair:
                continue
            primary, fallback = (p.strip() for p in pair.split("=", 1))
            if primary and fallback:
                out[primary] = fallback
        return out


class RuntimeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    image: str = Field(
        default="ghcr.io/usestrix/strix-sandbox:1.0.0",
        alias="STRIX_IMAGE",
    )
    backend: str = Field(default="docker", alias="STRIX_RUNTIME_BACKEND")


class TelemetrySettings(BaseSettings):
    model_config = _BASE_CONFIG

    enabled: bool = Field(default=True, alias="STRIX_TELEMETRY")


class IntegrationSettings(BaseSettings):
    model_config = _BASE_CONFIG

    perplexity_api_key: str | None = Field(default=None, alias="PERPLEXITY_API_KEY")


class Settings(BaseSettings):
    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
