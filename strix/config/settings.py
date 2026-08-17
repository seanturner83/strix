"""Strix application settings — pydantic-settings powered."""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, Field, field_validator
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
    # NOTE: no compressor/reporting role. The fork briefly had STRIX_LLM_COMPRESSOR
    # + STRIX_LLM_REPORTING (175ec25) but dropped them (6b45fc3) as inert on v1:
    # v1 uses a plain SQLiteSession (no compaction), and reporting is written
    # inline by the orchestrator (finish_scan is an orchestrator tool, not a
    # separate agent). Omitted rather than defined-but-inert.
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
    force_required_tool_choice: bool = Field(
        default=False,
        alias="STRIX_FORCE_REQUIRED_TOOL_CHOICE",
    )
    prompt_cache: bool = Field(
        default=True,
        alias="STRIX_PROMPT_CACHE",
    )
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


class DedupeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="STRIX_DEDUPE_MODEL")
    reasoning_effort: ReasoningEffort | None = Field(
        default=None,
        alias="STRIX_DEDUPE_REASONING_EFFORT",
    )
    api_key: str | None = Field(default=None, alias="DEDUPE_LLM_API_KEY")
    api_base: str | None = Field(default=None, alias="DEDUPE_LLM_API_BASE")


class VerifySettings(BaseSettings):
    """In-scan verify-before-emit pass (report/verify.py).

    A per-finding adjudication that fires right before a report is persisted (a
    sibling of the dedup-reject): re-derive the source->sink chain from the
    reported code + PoC and decide REAL vs FALSE_POSITIVE. Cuts the confident-but-
    wrong FP class that the report-tool's prompt-level "only file verified findings"
    guard can't (measured on the VLB corpus: verification moves the ROC curve;
    wording only slides the operating point). OFF by default — opt-in, since it
    adds one bounded LLM call per candidate finding.

    Safety: only a FALSE_POSITIVE verdict with confidence >= min_confidence rejects
    the report; REAL / uncertain / any error emits the finding (fail-open — a
    verifier miss must never suppress a real finding). min_severity avoids spending
    the call on low-severity noise; the strong classes (high/critical) are where a
    wrong emit costs the most and where verification pays off.
    """

    model_config = _BASE_CONFIG

    enabled: bool = Field(default=False, alias="STRIX_VERIFY")
    # Own cheap-model role — verification is a bounded re-derivation, not a deep
    # pentest. Falls back to STRIX_LLM_DEDUP then the base model (dedupe and verify
    # are the same "cheap bounded classifier" tier).
    model: str | None = Field(default=None, alias="STRIX_VERIFY_MODEL")
    reasoning_effort: ReasoningEffort | None = Field(
        default=None, alias="STRIX_VERIFY_REASONING_EFFORT"
    )
    # Only verify findings at or above this severity (crit>high>medium>low>info).
    # Default high: the confident-but-wrong FP tail that hurts is concentrated in
    # the high/crit grades a scanner over-claims.
    min_severity: str = Field(default="high", alias="STRIX_VERIFY_MIN_SEVERITY")
    # A FALSE_POSITIVE below this confidence does NOT reject (asymmetric: hold on
    # doubt — never suppress a possible-real finding).
    min_confidence: float = Field(default=0.7, ge=0.0, le=1.0, alias="STRIX_VERIFY_MIN_CONFIDENCE")
    api_key: str | None = Field(default=None, alias="VERIFY_LLM_API_KEY")
    api_base: str | None = Field(default=None, alias="VERIFY_LLM_API_BASE")


class DepVerifySettings(BaseSettings):
    """Deterministic dependency version-range verify (report/dep_verify.py).

    A dependency-CVE false positive is a FACTUAL question — is the installed
    version actually in the advisory's affected range? — not the code-reachability
    reasoning the LLM verify pass does. So it's a separate, deterministic check
    (no LLM) with its OWN toggle: a user may want the cheap version-range check
    without the LLM verifier, or vice versa.

    PROVIDER-PLUGGABLE (Strix is global FOSS — not everyone can/will call a
    hosted advisory API: air-gapped scans, data-residency rules, orgs with their
    own advisory DB). `provider` selects the source:
      "osv"  -> query an OSV-schema API (default https://api.osv.dev, override
                `osv_url` for a self-hosted OSV mirror — same /v1/query contract).
      "none" -> disabled (also the effect of enabled=False).
    OFF by default; fail-open (any uncertainty emits the finding).
    """

    model_config = _BASE_CONFIG

    enabled: bool = Field(default=False, alias="STRIX_DEP_VERIFY")
    provider: str = Field(default="osv", alias="STRIX_DEP_VERIFY_PROVIDER")
    # OSV-schema endpoint. Point at a self-hosted OSV mirror for air-gapped /
    # data-residency deployments (the /v1/query request+response contract is
    # identical, so no code changes — just the URL).
    osv_url: str = Field(default="https://api.osv.dev/v1/query", alias="STRIX_OSV_URL")


class ContextSettings(BaseSettings):
    """Context-window management: per-tool-output caps and history compaction."""

    model_config = _BASE_CONFIG

    auto_compact: bool = Field(default=True, alias="STRIX_CONTEXT_AUTO_COMPACT")
    compact_buffer_tokens: int = Field(default=20_000, gt=0, alias="STRIX_CONTEXT_BUFFER_TOKENS")
    keep_tokens: int = Field(default=8_000, gt=0, alias="STRIX_CONTEXT_KEEP_TOKENS")
    fallback_context_tokens: int = Field(
        default=200_000, gt=0, alias="STRIX_CONTEXT_FALLBACK_TOKENS"
    )
    summary_max_tokens: int = Field(default=4_096, gt=0, alias="STRIX_CONTEXT_SUMMARY_TOKENS")
    tool_output_max_tokens: int = Field(default=8_000, gt=0, alias="STRIX_TOOL_OUTPUT_MAX_TOKENS")
    tool_output_max_lines: int = Field(default=2_000, gt=0, alias="STRIX_TOOL_OUTPUT_MAX_LINES")
    # Floor above the truncation-notice size so a preview always fits.
    tool_output_max_bytes: int = Field(
        default=50 * 1024, ge=1024, alias="STRIX_TOOL_OUTPUT_MAX_BYTES"
    )


class RuntimeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    image: str = Field(
        default="ghcr.io/usestrix/strix-sandbox:1.1.0",
        alias="STRIX_IMAGE",
    )
    backend: str = Field(default="docker", alias="STRIX_RUNTIME_BACKEND")
    # Hard cap on a local target's size before we refuse to stream it into the
    # sandbox file-by-file (the SDK copies every file individually, which stalls
    # on large repos). Above this, the user must bind-mount via ``--mount``.
    # Set to 0 (or less) to disable the pre-flight check entirely.
    max_local_copy_mb: int = Field(default=1024, alias="STRIX_MAX_LOCAL_COPY_MB")
    # Max screenshot/image tool outputs kept live per agent context (0 = none).
    max_context_images: int = Field(default=3, ge=0, alias="STRIX_MAX_CONTEXT_IMAGES")
    # Per-agent turn-cap override, sourced from the pre-v1.x env var name for
    # back-compat with fleet callers that never migrated. Before the v1.x
    # SDK-harness rewrite, STRIX_MAX_ITERATIONS directly set the agent turn
    # cap; v1.x replaced that with the --max-turns CLI flag (argparse default
    # DEFAULT_MAX_TURNS=500 in strix.core.inputs) and dropped the env-var path
    # entirely. Callers that only ever set the env var — e.g. seedcx/strix-
    # scan-workflow's dynamic per-diff-shape cap, computed in strix-pr-
    # dispatch.yml's resolve_turn_cap step and exported as STRIX_MAX_ITERATIONS
    # — were silently disconnected: the env var was set but nothing read it,
    # so every scan ran at the hardcoded 500-turn ceiling instead of the
    # intended per-PR cap. None = no override; strix.core.inputs.
    # resolve_default_max_turns() falls back to DEFAULT_MAX_TURNS. An explicit
    # --max-turns CLI arg still wins over this (argparse only consults this
    # value as its *default*, used when the flag is omitted).
    max_turns: int | None = Field(default=None, gt=0, alias="STRIX_MAX_ITERATIONS")

    @field_validator("max_turns", mode="before")
    @classmethod
    def _blank_env_means_unset(cls, value: object) -> object:
        # strix-scan-workflow's composite action declares its max_iterations
        # input with default: "" and unconditionally exports it as
        # STRIX_MAX_ITERATIONS regardless of whether the caller passed a real
        # value — so most callers set this env var to a present-but-blank
        # string, not an absent one. Without this, pydantic's int coercion
        # raises on "" and crashes parse_arguments() on every invocation,
        # including --help (SEC-7400 follow-up, weekly-scan outage).
        if isinstance(value, str) and value.strip() == "":
            return None
        return value


class TelemetrySettings(BaseSettings):
    model_config = _BASE_CONFIG

    enabled: bool = Field(default=True, alias="STRIX_TELEMETRY")


class IntegrationSettings(BaseSettings):
    model_config = _BASE_CONFIG

    perplexity_api_key: str | None = Field(default=None, alias="PERPLEXITY_API_KEY")


class ViewerSettings(BaseSettings):
    model_config = _BASE_CONFIG

    # Base URL of the Strix relay the local viewer proxies to for email
    # verification and encrypted report delivery. The browser never talks to
    # the relay directly; the local server is the only caller.
    app_url: str = Field(default="https://app.strix.ai", alias="STRIX_APP_URL")


class Settings(BaseSettings):
    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    dedupe: DedupeSettings = Field(default_factory=DedupeSettings)
    verify: VerifySettings = Field(default_factory=VerifySettings)
    dep_verify: DepVerifySettings = Field(default_factory=DepVerifySettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    context: ContextSettings = Field(default_factory=ContextSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
    viewer: ViewerSettings = Field(default_factory=ViewerSettings)
