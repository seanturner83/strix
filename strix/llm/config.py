from typing import Any

from strix.config import Config
from strix.config.config import resolve_llm_config
from strix.llm.utils import resolve_strix_model


VALID_TOOL_MODES = ("serial", "parallel")


class LLMConfig:
    def __init__(
        self,
        model_name: str | None = None,
        enable_prompt_caching: bool = True,
        skills: list[str] | None = None,
        timeout: int | None = None,
        scan_mode: str = "deep",
        is_whitebox: bool = False,
        interactive: bool = False,
        reasoning_effort: str | None = None,
        system_prompt_context: dict[str, Any] | None = None,
        role: str | None = None,
        tool_mode: str | None = None,
    ):
        self.role = role
        resolved_model, self.api_key, self.api_base = resolve_llm_config(role=role)
        self.model_name = model_name or resolved_model

        if not self.model_name:
            raise ValueError("STRIX_LLM environment variable must be set and not empty")

        api_model, canonical = resolve_strix_model(self.model_name)
        self.litellm_model: str = api_model or self.model_name
        self.canonical_model: str = canonical or self.model_name

        self.enable_prompt_caching = enable_prompt_caching
        self.skills = skills or []

        self.timeout = timeout or int(Config.get("llm_timeout") or "300")

        self.scan_mode = scan_mode if scan_mode in ["quick", "standard", "deep"] else "deep"
        self.is_whitebox = is_whitebox
        self.interactive = interactive
        self.reasoning_effort = reasoning_effort
        self.system_prompt_context = system_prompt_context or {}

        if tool_mode is None:
            tool_mode = Config.get("strix_tool_mode") or "serial"
        if tool_mode not in VALID_TOOL_MODES:
            raise ValueError(
                f"Invalid tool_mode: {tool_mode!r}. "
                f"Expected one of {VALID_TOOL_MODES}."
            )
        self.tool_mode = tool_mode
