"""Tests for pure input builders in strix.core.inputs."""

from __future__ import annotations

from itertools import pairwise
from typing import Any

import pytest

from strix.core.inputs import (
    _claude_cache_extra_args,
    build_root_task,
    child_initial_input,
    make_model_settings,
)


def _child_kwargs(parent_history: list[Any]) -> dict[str, Any]:
    return {
        "name": "scout",
        "child_id": "agent-2",
        "parent_id": "agent-1",
        "task": "Audit the login flow.",
        "parent_history": parent_history,
    }


def test_child_initial_input_single_message_without_history() -> None:
    result = child_initial_input(**_child_kwargs([]))

    assert len(result) == 1
    assert result[0]["role"] == "user"
    content = result[0]["content"]
    assert "agent scout (agent-2)" in content
    assert "Audit the login flow." in content
    assert "Inherited context" not in content


def test_child_initial_input_single_message_with_history() -> None:
    history = [{"role": "assistant", "content": "previous work"}]
    result = child_initial_input(**_child_kwargs(history))

    assert len(result) == 1
    assert result[0]["role"] == "user"
    content = result[0]["content"]
    assert "Inherited context from parent" in content
    assert "previous work" in content
    assert "agent scout (agent-2)" in content
    assert "Audit the login flow." in content


@pytest.mark.parametrize(
    "parent_history",
    [[], [{"role": "assistant", "content": "previous work"}]],
)
def test_child_initial_input_no_consecutive_same_role(parent_history: list[Any]) -> None:
    result = child_initial_input(**_child_kwargs(parent_history))

    roles = [msg["role"] for msg in result]
    assert all(prev != nxt for prev, nxt in pairwise(roles))


def test_build_root_task_empty_config() -> None:
    assert build_root_task({}) == ""


def test_build_root_task_repository_target() -> None:
    config = {
        "targets": [
            {
                "type": "repository",
                "details": {
                    "target_repo": "https://example.com/repo.git",
                    "cloned_repo_path": "/workspace/repo",
                    "workspace_subdir": "repo",
                },
            },
        ],
    }
    task = build_root_task(config)

    assert "Repositories:" in task
    assert "/workspace/repo" in task
    assert "https://example.com/repo.git" in task


def test_build_root_task_web_application_with_instructions() -> None:
    config = {
        "targets": [
            {"type": "web_application", "details": {"target_url": "https://app.example.com"}},
        ],
        "user_instructions": "Focus on auth.",
    }
    task = build_root_task(config)

    assert "URLs:" in task
    assert "https://app.example.com" in task
    assert "Special instructions: Focus on auth." in task


def test_build_root_task_diff_scope() -> None:
    config = {
        "targets": [],
        "diff_scope": {
            "active": True,
            "repos": [
                {
                    "workspace_subdir": "repo",
                    "analyzable_files_count": 3,
                    "deleted_files_count": 2,
                },
            ],
        },
    }
    task = build_root_task(config)

    assert "Scope Constraints:" in task
    assert "3 changed file(s)" in task
    assert "2 deleted file(s)" in task


@pytest.mark.parametrize("model_name", ["openai/o3", "gpt-4o"])
def test_make_model_settings_forces_required_tool_choice_for_openai_models(
    model_name: str,
) -> None:
    settings = make_model_settings(
        "none",
        model_name=model_name,
        force_required_tool_choice=True,
    )

    assert settings.tool_choice == "required"


def test_make_model_settings_skips_required_tool_choice_for_non_openai_models() -> None:
    settings = make_model_settings(
        "none",
        model_name="anthropic/claude-3-7-sonnet-latest",
        force_required_tool_choice=True,
    )

    assert settings.tool_choice is None


def test_make_model_settings_forces_required_for_routed_openai_model() -> None:
    settings = make_model_settings(
        None,
        model_name="litellm/openai/gpt-4o",
        force_required_tool_choice=True,
    )

    assert settings.tool_choice == "required"


def test_make_model_settings_forces_required_for_anyllm_routed_openai_model() -> None:
    settings = make_model_settings(
        None,
        model_name="any-llm/openai/gpt-4o",
        force_required_tool_choice=True,
    )

    assert settings.tool_choice == "required"


# --- prompt-cache breakpoints ------------------------------------------------


def _injection_points() -> list[dict[str, Any]]:
    return _claude_cache_extra_args()["cache_control_injection_points"]


def test_claude_cache_marks_three_breakpoints() -> None:
    points = _injection_points()

    # Anthropic allows 4 cache breakpoints; we use 3 and leave headroom.
    assert len(points) == 3
    assert {"location": "message", "role": "system"} in points
    assert {"location": "tool_config"} in points
    # The rolling conversation-tail breakpoint — the lever that caches the
    # growing (append-only) transcript rather than only the fixed prefix.
    assert {"location": "message", "index": -1} in points


def test_claude_cache_tail_breakpoint_is_last_message_not_a_role() -> None:
    # Guard against a regression to a role-keyed tail (e.g. role="user"), which
    # would cache the FIRST matching message, not the moving tail.
    tail = next(p for p in _injection_points() if p.get("index") is not None)
    assert tail["index"] == -1
    assert "role" not in tail


def test_make_model_settings_injects_cache_points_for_claude() -> None:
    settings = make_model_settings("none", model_name="bedrock/anthropic.claude-opus-4-8")

    assert settings.extra_args is not None
    assert settings.extra_args["cache_control_injection_points"] == _injection_points()


def test_make_model_settings_no_cache_points_for_non_claude() -> None:
    settings = make_model_settings("none", model_name="openai/gpt-4o")

    extra = settings.extra_args or {}
    assert "cache_control_injection_points" not in extra


def test_tail_breakpoint_hits_growing_transcript_via_litellm_hook() -> None:
    """The append-only invariant, end-to-end: litellm's own injection logic must
    place the tail cache_control on the LAST message for a short transcript AND
    for a longer one (i.e. it moves with the tail across turns), proving the
    earlier 'a tail breakpoint would never hit' claim wrong.

    We drive the hook's static ``_process_message_injection`` directly rather
    than the full ``get_chat_completion_prompt`` entrypoint: the latter's
    signature carries prompt-manager kwargs that drift across litellm versions,
    while the message-injection primitive (the code path our tail point
    exercises) is stable.
    """
    hook_mod = pytest.importorskip("litellm.integrations.anthropic_cache_control_hook")
    apply = hook_mod.AnthropicCacheControlHook._apply_message_injections
    # Only message-location points go through this primitive (tool_config is
    # applied by the provider transform, not the message injector).
    msg_points = [p for p in _injection_points() if p.get("location") == "message"]

    def last_msg_cache_control(n_turns: int) -> Any:
        messages: list[dict[str, Any]] = [{"role": "system", "content": "stable prompt"}]
        for i in range(n_turns):
            messages.append({"role": "assistant", "content": f"turn {i} action"})
            messages.append({"role": "user", "content": f"turn {i} tool result"})
        processed = apply(msg_points, messages, 4)
        last = processed[-1]
        content = last.get("content")
        # Hook inserts on the message (string content) or its last content block.
        if isinstance(content, list):
            return content[-1].get("cache_control")
        return last.get("cache_control")

    # Breakpoint lands on the final message regardless of transcript length —
    # so as the transcript grows turn over turn, the immutable prefix-so-far is
    # what gets cached, and it is re-read on the next turn.
    assert last_msg_cache_control(2) == {"type": "ephemeral"}
    assert last_msg_cache_control(20) == {"type": "ephemeral"}
