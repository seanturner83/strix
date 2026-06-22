import asyncio
import inspect
import os
from typing import Any

import httpx

from strix.config import Config
from strix.telemetry import posthog


if os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "false":
    from strix.runtime import get_runtime

from .argument_parser import convert_arguments
from .registry import (
    get_tool_by_name,
    get_tool_names,
    get_tool_param_schema,
    is_tool_parallel_safe,
    needs_agent_state,
    should_execute_in_sandbox,
)


_SERVER_TIMEOUT = float(Config.get("strix_sandbox_execution_timeout") or "120")
SANDBOX_EXECUTION_TIMEOUT = _SERVER_TIMEOUT + 30
SANDBOX_CONNECT_TIMEOUT = float(Config.get("strix_sandbox_connect_timeout") or "10")

# SEC-???? spike: per-call tool-cost feedback. When enabled, append the
# approximate token cost of each tool RESULT to the observation the agent
# sees. The agent is an optimiser but reasons about capability ("can I
# reach the answer?") not cost ("what did that path burn?") — fleet
# telemetry shows read+grep results are ~48% of all tool-result tokens,
# and live observation shows the agent treats "search then read the whole
# file" as equivalent to a precise windowed fetch because it doesn't price
# the follow-up read. Making the cost legible at the point of choice lets
# it self-select the cheaper tool WHEN precision is what it needed (and
# keep grepping when breadth is). Pure economic signal, no directive —
# authority signals ("use X instead") are already ignored.
#
# DEFAULT OFF: this touches every tool result fleet-wide, so it ships inert
# and is enabled per-run (STRIX_TOOL_COST_FEEDBACK=1) to MEASURE the mix
# shift, never flipped live blind.
_TOOL_COST_FEEDBACK = (Config.get("strix_tool_cost_feedback") or "").strip().lower() in (
    "1",
    "true",
    "yes",
)
# ~4 chars/token is the standard rough estimate; deliberately char-based to
# add zero per-call latency (no tokenizer invocation on every result).
_CHARS_PER_TOKEN = 4


def _cost_feedback_line(result_str: str) -> str:
    """Render the per-call cost annotation appended to a tool result.

    Reports the approximate token cost the result adds to context. Bucketed
    coarsely so the agent reads it as a signal, not a precise figure it
    might over-fit to. Empty string when the feature is disabled."""
    if not _TOOL_COST_FEEDBACK:
        return ""
    approx_tokens = len(result_str) // _CHARS_PER_TOKEN
    return f"\n<cost>~{approx_tokens} tokens added to context by this result</cost>"


async def execute_tool(tool_name: str, agent_state: Any | None = None, **kwargs: Any) -> Any:
    execute_in_sandbox = should_execute_in_sandbox(tool_name)
    sandbox_mode = os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"

    if execute_in_sandbox and not sandbox_mode:
        return await _execute_tool_in_sandbox(tool_name, agent_state, **kwargs)

    return await _execute_tool_locally(tool_name, agent_state, **kwargs)


async def _execute_tool_in_sandbox(tool_name: str, agent_state: Any, **kwargs: Any) -> Any:
    if not hasattr(agent_state, "sandbox_id") or not agent_state.sandbox_id:
        raise ValueError("Agent state with a valid sandbox_id is required for sandbox execution.")

    if not hasattr(agent_state, "sandbox_token") or not agent_state.sandbox_token:
        raise ValueError(
            "Agent state with a valid sandbox_token is required for sandbox execution."
        )

    if (
        not hasattr(agent_state, "sandbox_info")
        or "tool_server_port" not in agent_state.sandbox_info
    ):
        raise ValueError(
            "Agent state with a valid sandbox_info containing tool_server_port is required."
        )

    runtime = get_runtime()
    tool_server_port = agent_state.sandbox_info["tool_server_port"]
    server_url = await runtime.get_sandbox_url(agent_state.sandbox_id, tool_server_port)
    request_url = f"{server_url}/execute"

    agent_id = getattr(agent_state, "agent_id", "unknown")

    request_data = {
        "agent_id": agent_id,
        "tool_name": tool_name,
        "kwargs": kwargs,
    }

    headers = {
        "Authorization": f"Bearer {agent_state.sandbox_token}",
        "Content-Type": "application/json",
    }

    timeout = httpx.Timeout(
        timeout=SANDBOX_EXECUTION_TIMEOUT,
        connect=SANDBOX_CONNECT_TIMEOUT,
    )

    async with httpx.AsyncClient(trust_env=False) as client:
        try:
            response = await client.post(
                request_url, json=request_data, headers=headers, timeout=timeout
            )
            response.raise_for_status()
            response_data = response.json()
            if response_data.get("error"):
                posthog.error("tool_execution_error", f"{tool_name}: {response_data['error']}")
                raise RuntimeError(f"Sandbox execution error: {response_data['error']}")
            return response_data.get("result")
        except httpx.HTTPStatusError as e:
            posthog.error("tool_http_error", f"{tool_name}: HTTP {e.response.status_code}")
            if e.response.status_code == 401:
                raise RuntimeError("Authentication failed: Invalid or missing sandbox token") from e
            raise RuntimeError(f"HTTP error calling tool server: {e.response.status_code}") from e
        except httpx.RequestError as e:
            error_type = type(e).__name__
            posthog.error("tool_request_error", f"{tool_name}: {error_type}")
            raise RuntimeError(f"Request error calling tool server: {error_type}") from e


async def _execute_tool_locally(tool_name: str, agent_state: Any | None, **kwargs: Any) -> Any:
    tool_func = get_tool_by_name(tool_name)
    if not tool_func:
        raise ValueError(f"Tool '{tool_name}' not found")

    converted_kwargs = convert_arguments(tool_func, kwargs)

    if needs_agent_state(tool_name):
        if agent_state is None:
            raise ValueError(f"Tool '{tool_name}' requires agent_state but none was provided.")
        result = tool_func(agent_state=agent_state, **converted_kwargs)
    else:
        result = tool_func(**converted_kwargs)

    return await result if inspect.isawaitable(result) else result


def validate_tool_availability(tool_name: str | None) -> tuple[bool, str]:
    if tool_name is None:
        available = ", ".join(sorted(get_tool_names()))
        return False, f"Tool name is missing. Available tools: {available}"

    if tool_name not in get_tool_names():
        available = ", ".join(sorted(get_tool_names()))
        return False, f"Tool '{tool_name}' is not available. Available tools: {available}"

    return True, ""


def _validate_tool_arguments(tool_name: str, kwargs: dict[str, Any]) -> str | None:
    param_schema = get_tool_param_schema(tool_name)
    if not param_schema or not param_schema.get("has_params"):
        return None

    allowed_params: set[str] = param_schema.get("params", set())
    required_params: set[str] = param_schema.get("required", set())
    optional_params = allowed_params - required_params

    schema_hint = _format_schema_hint(tool_name, required_params, optional_params)

    unknown_params = set(kwargs.keys()) - allowed_params
    if unknown_params:
        unknown_list = ", ".join(sorted(unknown_params))
        return f"Tool '{tool_name}' received unknown parameter(s): {unknown_list}\n{schema_hint}"

    missing_required = [
        param for param in required_params if param not in kwargs or kwargs.get(param) in (None, "")
    ]
    if missing_required:
        missing_list = ", ".join(sorted(missing_required))
        return f"Tool '{tool_name}' missing required parameter(s): {missing_list}\n{schema_hint}"

    return None


def _format_schema_hint(tool_name: str, required: set[str], optional: set[str]) -> str:
    parts = [f"Valid parameters for '{tool_name}':"]
    if required:
        parts.append(f"  Required: {', '.join(sorted(required))}")
    if optional:
        parts.append(f"  Optional: {', '.join(sorted(optional))}")
    return "\n".join(parts)


async def execute_tool_with_validation(
    tool_name: str | None, agent_state: Any | None = None, **kwargs: Any
) -> Any:
    is_valid, error_msg = validate_tool_availability(tool_name)
    if not is_valid:
        return f"Error: {error_msg}"

    assert tool_name is not None

    arg_error = _validate_tool_arguments(tool_name, kwargs)
    if arg_error:
        return f"Error: {arg_error}"

    try:
        result = await execute_tool(tool_name, agent_state, **kwargs)
    except Exception as e:  # noqa: BLE001
        error_str = str(e)
        if len(error_str) > 500:
            error_str = error_str[:500] + "... [truncated]"
        return f"Error executing {tool_name}: {error_str}"
    else:
        return result


async def execute_tool_invocation(tool_inv: dict[str, Any], agent_state: Any | None = None) -> Any:
    tool_name = tool_inv.get("toolName")
    tool_args = tool_inv.get("args", {})

    return await execute_tool_with_validation(tool_name, agent_state, **tool_args)


def _check_error_result(result: Any) -> tuple[bool, Any]:
    is_error = False
    error_payload: Any = None

    if (isinstance(result, dict) and "error" in result) or (
        isinstance(result, str) and result.strip().lower().startswith("error:")
    ):
        is_error = True
        error_payload = result

    return is_error, error_payload


def _update_tracer_with_result(
    tracer: Any, execution_id: Any, is_error: bool, result: Any, error_payload: Any
) -> None:
    if not tracer or not execution_id:
        return

    try:
        if is_error:
            tracer.update_tool_execution(execution_id, "error", error_payload)
        else:
            tracer.update_tool_execution(execution_id, "completed", result)
    except (ConnectionError, RuntimeError) as e:
        error_msg = str(e)
        if tracer and execution_id:
            tracer.update_tool_execution(execution_id, "error", error_msg)
        raise


def _format_tool_result(tool_name: str, result: Any) -> tuple[str, list[dict[str, Any]]]:
    images: list[dict[str, Any]] = []

    screenshot_data = extract_screenshot_from_result(result)
    if screenshot_data:
        images.append(
            {
                "type": "image_url",
                "image_url": {"url": f"data:image/png;base64,{screenshot_data}"},
            }
        )
        result_str = remove_screenshot_from_result(result)
    else:
        result_str = result

    if result_str is None:
        final_result_str = f"Tool {tool_name} executed successfully"
        cost_basis = ""
    else:
        final_result_str = str(result_str)
        # Cost is reported against the FULL result the agent is charged for
        # in context, before any display-truncation here — the truncation
        # notice and the cost line describe the same underlying size.
        cost_basis = final_result_str
        if len(final_result_str) > 10000:
            start_part = final_result_str[:4000]
            end_part = final_result_str[-4000:]
            final_result_str = start_part + "\n\n... [middle content truncated] ...\n\n" + end_part

    observation_xml = (
        f"<tool_result>\n<tool_name>{tool_name}</tool_name>\n"
        f"<result>{final_result_str}</result>\n</tool_result>"
        # Cost annotation sits OUTSIDE the </tool_result> wrapper on purpose:
        # the history-truncation pass (llm._TOOL_RESULT_PATTERN) matches
        # `</result>\s*</tool_result>`, so anything inserted between those
        # tags would break that match and silently disable truncation of
        # this result — a cost-feedback feature must not defeat cost control.
        f"{_cost_feedback_line(cost_basis)}"
    )

    return observation_xml, images


async def _execute_single_tool(
    tool_inv: dict[str, Any],
    agent_state: Any | None,
    tracer: Any | None,
    agent_id: str,
    batch_id: str | None = None,
) -> tuple[str, list[dict[str, Any]], bool]:
    tool_name = tool_inv.get("toolName", "unknown")
    args = tool_inv.get("args", {})
    execution_id = None
    should_agent_finish = False

    if tracer:
        execution_id = tracer.log_tool_execution_start(agent_id, tool_name, args, batch_id=batch_id)

    try:
        result = await execute_tool_invocation(tool_inv, agent_state)

        is_error, error_payload = _check_error_result(result)

        if (
            tool_name in ("finish_scan", "agent_finish")
            and not is_error
            and isinstance(result, dict)
        ):
            if tool_name == "finish_scan":
                should_agent_finish = result.get("scan_completed", False)
            elif tool_name == "agent_finish":
                should_agent_finish = result.get("agent_completed", False)

        _update_tracer_with_result(tracer, execution_id, is_error, result, error_payload)

    except (ConnectionError, RuntimeError, ValueError, TypeError, OSError) as e:
        error_msg = str(e)
        if tracer and execution_id:
            tracer.update_tool_execution(execution_id, "error", error_msg)
        raise

    observation_xml, images = _format_tool_result(tool_name, result)
    return observation_xml, images, should_agent_finish


def _get_tracer_and_agent_id(agent_state: Any | None) -> tuple[Any | None, str]:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        agent_id = agent_state.agent_id if agent_state else "unknown_agent"
    except (ImportError, AttributeError):
        tracer = None
        agent_id = "unknown_agent"

    return tracer, agent_id


def _all_parallel_safe(tool_invocations: list[dict[str, Any]]) -> bool:
    """True if every invocation is for a tool registered as parallel_safe=True."""
    for inv in tool_invocations:
        name = inv.get("toolName")
        if not isinstance(name, str) or not is_tool_parallel_safe(name):
            return False
    return True


async def process_tool_invocations(
    tool_invocations: list[dict[str, Any]],
    conversation_history: list[dict[str, Any]],
    agent_state: Any | None = None,
) -> bool:
    import uuid

    observation_parts: list[str] = []
    all_images: list[dict[str, Any]] = []
    should_agent_finish = False

    tracer, agent_id = _get_tracer_and_agent_id(agent_state)

    # Tag all invocations from one agent turn with a shared batch_id so OTel
    # consumers can answer "did this turn batch?" without inferring from
    # timestamps. Single-tool turns get a batch_id of size-1 (still useful for
    # joining started/updated events).
    batch_id = uuid.uuid4().hex if len(tool_invocations) >= 1 else None

    can_parallelise = (
        len(tool_invocations) > 1 and _all_parallel_safe(tool_invocations)
    )

    if can_parallelise:
        # Run independent tools concurrently. Results are gathered in invocation
        # order (asyncio.gather preserves ordering), so the LLM observes them
        # in the same order it requested.
        results = await asyncio.gather(
            *[
                _execute_single_tool(inv, agent_state, tracer, agent_id, batch_id=batch_id)
                for inv in tool_invocations
            ],
            return_exceptions=True,
        )
        for inv, result in zip(tool_invocations, results, strict=False):
            if isinstance(result, BaseException):
                tool_name = inv.get("toolName", "unknown")
                observation_parts.append(
                    f"<tool_result>\n<tool_name>{tool_name}</tool_name>\n"
                    f"<result>Error: {result!s}</result>\n</tool_result>"
                )
                continue
            observation_xml, images, tool_should_finish = result
            observation_parts.append(observation_xml)
            all_images.extend(images)
            if tool_should_finish:
                should_agent_finish = True
    else:
        for tool_inv in tool_invocations:
            observation_xml, images, tool_should_finish = await _execute_single_tool(
                tool_inv, agent_state, tracer, agent_id, batch_id=batch_id
            )
            observation_parts.append(observation_xml)
            all_images.extend(images)

            if tool_should_finish:
                should_agent_finish = True

    if all_images:
        content = [{"type": "text", "text": "Tool Results:\n\n" + "\n\n".join(observation_parts)}]
        content.extend(all_images)
        conversation_history.append({"role": "user", "content": content})
    else:
        observation_content = "Tool Results:\n\n" + "\n\n".join(observation_parts)
        conversation_history.append({"role": "user", "content": observation_content})

    return should_agent_finish


def extract_screenshot_from_result(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None

    screenshot = result.get("screenshot")
    if isinstance(screenshot, str) and screenshot:
        return screenshot

    return None


def remove_screenshot_from_result(result: Any) -> Any:
    if not isinstance(result, dict):
        return result

    result_copy = result.copy()
    if "screenshot" in result_copy:
        result_copy["screenshot"] = "[Image data extracted - see attached image]"

    return result_copy
