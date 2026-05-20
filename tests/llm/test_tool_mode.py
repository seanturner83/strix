"""Tests for STRIX_TOOL_MODE / LLMConfig.tool_mode."""

import asyncio

import pytest


@pytest.fixture(autouse=True)
def _clear_tool_mode_env(monkeypatch):
    monkeypatch.delenv("STRIX_TOOL_MODE", raising=False)
    monkeypatch.delenv("STRIX_LLM", raising=False)
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5.4")


def test_default_tool_mode_is_serial():
    from strix.llm.config import LLMConfig

    cfg = LLMConfig()
    assert cfg.tool_mode == "serial"


def test_env_var_sets_tool_mode(monkeypatch):
    from strix.llm.config import LLMConfig

    monkeypatch.setenv("STRIX_TOOL_MODE", "parallel")
    cfg = LLMConfig()
    assert cfg.tool_mode == "parallel"


def test_explicit_kwarg_overrides_env(monkeypatch):
    from strix.llm.config import LLMConfig

    monkeypatch.setenv("STRIX_TOOL_MODE", "parallel")
    cfg = LLMConfig(tool_mode="serial")
    assert cfg.tool_mode == "serial"


def test_invalid_tool_mode_raises():
    from strix.llm.config import LLMConfig

    with pytest.raises(ValueError, match="Invalid tool_mode"):
        LLMConfig(tool_mode="bogus")


def test_unrestricted_not_yet_implemented():
    from strix.llm.config import LLMConfig

    with pytest.raises(ValueError, match="Invalid tool_mode"):
        LLMConfig(tool_mode="unrestricted")


def test_strix_tool_mode_is_tracked_var():
    from strix.config.config import Config

    assert "STRIX_TOOL_MODE" in Config.tracked_vars()


def test_register_tool_parallel_safe_flag_default_false():
    from strix.tools.registry import is_tool_parallel_safe, register_tool, tools

    snapshot = list(tools)
    try:
        @register_tool
        def _test_unsafe_tool() -> dict:  # type: ignore[no-redef]
            return {"ok": True}

        assert is_tool_parallel_safe("_test_unsafe_tool") is False
    finally:
        tools.clear()
        tools.extend(snapshot)


def test_register_tool_parallel_safe_true():
    from strix.tools.registry import is_tool_parallel_safe, register_tool, tools

    snapshot = list(tools)
    try:
        @register_tool(parallel_safe=True)
        def _test_safe_tool() -> dict:  # type: ignore[no-redef]
            return {"ok": True}

        assert is_tool_parallel_safe("_test_safe_tool") is True
    finally:
        tools.clear()
        tools.extend(snapshot)


def test_listed_tools_marked_parallel_safe():
    """Sanity check: the small allowlist of safe tools is in fact registered as such."""
    from strix.tools.registry import is_tool_parallel_safe

    expected_safe = {
        "list_files",
        "search_files",
        "list_requests",
        "view_request",
        "list_sitemap",
        "view_sitemap_entry",
        "view_agent_graph",
        "batch_list_files",
        "batch_view_files",
        "batch_search_files",
        "batch_view_request",
    }
    for name in expected_safe:
        assert is_tool_parallel_safe(name), f"{name} should be parallel_safe"


def test_batch_list_files_runs_paths_concurrently(monkeypatch):
    """batch_list_files invokes list_files for each path via asyncio.gather."""
    from strix.tools.file_edit import file_edit_actions as mod

    invocations: list[str] = []

    def fake_list_files(path, recursive=False):
        invocations.append(path)
        return {"path": path, "recursive": recursive, "files": [f"f-in-{path}"]}

    monkeypatch.setattr(mod, "list_files", fake_list_files)

    result = asyncio.run(
        mod.batch_list_files(paths=["/a", "/b", "/c"])
    )

    assert result["count"] == 3
    assert set(result["results"].keys()) == {"/a", "/b", "/c"}
    assert result["results"]["/a"]["files"] == ["f-in-/a"]
    assert sorted(invocations) == ["/a", "/b", "/c"]


def test_batch_list_files_handles_per_path_errors(monkeypatch):
    """One failing path doesn't fail the whole batch."""
    from strix.tools.file_edit import file_edit_actions as mod

    def fake_list_files(path, recursive=False):
        if path == "/bad":
            raise OSError("permission denied")
        return {"path": path, "files": []}

    monkeypatch.setattr(mod, "list_files", fake_list_files)

    result = asyncio.run(mod.batch_list_files(paths=["/good", "/bad", "/also-good"]))

    assert "error" in result["results"]["/bad"]
    assert "permission denied" in result["results"]["/bad"]["error"]
    assert "error" not in result["results"]["/good"]
    assert "error" not in result["results"]["/also-good"]


def test_batch_list_files_rejects_empty_or_wrong_type():
    from strix.tools.file_edit.file_edit_actions import batch_list_files

    assert "error" in asyncio.run(batch_list_files(paths=[]))
    assert "error" in asyncio.run(batch_list_files(paths="not-a-list"))  # type: ignore[arg-type]


def test_batch_view_files_runs_concurrently(monkeypatch):
    from strix.tools.file_edit import file_edit_actions as mod

    seen: list[tuple] = []

    def fake_str_replace_editor(command, path, view_range=None, **kwargs):
        seen.append((command, path, view_range))
        return {"content": f"contents-of-{path}"}

    monkeypatch.setattr(mod, "str_replace_editor", fake_str_replace_editor)

    result = asyncio.run(mod.batch_view_files(views=[
        {"path": "/a.py"},
        {"path": "/b.py", "view_range": [1, 50]},
        {"path": "/c.py"},
    ]))

    assert result["count"] == 3
    assert all(call[0] == "view" for call in seen)
    assert ("view", "/b.py", [1, 50]) in seen
    assert result["results"][0]["path"] == "/a.py"
    assert "contents-of-/b.py" in result["results"][1]["content"]
    assert result["results"][1]["view_range"] == [1, 50]


def test_batch_view_files_handles_missing_file(monkeypatch):
    from strix.tools.file_edit import file_edit_actions as mod

    def fake_str_replace_editor(command, path, view_range=None, **kwargs):
        if path == "/missing.py":
            return {"error": f"File not found: {path}"}
        return {"content": f"ok-{path}"}

    monkeypatch.setattr(mod, "str_replace_editor", fake_str_replace_editor)

    result = asyncio.run(mod.batch_view_files(views=[
        {"path": "/good.py"},
        {"path": "/missing.py"},
    ]))

    assert result["count"] == 2
    assert "error" in result["results"][1]
    assert "content" in result["results"][0]


def test_batch_view_files_validates_input():
    from strix.tools.file_edit.file_edit_actions import batch_view_files

    assert "error" in asyncio.run(batch_view_files(views=[]))
    assert "error" in asyncio.run(batch_view_files(views=[{"no_path": "x"}]))


def test_batch_search_files_runs_searches_concurrently(monkeypatch):
    from strix.tools.file_edit import file_edit_actions as mod

    invocations: list[tuple] = []

    def fake_search_files(path, regex, file_pattern="*"):
        invocations.append((path, regex, file_pattern))
        return {"output": f"matches-for-{regex}-in-{path}"}

    monkeypatch.setattr(mod, "search_files", fake_search_files)

    result = asyncio.run(
        mod.batch_search_files(searches=[
            {"path": "/a", "regex": "TODO"},
            {"path": "/b", "regex": "FIXME", "file_pattern": "*.py"},
        ])
    )

    assert result["count"] == 2
    assert result["results"][0]["path"] == "/a"
    assert result["results"][0]["regex"] == "TODO"
    assert "matches-for-TODO" in result["results"][0]["output"]
    assert ("/b", "FIXME", "*.py") in invocations


def test_batch_search_files_validates_required_keys():
    from strix.tools.file_edit.file_edit_actions import batch_search_files

    # missing regex
    result = asyncio.run(batch_search_files(searches=[{"path": "/a"}]))
    assert "error" in result and "regex" in result["error"]


def test_batch_view_request_runs_concurrently(monkeypatch):
    from strix.tools.proxy import proxy_actions as mod

    seen: list[str] = []

    def fake_view_request(request_id, part="request", search_pattern=None, page=1, page_size=50):
        seen.append(request_id)
        return {"id": request_id, "part": part, "body": f"body-{request_id}"}

    monkeypatch.setattr(mod, "view_request", fake_view_request)

    result = asyncio.run(mod.batch_view_request(requests=[
        {"request_id": "r1"},
        {"request_id": "r2", "part": "response"},
    ]))

    assert result["count"] == 2
    assert sorted(seen) == ["r1", "r2"]
    assert result["results"][0]["request_id"] == "r1"
    assert result["results"][1]["part"] == "response"


def test_mutating_tools_NOT_marked_parallel_safe():
    """Sanity check: the obviously-mutating tools must not be parallel_safe."""
    from strix.tools.registry import is_tool_parallel_safe

    expected_unsafe = {
        "str_replace_editor",  # has create/insert/str_replace modes
        "create_agent",
        "agent_finish",
        "send_message_to_agent",
        "finish_scan",
        "send_request",  # mutates external state
    }
    for name in expected_unsafe:
        assert not is_tool_parallel_safe(name), f"{name} must not be parallel_safe"


def test_executor_runs_serial_when_any_tool_unsafe(monkeypatch):
    """If any invocation in a batch is non-parallel_safe, fall back to serial."""
    from strix.tools import executor as exec_mod

    call_order: list[str] = []
    completion_times: dict[str, float] = {}

    async def fake_execute_single_tool(inv, agent_state, tracer, agent_id, batch_id=None):
        name = inv.get("toolName", "?")
        call_order.append(f"start:{name}")
        await asyncio.sleep(0.01)
        completion_times[name] = asyncio.get_event_loop().time()
        call_order.append(f"end:{name}")
        return (f"<tool_result><tool_name>{name}</tool_name></tool_result>", [], False)

    monkeypatch.setattr(exec_mod, "_execute_single_tool", fake_execute_single_tool)
    # One safe + one unsafe → must run serial
    monkeypatch.setattr(
        exec_mod,
        "is_tool_parallel_safe",
        lambda name: name == "list_files",
    )

    invocations = [
        {"toolName": "list_files", "args": {"path": "."}},
        {"toolName": "str_replace_editor", "args": {"command": "create", "path": "x"}},
    ]
    history: list = []
    asyncio.run(exec_mod.process_tool_invocations(invocations, history))

    # Serial fallback: list_files completes before str_replace_editor starts.
    assert call_order == [
        "start:list_files",
        "end:list_files",
        "start:str_replace_editor",
        "end:str_replace_editor",
    ]


def test_executor_runs_parallel_when_all_tools_safe(monkeypatch):
    """All-safe batch executes via gather; both starts precede both ends."""
    from strix.tools import executor as exec_mod

    call_order: list[str] = []

    async def fake_execute_single_tool(inv, agent_state, tracer, agent_id, batch_id=None):
        name = inv.get("toolName", "?")
        call_order.append(f"start:{name}")
        await asyncio.sleep(0.05)
        call_order.append(f"end:{name}")
        return (f"<tool_result><tool_name>{name}</tool_name></tool_result>", [], False)

    monkeypatch.setattr(exec_mod, "_execute_single_tool", fake_execute_single_tool)
    monkeypatch.setattr(exec_mod, "is_tool_parallel_safe", lambda name: True)

    invocations = [
        {"toolName": "list_files", "args": {"path": "."}},
        {"toolName": "search_files", "args": {"path": ".", "regex": "x"}},
        {"toolName": "view_agent_graph", "args": {}},
    ]
    history: list = []
    asyncio.run(exec_mod.process_tool_invocations(invocations, history))

    # Parallel: all three starts come before any of the ends.
    starts = [i for i, ev in enumerate(call_order) if ev.startswith("start:")]
    ends = [i for i, ev in enumerate(call_order) if ev.startswith("end:")]
    assert max(starts) < min(ends), f"expected parallel start, got {call_order}"


def test_executor_serial_fallback_when_only_one_tool(monkeypatch):
    """Single-tool batches go through serial path even if marked parallel_safe."""
    from strix.tools import executor as exec_mod

    parallel_path_taken = False

    async def fake_execute_single_tool(inv, agent_state, tracer, agent_id, batch_id=None):
        return ("<tool_result/>", [], False)

    real_gather = asyncio.gather

    async def tracking_gather(*args, **kwargs):
        nonlocal parallel_path_taken
        parallel_path_taken = True
        return await real_gather(*args, **kwargs)

    monkeypatch.setattr(exec_mod, "_execute_single_tool", fake_execute_single_tool)
    monkeypatch.setattr(exec_mod, "is_tool_parallel_safe", lambda name: True)
    monkeypatch.setattr(exec_mod.asyncio, "gather", tracking_gather)

    invocations = [{"toolName": "list_files", "args": {"path": "."}}]
    history: list = []
    asyncio.run(exec_mod.process_tool_invocations(invocations, history))

    assert parallel_path_taken is False  # single-tool stays serial


def test_executor_emits_shared_batch_id_for_one_call(monkeypatch):
    """Tools from one process_tool_invocations call share a batch_id;
    tools from separate calls get distinct batch_ids. This is what makes
    'did the LLM batch?' answerable from OTel events."""
    from strix.tools import executor as exec_mod

    captured_batch_ids: list[str | None] = []

    async def fake_execute_single_tool(inv, agent_state, tracer, agent_id, batch_id=None):
        captured_batch_ids.append(batch_id)
        return ("<tool_result/>", [], False)

    monkeypatch.setattr(exec_mod, "_execute_single_tool", fake_execute_single_tool)
    monkeypatch.setattr(exec_mod, "is_tool_parallel_safe", lambda name: True)

    # First call: 3 tools — should share one batch_id
    asyncio.run(
        exec_mod.process_tool_invocations(
            [{"toolName": "list_files", "args": {}}] * 3, [], None
        )
    )

    first_call_ids = captured_batch_ids[:3]
    assert len(set(first_call_ids)) == 1, (
        f"3 tools in one call must share a batch_id, got {first_call_ids}"
    )
    assert first_call_ids[0] is not None

    # Second call: separate batch_id
    captured_batch_ids.clear()
    asyncio.run(
        exec_mod.process_tool_invocations(
            [{"toolName": "list_files", "args": {}}] * 2, [], None
        )
    )

    second_call_ids = captured_batch_ids[:2]
    assert len(set(second_call_ids)) == 1
    assert second_call_ids[0] != first_call_ids[0], (
        "Separate process_tool_invocations calls must produce distinct batch_ids"
    )


def test_executor_observation_order_preserves_invocation_order(monkeypatch):
    """Even when execution completes out-of-order, observations land in
    invocation order to keep the LLM's mental model consistent."""
    from strix.tools import executor as exec_mod

    delays = {"a": 0.05, "b": 0.01, "c": 0.03}

    async def fake_execute_single_tool(inv, agent_state, tracer, agent_id, batch_id=None):
        name = inv.get("toolName", "?")
        await asyncio.sleep(delays[name])
        return (
            f"<tool_result><tool_name>{name}</tool_name><result>{name}</result></tool_result>",
            [],
            False,
        )

    monkeypatch.setattr(exec_mod, "_execute_single_tool", fake_execute_single_tool)
    monkeypatch.setattr(exec_mod, "is_tool_parallel_safe", lambda name: True)

    invocations = [{"toolName": n, "args": {}} for n in ("a", "b", "c")]
    history: list = []
    asyncio.run(exec_mod.process_tool_invocations(invocations, history))

    # b finishes first (0.01), then c (0.03), then a (0.05). But observation
    # in conversation history must preserve invocation order: a, b, c.
    assert len(history) == 1
    content = history[0]["content"]
    pos_a = content.find("<result>a</result>")
    pos_b = content.find("<result>b</result>")
    pos_c = content.find("<result>c</result>")
    assert 0 < pos_a < pos_b < pos_c
