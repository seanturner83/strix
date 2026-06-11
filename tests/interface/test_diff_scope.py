import importlib.util
from pathlib import Path

import pytest


def _load_utils_module():
    module_path = Path(__file__).resolve().parents[2] / "strix" / "interface" / "utils.py"
    spec = importlib.util.spec_from_file_location("strix_interface_utils_test", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load strix.interface.utils for tests")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


utils = _load_utils_module()


def test_parse_name_status_uses_rename_destination_path() -> None:
    raw = (
        b"R100\x00old/path.py\x00new/path.py\x00"
        b"R75\x00legacy/module.py\x00modern/module.py\x00"
        b"M\x00src/app.py\x00"
        b"A\x00src/new_file.py\x00"
        b"D\x00src/deleted.py\x00"
    )

    entries = utils._parse_name_status_z(raw)
    classified = utils._classify_diff_entries(entries)

    assert "new/path.py" in classified["analyzable_files"]
    assert "old/path.py" not in classified["analyzable_files"]
    assert "modern/module.py" in classified["analyzable_files"]
    assert classified["renamed_files"][0]["old_path"] == "old/path.py"
    assert classified["renamed_files"][0]["new_path"] == "new/path.py"
    assert "src/deleted.py" in classified["deleted_files"]
    assert "src/deleted.py" not in classified["analyzable_files"]


def test_build_diff_scope_instruction_includes_added_modified_and_deleted_guidance() -> None:
    scope = utils.RepoDiffScope(
        source_path="/tmp/repo",
        workspace_subdir="repo",
        base_ref="refs/remotes/origin/main",
        merge_base="abc123",
        added_files=["src/added.py"],
        modified_files=["src/changed.py"],
        renamed_files=[{"old_path": "src/old.py", "new_path": "src/new.py", "similarity": 90}],
        deleted_files=["src/deleted.py"],
        analyzable_files=["src/added.py", "src/changed.py", "src/new.py"],
    )

    instruction = utils.build_diff_scope_instruction([scope])

    assert "For Added files, review the entire file content." in instruction
    assert "For Modified files, focus primarily on the changed areas." in instruction
    assert "Note: These files were deleted" in instruction
    assert "src/deleted.py" in instruction
    assert "src/old.py -> src/new.py" in instruction


def test_resolve_base_ref_prefers_github_base_ref(monkeypatch) -> None:
    calls: list[str] = []

    def fake_ref_exists(_repo_path: Path, ref: str) -> bool:
        calls.append(ref)
        return ref == "refs/remotes/origin/release-2026"

    monkeypatch.setattr(utils, "_git_ref_exists", fake_ref_exists)
    monkeypatch.setattr(utils, "_extract_github_base_sha", lambda _env: None)
    monkeypatch.setattr(utils, "_resolve_origin_head_ref", lambda _repo_path: None)

    base_ref = utils._resolve_base_ref(
        Path("/tmp/repo"),
        diff_base=None,
        env={"GITHUB_BASE_REF": "release-2026"},
    )

    assert base_ref == "refs/remotes/origin/release-2026"
    assert calls[0] == "refs/remotes/origin/release-2026"


def test_resolve_base_ref_falls_back_to_remote_main(monkeypatch) -> None:
    calls: list[str] = []

    def fake_ref_exists(_repo_path: Path, ref: str) -> bool:
        calls.append(ref)
        return ref == "refs/remotes/origin/main"

    monkeypatch.setattr(utils, "_git_ref_exists", fake_ref_exists)
    monkeypatch.setattr(utils, "_extract_github_base_sha", lambda _env: None)
    monkeypatch.setattr(utils, "_resolve_origin_head_ref", lambda _repo_path: None)

    base_ref = utils._resolve_base_ref(Path("/tmp/repo"), diff_base=None, env={})

    assert base_ref == "refs/remotes/origin/main"
    assert "refs/remotes/origin/main" in calls
    assert "origin/main" not in calls


def test_resolve_diff_scope_context_auto_degrades_when_repo_scope_resolution_fails(
    monkeypatch,
) -> None:
    source = {"source_path": "/tmp/repo", "workspace_subdir": "repo"}

    monkeypatch.setattr(utils, "_should_activate_auto_scope", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(utils, "_is_git_repo", lambda _repo_path: True)
    monkeypatch.setattr(
        utils,
        "_resolve_repo_diff_scope",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("shallow history")),
    )

    result = utils.resolve_diff_scope_context(
        local_sources=[source],
        scope_mode="auto",
        diff_base=None,
        non_interactive=True,
        env={},
    )

    assert result.active is False
    assert result.mode == "auto"
    assert result.metadata["active"] is False
    assert result.metadata["mode"] == "auto"
    assert "skipped_diff_scope_sources" in result.metadata
    assert result.metadata["skipped_diff_scope_sources"] == [
        "/tmp/repo (diff-scope skipped: shallow history)"
    ]


def test_resolve_diff_scope_context_diff_mode_still_raises_on_repo_scope_resolution_failure(
    monkeypatch,
) -> None:
    source = {"source_path": "/tmp/repo", "workspace_subdir": "repo"}

    monkeypatch.setattr(utils, "_is_git_repo", lambda _repo_path: True)
    monkeypatch.setattr(
        utils,
        "_resolve_repo_diff_scope",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("shallow history")),
    )

    with pytest.raises(ValueError, match="shallow history"):
        utils.resolve_diff_scope_context(
            local_sources=[source],
            scope_mode="diff",
            diff_base=None,
            non_interactive=True,
            env={},
        )


# ---- Diff-preload tests ----


def test_truncate_diff_content_under_cap_returns_unchanged() -> None:
    content = "diff --git a/x b/x\n+small\n"
    truncated, was_truncated, original = utils._truncate_diff_content(content, 1000)

    assert truncated == content
    assert was_truncated is False
    assert original == len(content.encode("utf-8"))


def test_truncate_diff_content_over_cap_keeps_head_and_tail() -> None:
    content = "HEAD_LINE\n" + ("x" * 5000) + "\nTAIL_LINE\n"
    truncated, was_truncated, original = utils._truncate_diff_content(content, 200)

    assert was_truncated is True
    assert original == len(content.encode("utf-8"))
    assert "HEAD_LINE" in truncated
    assert "TAIL_LINE" in truncated
    assert "diff truncated" in truncated
    assert len(truncated.encode("utf-8")) > 200  # marker added on top of caps


def test_capture_file_diffs_respects_total_cap(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path

    big_diff = "+" + ("x" * 100_000) + "\n"

    def fake_run(_repo_path, _args, check=False):
        class _Result:
            returncode = 0
            stdout = big_diff.encode("utf-8")
            stderr = b""

        return _Result()

    monkeypatch.setattr(utils, "_run_git_command_raw", fake_run)
    monkeypatch.setattr(utils, "_diff_preload_enabled", lambda: True)
    monkeypatch.setattr(utils, "_diff_preload_max_file_bytes", lambda: 50_000)
    monkeypatch.setattr(utils, "_diff_preload_max_total_bytes", lambda: 50_000)

    payloads = utils._capture_file_diffs(
        repo, "merge_base_sha", ["big1.py", "big2.py", "big3.py"]
    )

    assert len(payloads) == 3
    # First file fills the budget — inlined and truncated
    assert payloads[0].path == "big1.py"
    assert payloads[0].truncated is True
    assert payloads[0].skipped_reason is None
    # Second and third files dropped because total cap is exhausted
    assert payloads[1].path == "big2.py"
    assert payloads[1].skipped_reason == "total_cap_exceeded"
    assert payloads[1].content == ""
    assert payloads[2].path == "big3.py"
    assert payloads[2].skipped_reason == "total_cap_exceeded"


def test_capture_file_diffs_returns_empty_when_disabled(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(utils, "_diff_preload_enabled", lambda: False)
    payloads = utils._capture_file_diffs(tmp_path, "abc", ["a.py", "b.py"])
    assert payloads == []


def test_capture_file_diffs_handles_binary_or_non_utf8(monkeypatch, tmp_path: Path) -> None:
    def fake_run(_repo_path, _args, check=False):
        class _Result:
            returncode = 0
            stdout = b"\xff\xfe\xfd binary content"
            stderr = b""

        return _Result()

    monkeypatch.setattr(utils, "_run_git_command_raw", fake_run)
    monkeypatch.setattr(utils, "_diff_preload_enabled", lambda: True)
    monkeypatch.setattr(utils, "_diff_preload_max_file_bytes", lambda: 50_000)
    monkeypatch.setattr(utils, "_diff_preload_max_total_bytes", lambda: 200_000)

    payloads = utils._capture_file_diffs(tmp_path, "abc", ["bin.png"])

    assert len(payloads) == 1
    assert payloads[0].skipped_reason == "binary_or_non_utf8"
    assert payloads[0].content == ""


def test_capture_file_diffs_skips_files_with_failed_git_diff(monkeypatch, tmp_path: Path) -> None:
    def fake_run(_repo_path, _args, check=False):
        class _Result:
            returncode = 128
            stdout = b""
            stderr = b"fatal: bad object"

        return _Result()

    monkeypatch.setattr(utils, "_run_git_command_raw", fake_run)
    monkeypatch.setattr(utils, "_diff_preload_enabled", lambda: True)
    monkeypatch.setattr(utils, "_diff_preload_max_file_bytes", lambda: 50_000)
    monkeypatch.setattr(utils, "_diff_preload_max_total_bytes", lambda: 200_000)

    payloads = utils._capture_file_diffs(tmp_path, "abc", ["broken.py"])

    assert len(payloads) == 1
    assert payloads[0].skipped_reason == "diff_failed"


def test_build_diff_scope_instruction_includes_pr_diff_block_when_payloads_present() -> None:
    scope = utils.RepoDiffScope(
        source_path="/tmp/repo",
        workspace_subdir="repo",
        base_ref="refs/remotes/origin/main",
        merge_base="abc123",
        added_files=["src/added.py"],
        modified_files=["src/changed.py"],
        renamed_files=[],
        deleted_files=[],
        analyzable_files=["src/added.py", "src/changed.py"],
        file_diffs=[
            utils.FileDiffPayload(
                path="src/added.py",
                content="@@ -0,0 +1,3 @@\n+def hello():\n+    pass\n",
            ),
            utils.FileDiffPayload(
                path="src/changed.py",
                content="@@ -10,3 +10,3 @@\n-old\n+new\n",
            ),
        ],
    )

    instruction = utils.build_diff_scope_instruction([scope])

    assert "<pr_diff>" in instruction
    assert "</pr_diff>" in instruction
    assert '<file path="src/added.py">' in instruction
    assert "+def hello():" in instruction
    assert "+new" in instruction


def test_build_diff_scope_instruction_marks_truncated_files_with_attributes() -> None:
    scope = utils.RepoDiffScope(
        source_path="/tmp/repo",
        workspace_subdir="repo",
        base_ref="refs/remotes/origin/main",
        merge_base="abc123",
        added_files=[],
        modified_files=["large.go"],
        renamed_files=[],
        deleted_files=[],
        analyzable_files=["large.go"],
        file_diffs=[
            utils.FileDiffPayload(
                path="large.go",
                content="HEAD\n[... diff truncated ...]\nTAIL",
                truncated=True,
                original_bytes=200_000,
            ),
        ],
    )

    instruction = utils.build_diff_scope_instruction([scope])

    assert 'truncated="true"' in instruction
    assert 'original_bytes="200000"' in instruction


def test_build_diff_scope_instruction_lists_skipped_files_separately() -> None:
    scope = utils.RepoDiffScope(
        source_path="/tmp/repo",
        workspace_subdir="repo",
        base_ref="refs/remotes/origin/main",
        merge_base="abc123",
        added_files=[],
        modified_files=["small.py", "binary.png"],
        renamed_files=[],
        deleted_files=[],
        analyzable_files=["small.py", "binary.png"],
        file_diffs=[
            utils.FileDiffPayload(
                path="small.py", content="@@ -1 +1 @@\n-a\n+b\n"
            ),
            utils.FileDiffPayload(
                path="binary.png", content="", skipped_reason="binary_or_non_utf8"
            ),
        ],
    )

    instruction = utils.build_diff_scope_instruction([scope])

    assert "<pr_diff>" in instruction
    # Inlined file is in the diff block
    assert '<file path="small.py">' in instruction
    # Skipped file appears in the separate "NOT preloaded" list
    assert "binary.png (reason: binary_or_non_utf8)" in instruction
    # Skipped file should NOT be in the pr_diff block
    pr_diff_start = instruction.find("<pr_diff>")
    pr_diff_end = instruction.find("</pr_diff>")
    pr_diff_block = instruction[pr_diff_start:pr_diff_end]
    assert "binary.png" not in pr_diff_block


def test_build_diff_scope_instruction_omits_pr_diff_block_when_all_skipped() -> None:
    scope = utils.RepoDiffScope(
        source_path="/tmp/repo",
        workspace_subdir="repo",
        base_ref="refs/remotes/origin/main",
        merge_base="abc123",
        added_files=[],
        modified_files=["binary.png"],
        renamed_files=[],
        deleted_files=[],
        analyzable_files=["binary.png"],
        file_diffs=[
            utils.FileDiffPayload(
                path="binary.png", content="", skipped_reason="binary_or_non_utf8"
            ),
        ],
    )

    instruction = utils.build_diff_scope_instruction([scope])

    # No pr_diff block when there's nothing to inline
    assert "<pr_diff>" not in instruction
    # But the skipped file is still listed
    assert "binary.png (reason: binary_or_non_utf8)" in instruction


def test_repo_diff_scope_to_metadata_reports_inline_truncated_skipped_counts() -> None:
    scope = utils.RepoDiffScope(
        source_path="/tmp/repo",
        workspace_subdir="repo",
        base_ref="origin/main",
        merge_base="abc",
        added_files=[],
        modified_files=["a.py", "b.py", "huge.py", "binary.png"],
        renamed_files=[],
        deleted_files=[],
        analyzable_files=["a.py", "b.py", "huge.py", "binary.png"],
        file_diffs=[
            utils.FileDiffPayload(path="a.py", content="@@ -1 +1 @@\n-a\n+b"),
            utils.FileDiffPayload(path="b.py", content="@@ -1 +1 @@\n-c\n+d"),
            utils.FileDiffPayload(
                path="huge.py", content="HEAD..TAIL", truncated=True, original_bytes=99999
            ),
            utils.FileDiffPayload(
                path="binary.png", content="", skipped_reason="binary_or_non_utf8"
            ),
        ],
    )

    md = scope.to_metadata()

    assert md["file_diffs_inlined_count"] == 3  # a.py, b.py, huge.py (truncated still inlined)
    assert md["file_diffs_truncated_count"] == 1  # huge.py
    assert md["file_diffs_skipped_count"] == 1  # binary.png


# ───────────────────────────────────────────────────────────────────────────
# --scope-paths (explicit-path scoping bypassing git diff)
# ───────────────────────────────────────────────────────────────────────────


def _make_git_repo(tmp_path: Path) -> Path:
    """Initialise a minimal git repo for the explicit-paths tests."""
    import subprocess
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "test"], check=True)
    return repo


def test_resolve_repo_explicit_paths_returns_only_existing_files(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path)
    (repo / "src").mkdir()
    (repo / "src" / "real.py").write_text("# real\n")
    (repo / "src" / "also.go").write_text("// also\n")

    source = {"source_path": str(repo), "workspace_subdir": "repo"}
    scope = utils._resolve_repo_explicit_paths(
        source,
        ["src/real.py", "src/also.go", "src/missing.py"],
        env={},
    )

    assert set(scope.analyzable_files) == {"src/real.py", "src/also.go"}
    assert "src/missing.py" not in scope.analyzable_files
    assert scope.base_ref == "(explicit --scope-paths)"
    assert scope.merge_base == "(explicit --scope-paths)"
    assert scope.deleted_files == []
    assert scope.renamed_files == []


def test_resolve_repo_explicit_paths_rejects_absolute_and_traversal(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path)
    (repo / "real.py").write_text("# real\n")

    source = {"source_path": str(repo), "workspace_subdir": "repo"}
    scope = utils._resolve_repo_explicit_paths(
        source,
        ["real.py", "/etc/passwd", "../escape.py", "src/../sneaky.py"],
        env={},
    )

    # Only "real.py" survives; the absolute path, parent-traversal and the
    # parent-traversal-inside-path all get rejected.
    assert scope.analyzable_files == ["real.py"]


def test_resolve_repo_explicit_paths_errors_when_no_paths_survive(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path)

    source = {"source_path": str(repo), "workspace_subdir": "repo"}
    with pytest.raises(ValueError, match="zero existing files"):
        utils._resolve_repo_explicit_paths(
            source,
            ["nonexistent.py", "also_gone.go"],
            env={},
        )


def test_resolve_diff_scope_context_explicit_paths_takes_precedence_over_diff_base(
    tmp_path: Path,
) -> None:
    repo = _make_git_repo(tmp_path)
    (repo / "human.py").write_text("# human change\n")

    sources = [{"source_path": str(repo), "workspace_subdir": "repo"}]
    result = utils.resolve_diff_scope_context(
        local_sources=sources,
        scope_mode="diff",
        diff_base="origin/main",  # ignored when scope_paths is set
        scope_paths="human.py",
        non_interactive=True,
        env={},
    )

    assert result.active is True
    assert result.metadata["total_analyzable_files"] == 1
    repo_meta = result.metadata["repos"][0]
    assert repo_meta["analyzable_files"] == ["human.py"]
    assert repo_meta["base_ref"] == "(explicit --scope-paths)"


def test_resolve_diff_scope_context_rejects_scope_paths_with_full_mode(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path)
    (repo / "x.py").write_text("# x\n")

    sources = [{"source_path": str(repo), "workspace_subdir": "repo"}]
    with pytest.raises(ValueError, match="--scope-paths requires --scope-mode diff"):
        utils.resolve_diff_scope_context(
            local_sources=sources,
            scope_mode="full",
            diff_base=None,
            scope_paths="x.py",
            non_interactive=True,
            env={},
        )


def test_build_diff_scope_instruction_includes_self_reference_advisory_when_repo_full_name_set() -> None:
    # SEC: when the canonical owner/repo is known, the agent prompt
    # surfaces a self-reference advisory so intra-repo `uses:` /
    # imports / path refs aren't flagged as third-party.
    scope = utils.RepoDiffScope(
        source_path="/tmp/repo",
        workspace_subdir="target",
        base_ref="refs/remotes/origin/main",
        merge_base="abc123",
        added_files=[],
        modified_files=["foo.yml"],
        renamed_files=[],
        deleted_files=[],
        analyzable_files=["foo.yml"],
        repo_full_name="seedcx/composite-actions",
    )
    out = utils.build_diff_scope_instruction([scope])
    assert "Repository: seedcx/composite-actions" in out
    assert "Self-reference advisory" in out
    assert "seedcx/composite-actions/..." in out
    assert "intra-repo" in out


def test_build_diff_scope_instruction_omits_self_reference_when_repo_full_name_unset() -> None:
    # No repo_full_name → no advisory line, render stays as before.
    scope = utils.RepoDiffScope(
        source_path="/tmp/repo",
        workspace_subdir="target",
        base_ref="refs/remotes/origin/main",
        merge_base="abc123",
        added_files=[],
        modified_files=["foo.py"],
        renamed_files=[],
        deleted_files=[],
        analyzable_files=["foo.py"],
    )
    out = utils.build_diff_scope_instruction([scope])
    assert "Self-reference advisory" not in out
    # The basic Repository Scope line still renders unchanged.
    assert "Repository Scope: target" in out


def test_resolve_diff_scope_context_stamps_repo_full_name_on_first_scope(tmp_path: Path) -> None:
    repo = _make_git_repo(tmp_path)
    (repo / "x.py").write_text("# x\n")

    sources = [{"source_path": str(repo), "workspace_subdir": "repo"}]
    result = utils.resolve_diff_scope_context(
        local_sources=sources,
        scope_mode="diff",
        diff_base=None,
        scope_paths="x.py",
        non_interactive=True,
        env={},
        target_repo_full_name="seedcx/composite-actions",
    )
    assert result.active is True
    assert result.metadata["repos"][0]["repo_full_name"] == "seedcx/composite-actions"
    # The advisory lands in the rendered prompt on result.instruction_block.
    assert "Self-reference advisory" in result.instruction_block
    assert "seedcx/composite-actions" in result.instruction_block
