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

"""Tests for --scope-paths (explicit file allowlist). Forward-ported from the
0.8 seedcx-build feature (089e797/a775960) onto v1.2. The 0.8 file also tested
diff-truncation / file_diffs / name-status machinery that v1.x removed — those
tests were dropped; only the scope-paths behaviour is retained + schema-matched."""

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
