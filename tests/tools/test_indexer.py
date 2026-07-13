"""Tests for strix.tools.code_graph.indexer._convert_to_sqlite.

The convert-to-sqlite step shells out to `scip expt-convert`, whose
validator rejects malformed inputs (notably scip-python's synthetic
`_ScratchFile#` symbols — definition-occurrence without matching
SymbolInformation, observed on seedcx/composite-actions#1142).

These tests pin the multi-language fallback behavior: when the primary
.scip fails to convert, the function tries each remaining candidate in
priority order; total failure re-raises so _main() warn-and-continues.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from strix.tools.code_graph import indexer
from strix.tools.code_graph.indexer import IndexerError, _convert_to_sqlite


def _touch(path: Path, content: bytes = b"") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


@pytest.fixture
def fake_sqlite_writer():
    """Stub _run that writes a non-empty sqlite_path file iff the matcher
    function returns True for the candidate .scip path. Returns the list
    of (cmd, sqlite_path) tuples it was called with."""

    calls: list[tuple[list[str], Path]] = []

    def make_writer(should_succeed):
        def _run(cmd, cwd=None, timeout=600):
            calls.append((list(cmd), Path(cmd[-1])))
            # cmd is ["scip", "expt-convert", str(candidate), "--output", str(sqlite_path)]
            candidate = Path(cmd[2])
            sqlite_path = Path(cmd[4])
            if should_succeed(candidate):
                sqlite_path.write_bytes(b"sqlite-stub")
                return None
            raise IndexerError(
                f"command {cmd!r} failed (rc=1): "
                "validator rejected _ScratchFile# without SymbolInformation"
            )

        return _run, calls

    return make_writer


@pytest.fixture
def patched_scip(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(indexer, "_binary_exists", lambda name: True)


# --- single-candidate happy path ---------------------------------------

def test_single_scip_converts_in_one_call(
    tmp_path: Path,
    patched_scip: None,
    fake_sqlite_writer,
) -> None:
    scip = _touch(tmp_path / "py.scip", b"<scip>")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    runner, calls = fake_sqlite_writer(lambda _: True)
    with patch.object(indexer, "_run", side_effect=runner):
        sqlite = _convert_to_sqlite((scip,), out_dir)
    assert sqlite == out_dir / "code_graph.sqlite"
    assert sqlite.read_bytes() == b"sqlite-stub"
    assert len(calls) == 1


# --- primary fails, fallback succeeds ---------------------------------

def test_python_fails_falls_back_to_typescript(
    tmp_path: Path,
    patched_scip: None,
    fake_sqlite_writer,
) -> None:
    """The _ScratchFile# case: python is primary in this test, falls back."""
    py = _touch(tmp_path / "py.scip", b"<broken>")
    ts = _touch(tmp_path / "ts.scip", b"<ok>")
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    # Only ts.scip succeeds.
    runner, calls = fake_sqlite_writer(lambda c: c.name == "ts.scip")
    with patch.object(indexer, "_run", side_effect=runner):
        sqlite = _convert_to_sqlite((py, ts), out_dir)

    assert sqlite.exists()
    assert sqlite.read_bytes() == b"sqlite-stub"
    # Called once for py (failed), once for ts (succeeded).
    assert [c[0][2] for c in calls] == [str(py), str(ts)]


def test_partial_failure_cleans_up_stale_sqlite_between_attempts(
    tmp_path: Path,
    patched_scip: None,
) -> None:
    """If expt-convert writes a partial file before failing, the second
    attempt must not see the first attempt's stale bytes."""
    py = _touch(tmp_path / "py.scip", b"<broken>")
    ts = _touch(tmp_path / "ts.scip", b"<ok>")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    sqlite_target = out_dir / "code_graph.sqlite"

    def runner(cmd, cwd=None, timeout=600):
        candidate = Path(cmd[2])
        sqlite_path = Path(cmd[4])
        if candidate.name == "py.scip":
            # Write a partial file, then fail.
            sqlite_path.write_bytes(b"partial-junk-from-failed-convert")
            raise IndexerError("failed")
        # ts succeeds.
        sqlite_path.write_bytes(b"clean-ts-sqlite")
        return None

    with patch.object(indexer, "_run", side_effect=runner):
        sqlite = _convert_to_sqlite((py, ts), out_dir)

    assert sqlite.read_bytes() == b"clean-ts-sqlite", (
        "stale partial sqlite from the first failed attempt should not "
        "survive into the second attempt's output"
    )


# --- total failure path ------------------------------------------------

def test_all_candidates_failing_re_raises_last_error(
    tmp_path: Path,
    patched_scip: None,
    fake_sqlite_writer,
) -> None:
    py = _touch(tmp_path / "py.scip", b"<broken>")
    ts = _touch(tmp_path / "ts.scip", b"<also-broken>")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    runner, calls = fake_sqlite_writer(lambda _: False)
    with patch.object(indexer, "_run", side_effect=runner):
        with pytest.raises(IndexerError) as exc_info:
            _convert_to_sqlite((py, ts), out_dir)

    # Last error wins (the ts.scip failure, not py.scip's)
    assert "ts.scip" in calls[-1][0][2]
    # And sqlite_path must not be left around with stale bytes
    assert not (out_dir / "code_graph.sqlite").exists()


# --- missing CLI ------------------------------------------------------

def test_missing_scip_binary_raises_immediately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(indexer, "_binary_exists", lambda name: False)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    scip = _touch(tmp_path / "py.scip")
    with pytest.raises(IndexerError, match="scip CLI missing"):
        _convert_to_sqlite((scip,), out_dir)


# --- build_index per-language degradation -----------------------------
#
# A language indexer can RAISE (not just return None) when its marker is
# present but the tool then fails — e.g. package.json without tsconfig.json
# makes scip-typescript exit rc=1. build_index must isolate each language so
# one hard failure degrades to the next instead of aborting all indexing.

def test_build_index_degrades_past_failing_first_language(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    go_scip = _touch(out_dir / "go.scip", b"<scip>")

    # TS is tried first and RAISES (package.json w/o tsconfig); Go succeeds.
    monkeypatch.setattr(
        indexer, "_index_typescript",
        lambda t, o: (_ for _ in ()).throw(IndexerError("scip-typescript rc=1: missing tsconfig.json")))
    monkeypatch.setattr(indexer, "_index_go", lambda t, o: go_scip)
    monkeypatch.setattr(indexer, "_index_python", lambda t, o: None)
    monkeypatch.setattr(indexer, "_index_rust", lambda t, o: None)
    monkeypatch.setattr(indexer, "_convert_to_sqlite",
                        lambda paths, o: _touch(o / "code_graph.sqlite", b"db"))

    result = indexer.build_index(tmp_path, out_dir)
    # Go still indexed despite TS raising first.
    assert go_scip in result.scip_paths
    assert result.sqlite_path.exists()


def test_build_index_raises_only_when_all_languages_fail_or_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    # One language raises, the rest detect nothing → no scip_paths at all.
    monkeypatch.setattr(
        indexer, "_index_typescript",
        lambda t, o: (_ for _ in ()).throw(IndexerError("scip-typescript rc=1")))
    monkeypatch.setattr(indexer, "_index_go", lambda t, o: None)
    monkeypatch.setattr(indexer, "_index_python", lambda t, o: None)
    monkeypatch.setattr(indexer, "_index_rust", lambda t, o: None)

    with pytest.raises(IndexerError, match="no supported source languages"):
        indexer.build_index(tmp_path, out_dir)
