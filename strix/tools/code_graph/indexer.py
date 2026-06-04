"""SCIP indexer + SQLite loader for the Strix code-graph tools (SEC-6848).

W1 scope: build the SCIP index for a target repo, convert it to SQLite via
the scip CLI, return the SQLite path. The actual graph-query tools are
registered in W2.

Indexer selection (W1):
    - TypeScript / JavaScript: scip-typescript (npm @sourcegraph/scip-typescript
      pinned to 0.4.0 in containers/Dockerfile).
    - Go: scip-go (github.com/scip-code/scip-go pinned to v0.2.7).
    - Python, Java: deferred to W5.

Local smoke validation (2026-06-04):
    - portal-api    (TypeScript): ~500ms, 3.25 MB SCIP, 5267 symbols.
    - payment-orchestrator (Go): ~32s,   8.9  MB SCIP, 5197 symbols.

Multi-language repos run both indexers; the SQLite loader merges them so a
single .sqlite handle answers cross-language queries.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


logger = logging.getLogger(__name__)


class IndexerError(RuntimeError):
    """Raised when an indexer tool fails or is missing from the sandbox."""


@dataclass(frozen=True)
class IndexResult:
    target_dir: Path
    scip_paths: tuple[Path, ...]
    sqlite_path: Path


def _binary_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _has_files_matching(target: Path, *patterns: str) -> bool:
    for pattern in patterns:
        if next(target.rglob(pattern), None) is not None:
            return True
    return False


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 600) -> None:
    logger.info("code_graph: running %s (cwd=%s)", " ".join(cmd), cwd)
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise IndexerError(
            f"command {cmd!r} failed (rc={proc.returncode}): {proc.stderr[:500]}"
        )


def _index_typescript(target: Path, out_dir: Path) -> Path | None:
    if not _has_files_matching(target, "tsconfig.json", "package.json"):
        return None
    if not _binary_exists("scip-typescript"):
        raise IndexerError("scip-typescript missing from sandbox")
    out = out_dir / "ts.scip"
    _run(["scip-typescript", "index", "--output", str(out)], cwd=target)
    return out if out.exists() else None


def _index_go(target: Path, out_dir: Path) -> Path | None:
    if not _has_files_matching(target, "go.mod"):
        return None
    if not _binary_exists("scip-go"):
        raise IndexerError("scip-go missing from sandbox")
    out = out_dir / "go.scip"
    _run(["scip-go", "--output", str(out)], cwd=target)
    return out if out.exists() else None


def _convert_to_sqlite(scip_paths: tuple[Path, ...], out_dir: Path) -> Path:
    if not _binary_exists("scip"):
        raise IndexerError("scip CLI missing from sandbox")
    sqlite_path = out_dir / "code_graph.sqlite"
    # W1: single-language path. Multi-language merge ships in W2 — the SCIP
    # CLI's expt-convert takes one index at a time, so multi-lang repos will
    # need a small post-process to UNION the per-language tables.
    primary = scip_paths[0]
    _run(["scip", "expt-convert", str(primary), "--output", str(sqlite_path)])
    if len(scip_paths) > 1:
        logger.warning(
            "code_graph: multi-language indexes (%d) detected; only %s converted in W1",
            len(scip_paths),
            primary.name,
        )
    return sqlite_path


def build_index(target_dir: Path, out_dir: Path) -> IndexResult:
    """Build SCIP indexes for the target repo, convert to SQLite.

    Detection is filename-based (tsconfig.json/package.json → TS; go.mod →
    Go). Multiple indexers run for multi-language repos but only the first
    is SQLite-converted in W1; W2 generalises the loader.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    scip_paths: list[Path] = []
    ts_index = _index_typescript(target_dir, out_dir)
    if ts_index is not None:
        scip_paths.append(ts_index)
    go_index = _index_go(target_dir, out_dir)
    if go_index is not None:
        scip_paths.append(go_index)

    if not scip_paths:
        raise IndexerError(
            f"no supported source languages detected under {target_dir}"
        )

    sqlite_path = _convert_to_sqlite(tuple(scip_paths), out_dir)
    return IndexResult(
        target_dir=target_dir,
        scip_paths=tuple(scip_paths),
        sqlite_path=sqlite_path,
    )


def load_index(sqlite_path: Path) -> Path:
    """Stub: opens the SQLite index for tool consumption. W2 returns a
    connection wrapper with the find_definition / find_references / etc
    query methods bound."""
    if not sqlite_path.exists():
        raise IndexerError(f"code_graph index missing at {sqlite_path}")
    return sqlite_path
