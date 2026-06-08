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

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .cache import CacheKey, CodeGraphCache, from_env as _cache_from_env


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


def _ensure_node_version(target: Path) -> str | None:
    """Resolve the Node version pinned by package.json's `engines.node` and
    install it into /tmp on demand if the sandbox's default node doesn't
    match. Returns the absolute path to the resolved node bin dir (suitable
    for prepending to PATH), or None if no version pin is found or current
    node already satisfies it.

    Background: many TS repos pin engines.node to a specific major (e.g.
    "22.15.0"). npm install fails with EBADENGINE if the sandbox's bundled
    node is older. Rather than baking every required node version into the
    Strix sandbox image, fetch the requested version from nodejs.org on
    demand and stage it under /tmp.
    """
    pkg = target / "package.json"
    if not pkg.exists():
        return None
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("code_graph: package.json unparseable (%s); skipping node pin", exc)
        return None
    desired_raw = (data.get("engines") or {}).get("node", "")
    if not isinstance(desired_raw, str):
        return None
    # Strip semver-range prefixes / whitespace ("^22", "~22.15", ">=22.15.0").
    # For simple ranges we pick the lower bound; for an exact pin we use as-is.
    # Multi-clause ranges ("^22 || ^20") fall through to "use whatever exists";
    # nodejs.org doesn't serve range-resolution.
    match = re.match(r'^\s*[\^~>=<]*\s*(\d+(?:\.\d+){0,2})', desired_raw)
    if not match:
        return None
    desired = match.group(1)
    # Pad to full M.m.p — nodejs.org only serves complete tarball names.
    parts = desired.split(".")
    if len(parts) == 1:
        # "22" → resolve to a known-LTS minor.patch. For simplicity pin to
        # the latest *known stable* for the major. Default to .0.0 and let
        # nodejs.org redirect; if that doesn't exist we'll fall through.
        desired = f"{parts[0]}.0.0"
    elif len(parts) == 2:
        desired = f"{desired}.0"

    # Skip download if the system node already matches.
    try:
        rc = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=5)
        if rc.returncode == 0 and rc.stdout.strip().lstrip("v") == desired:
            return None  # system node already matches; nothing to do
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    node_dir = Path(f"/tmp/node-v{desired}-linux-x64")
    if node_dir.exists() and (node_dir / "bin" / "node").exists():
        logger.info("code_graph: using cached node v%s at %s", desired, node_dir)
        return str(node_dir / "bin")

    url = f"https://nodejs.org/dist/v{desired}/node-v{desired}-linux-x64.tar.xz"
    logger.info("code_graph: fetching node v%s from nodejs.org", desired)
    try:
        _run(
            ["sh", "-c", f"curl -fLsS {url} | tar -xJ -C /tmp/"],
            timeout=180,
        )
    except IndexerError as exc:
        logger.warning(
            "code_graph: node v%s install failed (%s); falling back to system node",
            desired,
            exc,
        )
        return None
    if not (node_dir / "bin" / "node").exists():
        logger.warning(
            "code_graph: node v%s tarball extracted but no node binary at %s",
            desired,
            node_dir / "bin" / "node",
        )
        return None
    return str(node_dir / "bin")


def _index_typescript(target: Path, out_dir: Path) -> Path | None:
    if not _has_files_matching(target, "tsconfig.json", "package.json"):
        return None
    if not _binary_exists("scip-typescript"):
        raise IndexerError("scip-typescript missing from sandbox")
    # scip-typescript invokes the TypeScript compiler under the hood,
    # which refuses to proceed if `tsconfig.json` has an extends chain
    # it can't resolve. The common idiom of extending a package config
    # (e.g. `"extends": "@some-org/tsconfig-node"`) requires that
    # package to be present under node_modules — relative-path extends
    # (e.g. `"./tsconfig.base.json"`) don't.
    #
    # Most CI checkouts don't run `npm install`, so package-named
    # extends are unresolvable at index time and scip-typescript
    # fails with "error TS6053: File '<pkg>' not found" → no SCIP
    # produced.
    #
    # Install deps minimally to make the compiler happy: skip lifecycle
    # scripts + audit + funding for speed, use prefer-offline so repeat
    # scans of the same repo hit the npm cache warm. Cleanup of
    # node_modules + package-lock.json happens in the docker_runtime
    # hook after the indexer returns, so downstream tools (agent
    # loop, etc.) never see the installed deps.
    if not (target / "node_modules").exists() and (target / "package.json").exists():
        # Fallback chain for npm install:
        #   1. Try to match Node version from package.json engines.node.
        #      Many repos pin a specific node (e.g. "22.15.0") and npm
        #      refuses install with EBADENGINE on mismatch.
        #   2. If install still fails, retry with --engine-strict=false
        #      to bypass the engine check entirely.
        #   3. If THAT also fails, log + proceed without deps;
        #      scip-typescript will run on the bare tree and produce
        #      partial output (or fail; indexer module exits 0 either
        #      way per SEC-6848 warn-and-continue policy).
        node_bin = _ensure_node_version(target)
        base_args = [
            "npm",
            "install",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--prefer-offline",
        ]
        # If we resolved a node bin, wrap cmd in sh -c to prepend its
        # bin dir to PATH for the subprocess (subprocess.run env doesn't
        # shell-expand $PATH).
        if node_bin:
            wrapped = (
                f"export PATH={node_bin}:$PATH; "
                + " ".join(base_args)
            )
            install_cmd = ["sh", "-c", wrapped]
        else:
            install_cmd = base_args
        try:
            _run(install_cmd, cwd=target, timeout=300)
        except IndexerError as exc:
            logger.warning(
                "code_graph: npm install (engine-strict default) failed (%s); "
                "retrying with --engine-strict=false",
                exc,
            )
            fallback_args = base_args + ["--engine-strict=false"]
            if node_bin:
                fallback_cmd = [
                    "sh",
                    "-c",
                    f"export PATH={node_bin}:$PATH; " + " ".join(fallback_args),
                ]
            else:
                fallback_cmd = fallback_args
            try:
                _run(fallback_cmd, cwd=target, timeout=300)
            except IndexerError as exc2:
                logger.warning(
                    "code_graph: npm install fallback (--engine-strict=false) also "
                    "failed (%s); indexing without deps",
                    exc2,
                )
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


def _index_python(target: Path, out_dir: Path) -> Path | None:
    """SCIP index for Python projects via @sourcegraph/scip-python.

    Detection: pyproject.toml / setup.py / setup.cfg / requirements.txt.
    Dependency install: scip-python uses Pyright under the hood; for
    accurate import resolution we install deps when an obvious
    install path exists (uv.lock → uv, pyproject.toml → uv if
    available else pip-install -e, requirements.txt → pip install -r).
    If the install fails or the toolchain is missing we proceed
    without — scip-python emits a partial index rather than failing.
    Cleanup of .venv/ + venv/ + __pycache__/ happens in the
    docker_runtime hook.
    """
    py_markers = ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt")
    if not _has_files_matching(target, *py_markers):
        return None
    if not _binary_exists("scip-python"):
        raise IndexerError("scip-python missing from sandbox")

    has_venv = (target / ".venv").exists() or (target / "venv").exists()
    has_pyproject = (target / "pyproject.toml").exists()
    has_requirements = (target / "requirements.txt").exists()

    if not has_venv:
        try:
            if has_pyproject and _binary_exists("uv"):
                # uv is 10-100x faster than pip; prefer it when present.
                _run(
                    ["uv", "sync", "--no-dev", "--frozen"],
                    cwd=target,
                    timeout=300,
                )
            elif has_pyproject:
                _run(
                    ["pip", "install", "--no-deps", "-e", "."],
                    cwd=target,
                    timeout=300,
                )
            elif has_requirements:
                _run(
                    ["pip", "install", "-r", "requirements.txt"],
                    cwd=target,
                    timeout=300,
                )
        except IndexerError as exc:
            logger.warning(
                "code_graph: python deps install failed (%s); "
                "indexing without resolved imports",
                exc,
            )

    out = out_dir / "py.scip"
    _run(["scip-python", "index", "--output", str(out)], cwd=target)
    return out if out.exists() else None


def _ensure_rust_toolchain() -> str | None:
    """Lazy-install rustup + rust-analyzer component on first use.

    Rust toolchain is ~500MB which we don't want to bake into the
    sandbox image — most scans don't touch Rust. Install on demand
    into /home/pentester/.cargo + /home/pentester/.rustup; cached
    across scans in the same sandbox lifetime.

    Returns the bin dir containing rust-analyzer + cargo + rustc, or
    None if install fails (caller logs + degrades to no-index).
    """
    cargo_bin = Path("/home/pentester/.cargo/bin")
    if (cargo_bin / "rust-analyzer").exists():
        return str(cargo_bin)
    logger.info("code_graph: lazy-installing rust toolchain for first Rust target")
    try:
        # rustup-init script: minimal profile (no docs/clippy/rustfmt),
        # stable channel, then add rust-analyzer component explicitly.
        _run(
            [
                "sh",
                "-c",
                "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs "
                "| sh -s -- -y --default-toolchain stable --profile minimal "
                "--no-modify-path",
            ],
            timeout=600,
        )
        _run(
            [
                "sh",
                "-c",
                "/home/pentester/.cargo/bin/rustup component add rust-analyzer",
            ],
            timeout=300,
        )
    except IndexerError as exc:
        logger.warning("code_graph: rust toolchain lazy-install failed (%s)", exc)
        return None
    if not (cargo_bin / "rust-analyzer").exists():
        logger.warning(
            "code_graph: rustup install reported success but rust-analyzer "
            "not at %s; check toolchain",
            cargo_bin,
        )
        return None
    return str(cargo_bin)


def _index_rust(target: Path, out_dir: Path) -> Path | None:
    """SCIP index for Rust projects via rust-analyzer's built-in `scip`
    subcommand (rust-analyzer >= 2024.x ships SCIP support natively).

    Detection: Cargo.toml. rust-analyzer is lazy-installed on first
    use to keep the sandbox image lean — see _ensure_rust_toolchain.
    Cleanup of target/ happens in the docker_runtime hook.
    """
    if not _has_files_matching(target, "Cargo.toml"):
        return None
    cargo_bin = _ensure_rust_toolchain()
    if not cargo_bin:
        raise IndexerError("rust toolchain unavailable for indexing")

    rust_analyzer = f"{cargo_bin}/rust-analyzer"
    cargo = f"{cargo_bin}/cargo"

    # Pre-fetch the crate graph. rust-analyzer's metadata pass would
    # otherwise stall on network; pulling crates explicitly with a
    # tight timeout fails fast on network issues without blocking
    # the indexer indefinitely.
    try:
        _run([cargo, "fetch"], cwd=target, timeout=300)
    except IndexerError as exc:
        logger.warning(
            "code_graph: cargo fetch failed (%s); rust-analyzer may emit "
            "partial scip without dep resolution",
            exc,
        )

    out = out_dir / "rs.scip"
    _run(
        [rust_analyzer, "scip", str(target), "--output", str(out)],
        cwd=target,
        timeout=600,
    )
    return out if out.exists() else None


def _convert_to_sqlite(scip_paths: tuple[Path, ...], out_dir: Path) -> Path:
    if not _binary_exists("scip"):
        raise IndexerError("scip CLI missing from sandbox")
    sqlite_path = out_dir / "code_graph.sqlite"
    # W1: single-language path. Multi-language merge ships in W2 — the SCIP
    # CLI's expt-convert takes one index at a time, so multi-lang repos will
    # need a small post-process to UNION the per-language tables.
    #
    # Try each .scip in priority order, using the first that converts
    # successfully. The fallback catches a real failure mode: scip-python
    # emits synthetic `_ScratchFile#` symbols (definition-occurrence with
    # no matching SymbolInformation), and `scip expt-convert`'s validator
    # rejects the whole file. Observed on seedcx/composite-actions#1142
    # (2026-06-08, missing SQLite then downstream hang on iter-2 startup).
    # When the Python index fails but other languages are present, this
    # gives the agent partial coverage instead of nothing.
    last_error: IndexerError | None = None
    for candidate in scip_paths:
        try:
            _run(["scip", "expt-convert", str(candidate), "--output", str(sqlite_path)])
        except IndexerError as exc:
            last_error = exc
            logger.warning(
                "code_graph: expt-convert failed on %s: %s",
                candidate.name,
                str(exc)[:300],
            )
            # Remove any partial output before next try — sqlite3 would
            # otherwise see a non-database file when we re-open later.
            sqlite_path.unlink(missing_ok=True)
            continue
        # Success.
        if candidate is not scip_paths[0]:
            logger.warning(
                "code_graph: primary scip %s failed conversion; used fallback %s",
                scip_paths[0].name,
                candidate.name,
            )
        elif len(scip_paths) > 1:
            logger.warning(
                "code_graph: multi-language indexes (%d) detected; only %s converted in W1",
                len(scip_paths),
                candidate.name,
            )
        return sqlite_path

    # All candidates failed conversion. Re-raise so _main() warn-and-
    # continues (INDEXER: SKIPPED → tool layer degrades to "code graph
    # unavailable", per the contract in W2.2's _open_index).
    raise last_error or IndexerError("no scip paths to convert")


def build_index(target_dir: Path, out_dir: Path) -> IndexResult:
    """Build SCIP indexes for the target repo, convert to SQLite.

    Detection is filename-based (tsconfig.json/package.json → TS; go.mod →
    Go). Multiple indexers run for multi-language repos but only the first
    is SQLite-converted in W1; W2 generalises the loader.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    scip_paths: list[Path] = []
    # Indexer order = priority. _convert_to_sqlite only consumes
    # scip_paths[0] today (W1 single-language path), so the first
    # language detected wins. TS first to match the common shape of
    # zh services (TS auth/business-logic with Python scripts);
    # multi-language merge is W5 follow-up.
    ts_index = _index_typescript(target_dir, out_dir)
    if ts_index is not None:
        scip_paths.append(ts_index)
    go_index = _index_go(target_dir, out_dir)
    if go_index is not None:
        scip_paths.append(go_index)
    py_index = _index_python(target_dir, out_dir)
    if py_index is not None:
        scip_paths.append(py_index)
    rs_index = _index_rust(target_dir, out_dir)
    if rs_index is not None:
        scip_paths.append(rs_index)

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


def build_index_cached(
    target_dir: Path,
    out_dir: Path,
    *,
    repo: str | None = None,
    head_sha: str | None = None,
    cache: CodeGraphCache | None = None,
) -> IndexResult:
    """Build the index, but consult the cache first when (repo, head_sha)
    are known. Cache miss falls through to a full build and a put."""
    cache = cache if cache is not None else _cache_from_env()
    sqlite_path = out_dir / "code_graph.sqlite"

    cache_key: CacheKey | None = None
    if repo and head_sha:
        try:
            cache_key = CacheKey(repo=repo, head_sha=head_sha)
        except ValueError as exc:
            logger.warning("code_graph: invalid cache key (%s); proceeding uncached", exc)

    if cache_key is not None and cache.get(cache_key, sqlite_path):
        return IndexResult(
            target_dir=target_dir,
            scip_paths=(),
            sqlite_path=sqlite_path,
        )

    result = build_index(target_dir, out_dir)
    if cache_key is not None:
        cache.put(cache_key, result.sqlite_path)
    return result


def _main(argv: list[str] | None = None) -> int:
    """Sandbox-side CLI: invoked by docker_runtime.create_sandbox after the
    target repo is copied into the container. Failure must not break the
    scan — exit 0 even on indexer error, just leave the SQLite missing and
    let the tools layer handle the absence (W2)."""
    # SEC-6848 diag: print() to stderr bypasses log-config no-op risk
    # (basicConfig is a no-op if any import already configured logging).
    # Keep these prints until SCIP is end-to-end-validated in GHA.
    print("INDEXER: _main entered", file=sys.stderr, flush=True)
    parser = argparse.ArgumentParser(
        prog="python -m strix.tools.code_graph.indexer",
        description="Build SCIP code-graph index for the target repo (SEC-6848 W1).",
    )
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--repo", default=None, help="owner/name, for cache key")
    parser.add_argument("--head-sha", default=None, help="full commit SHA, for cache key")
    args = parser.parse_args(argv)
    print(
        f"INDEXER: args target={args.target} out_dir={args.out_dir} "
        f"repo={args.repo} head_sha={args.head_sha}",
        file=sys.stderr,
        flush=True,
    )
    print(
        f"INDEXER: target.exists={args.target.exists()} "
        f"tsconfig={(args.target / 'tsconfig.json').exists()} "
        f"package.json={(args.target / 'package.json').exists()} "
        f"go.mod={(args.target / 'go.mod').exists()}",
        file=sys.stderr,
        flush=True,
    )

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        result = build_index_cached(
            args.target,
            args.out_dir,
            repo=args.repo,
            head_sha=args.head_sha,
        )
        print(
            f"INDEXER: SUCCESS sqlite={result.sqlite_path} "
            f"scip_paths={[str(p) for p in result.scip_paths]}",
            file=sys.stderr,
            flush=True,
        )
    except IndexerError as exc:
        # Warn-and-continue: a missing index means W2 graph tools degrade
        # to no-ops; it does not break the scan.
        print(f"INDEXER: SKIPPED ({exc})", file=sys.stderr, flush=True)
    except Exception as exc:  # noqa: BLE001
        # Diagnostic: surface any non-IndexerError exceptions to stderr
        # before re-raising. Without this they'd disappear silently.
        import traceback
        print(
            f"INDEXER: UNEXPECTED {type(exc).__name__}: {exc}\n{traceback.format_exc()}",
            file=sys.stderr,
            flush=True,
        )
        raise
    return 0


if __name__ == "__main__":
    sys.exit(_main())
