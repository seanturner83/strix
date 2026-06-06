"""Strix tool wrappers around the SCIP code-graph query layer (SEC-6848 W2.2).

Each function in this module is registered as an LLM-visible tool via
`register_tool`. They open the SQLite code-graph index (built at sandbox
setup time by `indexer.build_index_cached`) and call into the
`query.CodeGraphIndex` query primitives.

Failure modes:
  - No index present (sandbox indexer failed, target language unsupported):
    tools return a clear "code graph unavailable" output, NOT an error.
    The LLM may proceed using its normal grep/read_file path.
  - Symbol not found: empty result with "no matches" output.
  - Index file corrupted or query fails: error string returned.

All tools are parallel_safe — they hit a read-only SQLite handle and
don't mutate any sandbox state.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.tools.registry import register_tool

from .query import CodeGraphIndex


logger = logging.getLogger(__name__)

# Per-tool cap. The LLM-facing limit is conservative: a single graph
# query returning hundreds of locations is unhelpful, the LLM is better
# served by 50 and a follow-up if it needs more.
LLM_RESULT_LIMIT = 50


def _open_index() -> CodeGraphIndex | None:
    """Discover and open the code-graph index. Returns None if the indexer
    step didn't run for this scan — the tools then degrade to "no graph
    available" outputs rather than erroring out."""
    return CodeGraphIndex.discover()


def _render_unavailable() -> dict[str, Any]:
    return {
        "output": (
            "code graph not available for this target — indexer was "
            "skipped or unsupported language. Use search_files / "
            "list_files for structural questions."
        )
    }


def _render_no_matches(kind: str, query: str) -> dict[str, Any]:
    return {"output": f"no {kind} matches found for {query!r}"}


@register_tool(parallel_safe=True)
def code_graph_find_definition(symbol: str) -> dict[str, Any]:
    """Return file:line locations where `symbol` is defined in the
    indexed source tree."""
    idx = _open_index()
    if idx is None:
        return _render_unavailable()
    try:
        results = idx.find_definition(symbol, limit=LLM_RESULT_LIMIT)
    except Exception as exc:  # noqa: BLE001
        logger.warning("code_graph_find_definition failed: %s", exc)
        return {"error": f"code graph query failed: {exc}"}
    finally:
        idx.close()

    if not results:
        return _render_no_matches("definition", symbol)

    lines = [f"{m.display_name} defined at {loc.render()}" for m, loc in results]
    return {"output": "\n".join(lines)}


@register_tool(parallel_safe=True)
def code_graph_find_references(
    symbol: str, include_definition: bool = False
) -> dict[str, Any]:
    """Return file:line locations where `symbol` is referenced. The
    definition site is excluded unless include_definition=True."""
    idx = _open_index()
    if idx is None:
        return _render_unavailable()
    try:
        results = idx.find_references(
            symbol,
            limit=LLM_RESULT_LIMIT,
            include_definition=include_definition,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("code_graph_find_references failed: %s", exc)
        return {"error": f"code graph query failed: {exc}"}
    finally:
        idx.close()

    if not results:
        return _render_no_matches("reference", symbol)

    # Group by display_name so LIKE-collisions are obvious in the output.
    by_name: dict[str, list[str]] = {}
    for match, loc in results:
        by_name.setdefault(match.display_name, []).append(loc.render())

    blocks: list[str] = []
    for name, locs in by_name.items():
        blocks.append(f"{name} — {len(locs)} occurrence(s):")
        blocks.extend(f"  {loc}" for loc in locs)
    if len(results) >= LLM_RESULT_LIMIT:
        blocks.append(
            f"… result capped at {LLM_RESULT_LIMIT}; narrow the symbol "
            "name for more precise matches."
        )
    return {"output": "\n".join(blocks)}


@register_tool(parallel_safe=True)
def code_graph_find_implementations(interface: str) -> dict[str, Any]:
    """Return implementations / subtypes of `interface`. Reads the SCIP
    `global_symbols.relationships` blob and surfaces symbols whose
    Relationship records flag is_implementation=true pointing at the
    target interface or class."""
    idx = _open_index()
    if idx is None:
        return _render_unavailable()
    try:
        results = idx.find_implementations(interface, limit=LLM_RESULT_LIMIT)
    except Exception as exc:  # noqa: BLE001
        logger.warning("code_graph_find_implementations failed: %s", exc)
        return {"error": f"code graph query failed: {exc}"}
    finally:
        idx.close()

    if not results:
        return _render_no_matches("implementation", interface)

    lines = [f"{m.display_name} implements {interface} at {loc.render()}" for m, loc in results]
    if len(results) >= LLM_RESULT_LIMIT:
        lines.append(
            f"… result capped at {LLM_RESULT_LIMIT}; narrow the interface "
            "name for more precise matches."
        )
    return {"output": "\n".join(lines)}


@register_tool(parallel_safe=True)
def code_graph_list_symbols(scope: str) -> dict[str, Any]:
    """List symbols defined under a file or directory path. Useful for
    "what's in this module" triage without reading the whole file —
    returns symbol name + definition file:line per row.

    `scope` can be a single file path (e.g. "src/auth/middlewares.ts")
    or a directory prefix (e.g. "src/auth/"). Matching is by path
    prefix on the indexed document's relative_path."""
    idx = _open_index()
    if idx is None:
        return _render_unavailable()
    try:
        results = idx.list_symbols(scope, limit=LLM_RESULT_LIMIT)
    except Exception as exc:  # noqa: BLE001
        logger.warning("code_graph_list_symbols failed: %s", exc)
        return {"error": f"code graph query failed: {exc}"}
    finally:
        idx.close()

    if not results:
        return _render_no_matches("symbol under", scope)

    # Group by file so output stays compact for directory queries
    by_file: dict[str, list[str]] = {}
    for match, loc in results:
        by_file.setdefault(loc.relative_path, []).append(
            f"{match.display_name} (line {loc.start_line})"
        )

    blocks: list[str] = []
    for path, syms in by_file.items():
        blocks.append(f"{path}:")
        blocks.extend(f"  {s}" for s in syms)
    if len(results) >= LLM_RESULT_LIMIT:
        blocks.append(
            f"… result capped at {LLM_RESULT_LIMIT}; narrow the scope "
            "to a deeper subdirectory or specific file."
        )
    return {"output": "\n".join(blocks)}


@register_tool(parallel_safe=True)
def code_graph_get_imports(file: str) -> dict[str, Any]:
    """Return the global symbols referenced from `file`. This is a
    superset of imports (includes in-file references to external
    symbols) but answers "what does this file depend on"."""
    idx = _open_index()
    if idx is None:
        return _render_unavailable()
    try:
        imports = idx.get_imports(file, limit=LLM_RESULT_LIMIT)
    except Exception as exc:  # noqa: BLE001
        logger.warning("code_graph_get_imports failed: %s", exc)
        return {"error": f"code graph query failed: {exc}"}
    finally:
        idx.close()

    if not imports:
        return _render_no_matches("imports/references", file)

    names = sorted({m.display_name for m in imports})
    if len(names) >= LLM_RESULT_LIMIT:
        return {
            "output": (
                f"{file}: {len(names)} referenced symbols (showing "
                f"first {LLM_RESULT_LIMIT}):\n  " + "\n  ".join(names)
            )
        }
    return {"output": f"{file} references:\n  " + "\n  ".join(names)}


@register_tool(parallel_safe=True)
def code_graph_get_symbol_at(file: str, line: int) -> dict[str, Any]:
    """Return the symbols mentioned in the chunk that contains `line` in
    `file`. Useful for "what is this code talking about" inquiries
    without having to read the whole file."""
    idx = _open_index()
    if idx is None:
        return _render_unavailable()
    try:
        symbols = idx.get_symbol_at(file, line)
    except Exception as exc:  # noqa: BLE001
        logger.warning("code_graph_get_symbol_at failed: %s", exc)
        return {"error": f"code graph query failed: {exc}"}
    finally:
        idx.close()

    if not symbols:
        return _render_no_matches("symbol", f"{file}:{line}")

    names = sorted({m.display_name for m in symbols})
    return {"output": f"{file}:{line} mentions:\n  " + "\n  ".join(names)}
