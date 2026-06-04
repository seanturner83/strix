# SEC-6848 Tier 2: SCIP-backed code graph tools.
#
# W1 (shipped): SCIP indexer install in sandbox image + indexer module +
#               cache abstraction + docker_runtime wiring to build the
#               index at sandbox setup.
# W2 (this  ): SQLite query layer + 5 LLM-visible tools registered with
#               the Strix tool registry.
# W3-W6 (TBD): SCIP relationship-blob parsing for find_implementations;
#               prompt-side guidance to prefer graph over grep; e2e
#               validation; scip-python; broader rollout.

from .cache import CacheKey, CodeGraphCache, FilesystemCache, NullCache
from .code_graph_actions import (
    code_graph_find_definition,
    code_graph_find_implementations,
    code_graph_find_references,
    code_graph_get_imports,
    code_graph_get_symbol_at,
)
from .indexer import build_index, build_index_cached, load_index
from .query import CodeGraphIndex, Location, SymbolMatch


__all__ = [
    "CacheKey",
    "CodeGraphCache",
    "CodeGraphIndex",
    "FilesystemCache",
    "Location",
    "NullCache",
    "SymbolMatch",
    "build_index",
    "build_index_cached",
    "code_graph_find_definition",
    "code_graph_find_implementations",
    "code_graph_find_references",
    "code_graph_get_imports",
    "code_graph_get_symbol_at",
    "load_index",
]
