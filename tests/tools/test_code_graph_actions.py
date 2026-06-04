"""Unit tests for the Strix tool wrappers around the code-graph query
layer (SEC-6848 W2.2). Verifies the LLM-facing output shape and the
graceful-degradation paths.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from strix.tools.code_graph import code_graph_actions
from strix.tools.code_graph.code_graph_actions import (
    code_graph_find_definition,
    code_graph_find_implementations,
    code_graph_find_references,
    code_graph_get_imports,
    code_graph_get_symbol_at,
)


# Reuse the synthetic-index fixture shape from test_code_graph_query.py
# (kept independent to avoid cross-test-file fixture coupling).
SCHEMA_SQL = """
CREATE TABLE documents (
    id INTEGER PRIMARY KEY,
    language TEXT,
    relative_path TEXT NOT NULL UNIQUE,
    position_encoding TEXT,
    text TEXT
);
CREATE TABLE chunks (
    id INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL,
    chunk_index INTEGER NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    occurrences BLOB NOT NULL
);
CREATE TABLE global_symbols (
    id INTEGER PRIMARY KEY,
    symbol TEXT NOT NULL UNIQUE,
    display_name TEXT,
    kind INTEGER,
    documentation TEXT,
    signature BLOB,
    enclosing_symbol TEXT,
    relationships BLOB
);
CREATE TABLE mentions (
    chunk_id INTEGER NOT NULL,
    symbol_id INTEGER NOT NULL,
    role INTEGER NOT NULL,
    PRIMARY KEY (chunk_id, symbol_id, role)
);
CREATE TABLE defn_enclosing_ranges (
    id INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL,
    symbol_id INTEGER NOT NULL,
    start_line INTEGER NOT NULL,
    start_char INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    end_char INTEGER NOT NULL
);
"""


@pytest.fixture
def fake_index_root(tmp_path: Path) -> Path:
    root = tmp_path / "code_graph" / "portal-api"
    root.mkdir(parents=True)
    db_path = root / "code_graph.sqlite"
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    auth_prefix = "scip-typescript npm portal-api HEAD src/auth/`index.ts`/"
    conn.executemany(
        "INSERT INTO documents (id, language, relative_path, position_encoding) VALUES (?,?,?,?)",
        [
            (1, "typescript", "src/auth/index.ts", "utf8"),
            (2, "typescript", "src/transfers/router.ts", "utf8"),
        ],
    )
    conn.executemany(
        "INSERT INTO global_symbols (id, symbol) VALUES (?, ?)",
        [
            (10, auth_prefix + "authorizeToParticipantAndAdminRole."),
            (11, auth_prefix + "userExists."),
        ],
    )
    conn.executemany(
        "INSERT INTO chunks (id, document_id, chunk_index, start_line, end_line, occurrences) VALUES (?,?,?,?,?,?)",
        [
            (100, 1, 0, 0, 50, b""),
            (101, 2, 0, 0, 100, b""),
        ],
    )
    conn.executemany(
        "INSERT INTO mentions (chunk_id, symbol_id, role) VALUES (?, ?, ?)",
        [
            (100, 10, 1),  # def in auth/index.ts
            (101, 10, 0),  # ref in transfers/router.ts
            (101, 11, 0),  # userExists also referenced there
        ],
    )
    conn.execute(
        "INSERT INTO defn_enclosing_ranges (id, document_id, symbol_id, start_line, start_char, end_line, end_char) VALUES (1, 1, 10, 12, 0, 18, 1)"
    )
    conn.commit()
    conn.close()
    return tmp_path / "code_graph"


@pytest.fixture
def patched_discover(monkeypatch: pytest.MonkeyPatch, fake_index_root: Path):
    """Make CodeGraphIndex.discover() use the fixture root."""
    from strix.tools.code_graph.query import CodeGraphIndex
    original = CodeGraphIndex.discover

    def _discover(root=None):
        return original(fake_index_root)

    monkeypatch.setattr(CodeGraphIndex, "discover", classmethod(lambda cls, root=None: original(fake_index_root)))
    return fake_index_root


# ---------------------------------------------------------------------------
# Unavailable path: no index found
# ---------------------------------------------------------------------------


def test_find_definition_unavailable_when_no_index(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(code_graph_actions, "_open_index", lambda: None)
    result = code_graph_find_definition("foo")
    assert "code graph not available" in result["output"]


def test_find_references_unavailable_when_no_index(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(code_graph_actions, "_open_index", lambda: None)
    result = code_graph_find_references("foo")
    assert "code graph not available" in result["output"]


def test_get_imports_unavailable_when_no_index(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(code_graph_actions, "_open_index", lambda: None)
    result = code_graph_get_imports("src/foo.ts")
    assert "code graph not available" in result["output"]


def test_get_symbol_at_unavailable_when_no_index(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(code_graph_actions, "_open_index", lambda: None)
    result = code_graph_get_symbol_at("src/foo.ts", 10)
    assert "code graph not available" in result["output"]


# ---------------------------------------------------------------------------
# find_implementations is always a stub in W2
# ---------------------------------------------------------------------------


def test_find_implementations_returns_stub_message() -> None:
    result = code_graph_find_implementations("AnyInterface")
    assert "not yet supported" in result["output"]
    assert "find_references" in result["output"]


# ---------------------------------------------------------------------------
# Real queries against the fixture index
# ---------------------------------------------------------------------------


def test_find_definition_returns_location(patched_discover) -> None:
    result = code_graph_find_definition("authorizeToParticipantAndAdminRole")
    assert "src/auth/index.ts:12:0" in result["output"]
    assert "authorizeToParticipantAndAdminRole defined" in result["output"]


def test_find_references_excludes_def(patched_discover) -> None:
    result = code_graph_find_references("authorizeToParticipantAndAdminRole")
    assert "src/transfers/router.ts" in result["output"]
    assert "src/auth/index.ts" not in result["output"]
    assert "occurrence" in result["output"]


def test_find_references_can_include_def(patched_discover) -> None:
    result = code_graph_find_references(
        "authorizeToParticipantAndAdminRole", include_definition=True
    )
    assert "src/auth/index.ts" in result["output"]
    assert "src/transfers/router.ts" in result["output"]


def test_find_references_unknown_symbol(patched_discover) -> None:
    result = code_graph_find_references("doesNotExistAnywhere")
    assert "no reference matches" in result["output"]


def test_get_imports_lists_referenced_symbols(patched_discover) -> None:
    result = code_graph_get_imports("src/transfers/router.ts")
    assert "authorizeToParticipantAndAdminRole" in result["output"]
    assert "userExists" in result["output"]


def test_get_imports_unknown_file(patched_discover) -> None:
    result = code_graph_get_imports("src/missing.ts")
    assert "no imports/references" in result["output"]


def test_get_symbol_at_inside_chunk(patched_discover) -> None:
    result = code_graph_get_symbol_at("src/transfers/router.ts", 50)
    assert "authorizeToParticipantAndAdminRole" in result["output"]
    assert "userExists" in result["output"]


def test_get_symbol_at_outside_chunk(patched_discover) -> None:
    result = code_graph_get_symbol_at("src/transfers/router.ts", 9999)
    assert "no symbol matches" in result["output"]


# ---------------------------------------------------------------------------
# Tool registration smoke
# ---------------------------------------------------------------------------


def test_tools_are_registered_with_registry() -> None:
    """The 5 tools should be reachable via the Strix tool registry by
    name, with the expected XML schema attached when running outside
    sandbox mode."""
    from strix.tools.registry import tools

    registered_names = {t["name"] for t in tools}
    expected = {
        "code_graph_find_definition",
        "code_graph_find_references",
        "code_graph_find_implementations",
        "code_graph_get_imports",
        "code_graph_get_symbol_at",
    }
    missing = expected - registered_names
    assert not missing, f"missing registrations: {missing}"
