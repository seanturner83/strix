"""SQLite-backed code-graph query layer (SEC-6848 W2.1).

Opens the SQLite index produced by `indexer.build_index` and exposes the
five primitives the Strix tool layer needs:

  * find_definition(symbol)      → file:line:col where the symbol is defined
  * find_references(symbol)      → file:line ranges where it's used
  * find_implementations(iface)  → defs of subtypes (W2: relationship-blob
                                   parsing deferred; W2 stubs and returns
                                   empty list)
  * get_imports(file)            → other symbols this file imports
  * get_symbol_at(file, line)    → symbol moniker at that line

SCIP SQLite schema (produced by `scip expt-convert`):
  documents(id, language, relative_path, position_encoding, text)
  global_symbols(id, symbol, display_name, kind, documentation, ...)
  chunks(id, document_id, chunk_index, start_line, end_line, occurrences)
  mentions(chunk_id, symbol_id, role)         -- role 1=def, 0=ref
  defn_enclosing_ranges(symbol_id, document_id, start_line, start_char,
                        end_line, end_char)    -- not populated for every
                                                  symbol (re-exports lack
                                                  bodies); fall back to
                                                  mentions+chunks.

Design notes:
  * Symbol monikers in SCIP look like
      "scip-typescript npm portal-api HEAD src/auth/`index.ts`/foo."
    The LLM will query with bare names like "authorizeToParticipantAndAdminRole".
    We match via LIKE %name% which is fast enough at our scale (~5k symbols
    per repo); the moniker has its own indexed column.
  * SCIP's role enum is a bitfield in the spec but expt-convert collapses
    to 0/1 in practice. Treat 1 as definition, 0 as reference.
  * Results capped at MAX_ROWS per call. Higher limits are available via
    explicit kwarg for callers that need them (tests), but the LLM-facing
    tool wrappers (W2.2) lock the cap.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


logger = logging.getLogger(__name__)


MAX_ROWS = 50


# SCIP role flags. We only see two distinct values from expt-convert but
# keep the constants named so the call sites read clearly.
ROLE_REFERENCE = 0
ROLE_DEFINITION = 1


@dataclass(frozen=True)
class Location:
    """A file + line range. For find_definition we have precise start_char
    when defn_enclosing_ranges is populated; otherwise we fall back to the
    chunk's line range and start_char is None."""

    file: str
    start_line: int
    end_line: int
    start_char: int | None = None
    end_char: int | None = None

    def render(self) -> str:
        if self.start_char is not None:
            return f"{self.file}:{self.start_line}:{self.start_char}"
        if self.start_line == self.end_line:
            return f"{self.file}:{self.start_line}"
        return f"{self.file}:{self.start_line}-{self.end_line}"


@dataclass(frozen=True)
class SymbolMatch:
    """A symbol moniker the index knows about. `display_name` is what we
    extract from the tail of the moniker (scip-typescript leaves the
    proper display_name column empty)."""

    symbol: str
    display_name: str


class CodeGraphIndex:
    """Read-only handle on a SCIP-converted SQLite index."""

    def __init__(self, sqlite_path: Path) -> None:
        if not sqlite_path.exists():
            raise FileNotFoundError(f"code_graph index missing at {sqlite_path}")
        # uri=true + mode=ro: prevent accidental writes; SQLite will
        # surface readonly attempts as exceptions.
        uri = f"file:{sqlite_path}?mode=ro"
        self._conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.sqlite_path = sqlite_path

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        cur = self._conn.cursor()
        try:
            yield cur
        finally:
            cur.close()

    @staticmethod
    def _extract_display_name(symbol: str) -> str:
        """SCIP monikers look like
              "scip-typescript npm portal-api HEAD src/foo/`bar.ts`/baz."
        The trailing token after the last `/` or `` ` `` is the identifier
        the LLM will query for. We strip the trailing scip-suffix sigil
        (`.`, `#`, `()` if present) so equality compares cleanly.
        """
        tail = symbol.rstrip(".#()/")
        # Symbol fragments are separated by `/`. Take the rightmost.
        if "/" in tail:
            tail = tail.rsplit("/", 1)[-1]
        # scip-typescript wraps file names in backticks; strip if leftover.
        return tail.strip("`")

    def _resolve_symbol(self, name: str) -> list[SymbolMatch]:
        """Find global_symbols rows whose moniker contains `name` as a
        token. Returns up to MAX_ROWS matches sorted by symbol length
        (shorter = more specific match first, since trailing extras
        like `.` `()` make canonical names slightly longer)."""
        like = f"%{name}%"
        with self._cursor() as cur:
            cur.execute(
                "SELECT symbol FROM global_symbols WHERE symbol LIKE ? "
                "ORDER BY LENGTH(symbol) ASC LIMIT ?",
                (like, MAX_ROWS),
            )
            rows = cur.fetchall()
        matches = [
            SymbolMatch(symbol=row["symbol"], display_name=self._extract_display_name(row["symbol"]))
            for row in rows
        ]
        # Exact display-name match wins; everything else stays in length
        # order. The LLM tool wrapper presents only exact matches by
        # default and exposes "did-you-mean" partials via a separate
        # listing.
        exact = [m for m in matches if m.display_name == name]
        partial = [m for m in matches if m.display_name != name]
        return exact + partial

    # ------------------------------------------------------------------
    # Public query methods (called by the W2.2 tool wrappers)
    # ------------------------------------------------------------------

    def find_definition(
        self, name: str, *, limit: int = MAX_ROWS
    ) -> list[tuple[SymbolMatch, Location]]:
        """Return (symbol, location) pairs for definitions matching `name`.

        Prefers `defn_enclosing_ranges` (precise file:line:col) but falls
        back to mentions with role=1 + chunk range when ranges are absent
        (common for re-exports and barrel files).
        """
        results: list[tuple[SymbolMatch, Location]] = []
        for match in self._resolve_symbol(name):
            with self._cursor() as cur:
                # Try defn_enclosing_ranges first.
                cur.execute(
                    """
                    SELECT d.relative_path, der.start_line, der.start_char,
                           der.end_line, der.end_char
                    FROM defn_enclosing_ranges der
                    JOIN documents d  ON d.id = der.document_id
                    JOIN global_symbols gs ON gs.id = der.symbol_id
                    WHERE gs.symbol = ?
                    LIMIT ?
                    """,
                    (match.symbol, limit),
                )
                rows = cur.fetchall()
                if rows:
                    for r in rows:
                        results.append((
                            match,
                            Location(
                                file=r["relative_path"],
                                start_line=r["start_line"],
                                start_char=r["start_char"],
                                end_line=r["end_line"],
                                end_char=r["end_char"],
                            ),
                        ))
                    continue
                # Fall back: definition via mentions role=1.
                cur.execute(
                    """
                    SELECT d.relative_path, c.start_line, c.end_line
                    FROM mentions m
                    JOIN chunks c     ON c.id = m.chunk_id
                    JOIN documents d  ON d.id = c.document_id
                    JOIN global_symbols gs ON gs.id = m.symbol_id
                    WHERE gs.symbol = ? AND m.role = ?
                    ORDER BY d.relative_path, c.start_line
                    LIMIT ?
                    """,
                    (match.symbol, ROLE_DEFINITION, limit),
                )
                for r in cur.fetchall():
                    results.append((
                        match,
                        Location(
                            file=r["relative_path"],
                            start_line=r["start_line"],
                            end_line=r["end_line"],
                        ),
                    ))
            if len(results) >= limit:
                break
        return results[:limit]

    def find_references(
        self, name: str, *, limit: int = MAX_ROWS, include_definition: bool = False
    ) -> list[tuple[SymbolMatch, Location]]:
        """Return all references (role=0) to symbols matching `name`. The
        definition site is excluded unless `include_definition` is set."""
        results: list[tuple[SymbolMatch, Location]] = []
        role_filter = (ROLE_REFERENCE, ROLE_DEFINITION) if include_definition else (ROLE_REFERENCE,)
        placeholders = ",".join("?" for _ in role_filter)

        for match in self._resolve_symbol(name):
            with self._cursor() as cur:
                cur.execute(
                    f"""
                    SELECT d.relative_path, c.start_line, c.end_line
                    FROM mentions m
                    JOIN chunks c     ON c.id = m.chunk_id
                    JOIN documents d  ON d.id = c.document_id
                    JOIN global_symbols gs ON gs.id = m.symbol_id
                    WHERE gs.symbol = ? AND m.role IN ({placeholders})
                    ORDER BY d.relative_path, c.start_line
                    LIMIT ?
                    """,
                    (match.symbol, *role_filter, limit),
                )
                for r in cur.fetchall():
                    results.append((
                        match,
                        Location(
                            file=r["relative_path"],
                            start_line=r["start_line"],
                            end_line=r["end_line"],
                        ),
                    ))
            if len(results) >= limit:
                break
        return results[:limit]

    def find_implementations(
        self, name: str, *, limit: int = MAX_ROWS
    ) -> list[tuple[SymbolMatch, Location]]:
        """W2 stub: SCIP encodes implementor/subtype relationships in the
        `global_symbols.relationships` BLOB (protobuf-encoded). Parsing
        the blob is W3 territory; for W2 the tool returns no results and
        the W2.2 wrapper communicates this clearly."""
        del name, limit  # Intentionally unused until W3.
        return []

    def get_imports(self, file: str, *, limit: int = MAX_ROWS) -> list[SymbolMatch]:
        """Return the global symbols mentioned in `file`. SCIP doesn't tag
        imports specifically; what we can do without decoding the
        occurrences blob is enumerate distinct symbols referenced from
        that file's chunks. That's a superset of imports (includes
        in-file refs to globals) but useful for "what does this file
        depend on" questions."""
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT gs.symbol
                FROM mentions m
                JOIN chunks c    ON c.id = m.chunk_id
                JOIN documents d ON d.id = c.document_id
                JOIN global_symbols gs ON gs.id = m.symbol_id
                WHERE d.relative_path = ? AND m.role = ?
                ORDER BY gs.symbol
                LIMIT ?
                """,
                (file, ROLE_REFERENCE, limit),
            )
            return [
                SymbolMatch(symbol=r["symbol"], display_name=self._extract_display_name(r["symbol"]))
                for r in cur.fetchall()
            ]

    def get_symbol_at(self, file: str, line: int) -> list[SymbolMatch]:
        """Return the symbols mentioned in the chunk that contains `line`
        in `file`. Coarser than what an IDE gives you — we return every
        symbol in the chunk rather than the one under the cursor —
        because we don't decode the occurrence blob in W2. Still useful
        for 'what is this code talking about' lookups."""
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT gs.symbol
                FROM chunks c
                JOIN documents d  ON d.id = c.document_id
                JOIN mentions m   ON m.chunk_id = c.id
                JOIN global_symbols gs ON gs.id = m.symbol_id
                WHERE d.relative_path = ?
                  AND c.start_line <= ? AND c.end_line >= ?
                ORDER BY gs.symbol
                LIMIT ?
                """,
                (file, line, line, MAX_ROWS),
            )
            return [
                SymbolMatch(symbol=r["symbol"], display_name=self._extract_display_name(r["symbol"]))
                for r in cur.fetchall()
            ]

    # ------------------------------------------------------------------
    # Index discovery helpers
    # ------------------------------------------------------------------

    @classmethod
    def discover(cls, root: Path = Path("/app/runtime/code_graph")) -> "CodeGraphIndex | None":
        """Find the most-recently-built index under `root` and open it.

        Returns None if no index exists — the W2.2 tool wrappers degrade
        gracefully to "code graph unavailable" when this is the case
        (eg. the sandbox's indexer step failed or was skipped).
        """
        if not root.exists():
            return None
        candidates = sorted(
            root.glob("*/code_graph.sqlite"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            return None
        return cls(candidates[0])
