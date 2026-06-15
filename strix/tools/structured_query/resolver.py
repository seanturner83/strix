"""Line-accurate path resolution for YAML / JSON / structured config files.

The inverse of code_graph_get_symbol_at: given a structural PATH into a
YAML or JSON document, return the value AND its 1-based line range. This
is what lets the agent cite a real file:line for findings in workflow /
IaC / config files — closing the structured-file slice of the
location-quality gap (most such findings historically dropped to the
synthetic SECURITY.md anchor because the agent had no way to map a node
to a line).

Dependency stance: PyYAML (already in the sandbox) + stdlib json ONLY.
No ruamel, no jsonpath_ng — the sandbox image is kept lean. PyYAML's
node start_mark/end_mark give exact line spans, including multi-line
block scalars (`run: |`), which is the common workflow case.

Path syntax (deliberately tiny, not full JSONPath):
    a.b.c            mapping keys
    a.b[2]           sequence index
    a.b[2].c         mixed
Keys containing '.' or '[' are not expressible — callers needing those
should use structured_find (regex over keys) instead.
"""

from __future__ import annotations

import json
import re
from typing import Any

import yaml

_TOKEN = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def parse_path(path: str) -> list[str | int]:
    """Parse 'a.b[2].c' into ['a','b',2,'c']. Raises ValueError on garbage."""
    parts: list[str | int] = []
    pos = 0
    s = path.strip()
    if not s:
        return parts
    for m in _TOKEN.finditer(s):
        if m.start() != pos:
            raise ValueError(f"unparseable path near offset {pos}: {path!r}")
        key, idx = m.group(1), m.group(2)
        parts.append(int(idx) if idx is not None else key)
        pos = m.end()
        # tolerate a single '.' separator between tokens
        if pos < len(s) and s[pos] == ".":
            pos += 1
    if pos != len(s):
        raise ValueError(f"trailing characters in path: {path!r}")
    return parts


# --------------------------------------------------------------------------
# YAML — PyYAML node tree carries start_mark/end_mark (0-based lines).
# --------------------------------------------------------------------------
def _yaml_node(text: str) -> yaml.nodes.Node | None:
    loader = yaml.SafeLoader(text)
    try:
        return loader.get_single_node()
    finally:
        loader.dispose()


def _descend_yaml(node: yaml.nodes.Node, parts: list[str | int]) -> yaml.nodes.Node | None:
    cur = node
    for p in parts:
        if isinstance(p, int):
            if not isinstance(cur, yaml.SequenceNode) or p >= len(cur.value):
                return None
            cur = cur.value[p]
        else:
            if not isinstance(cur, yaml.MappingNode):
                return None
            found = None
            for k, v in cur.value:
                if getattr(k, "value", None) == p:
                    found = v
                    break
            if found is None:
                return None
            cur = found
    return cur


def _yaml_end_line(node: yaml.nodes.Node) -> int:
    """1-based last line of a YAML node, correcting PyYAML's end_mark.

    PyYAML's end_mark for a block node points at the START of the following
    content (column 0 of the next line) rather than the node's own last
    line. When end_mark.column == 0 the node ended at a line boundary, so
    the true last content line is end_mark.line - 1. Inline/flow scalars
    end mid-line (column > 0) and need no correction. Clamp to >= start.
    """
    end = node.end_mark.line
    if node.end_mark.column == 0 and end > node.start_mark.line:
        end -= 1
    return max(end, node.start_mark.line) + 1


def _node_text(text: str, node: yaml.nodes.Node) -> str:
    lines = text.splitlines()
    s = node.start_mark.line
    e = _yaml_end_line(node) - 1  # back to 0-based inclusive
    return "\n".join(lines[s : e + 1])


# --------------------------------------------------------------------------
# JSON — stdlib json has no line info, so build an offset→line index and a
# parallel position tree via a minimal scanner over json.JSONDecoder.
# We re-walk with raw_decode tracking, but the cheap robust approach is to
# parse to Python, then locate the path's value span by re-scanning. For
# the tool's purpose (cite a line) we use a token-position decoder.
# --------------------------------------------------------------------------
def _json_line_index(text: str) -> list[int]:
    """Return a list mapping char-offset -> 1-based line (prefix-sum of \n)."""
    idx = [1]
    line = 1
    for ch in text:
        if ch == "\n":
            line += 1
        idx.append(line)
    return idx


class _PosDecoder(json.JSONDecoder):
    """JSONDecoder that records (start,end) char offsets for every container
    and scalar it parses, keyed by id() of the produced object. Scalars are
    immutable/deduped in CPython so we instead capture during scan_once."""


def _json_value_span(text: str, parts: list[str | int]) -> tuple[int, int] | None:
    """Best-effort char-span of the value at `parts`. Walk with a custom
    object_pairs_hook / array tracking is complex; instead we re-tokenise.
    Strategy: decode to data to validate the path exists, then re-find the
    span by structural scanning. For robustness we use a streaming approach
    over json's raw_decode on progressively narrowed substrings."""
    # Validate path against decoded data first.
    data = json.loads(text)
    cur: Any = data
    for p in parts:
        try:
            cur = cur[p]
        except (KeyError, IndexError, TypeError):
            return None
    # Re-scan: find the byte span of the value. We reproduce the path by
    # walking the raw text with a brace/bracket-aware scanner.
    return _scan_span(text, parts)


def _scan_span(text: str, parts: list[str | int]) -> tuple[int, int] | None:
    """Walk JSON text following `parts`, returning the (start,end) offsets of
    the targeted value. Uses json.JSONDecoder.raw_decode to measure spans."""
    dec = json.JSONDecoder()

    def skip_ws(s: str, i: int) -> int:
        while i < len(s) and s[i] in " \t\r\n":
            i += 1
        return i

    def value_span(s: str, i: int) -> tuple[int, int]:
        i = skip_ws(s, i)
        _, end = dec.raw_decode(s, i)
        return i, end

    def find_in(s: str, i: int, parts: list[str | int]) -> tuple[int, int] | None:
        if not parts:
            return value_span(s, i)
        i = skip_ws(s, i)
        head, rest = parts[0], parts[1:]
        if isinstance(head, int):
            if i >= len(s) or s[i] != "[":
                return None
            i += 1
            k = 0
            while True:
                i = skip_ws(s, i)
                if i < len(s) and s[i] == "]":
                    return None
                vs, ve = value_span(s, i)
                if k == head:
                    if not rest:
                        return vs, ve
                    return find_in(s, vs, rest)
                i = skip_ws(s, ve)
                if i < len(s) and s[i] == ",":
                    i += 1
                    k += 1
                    continue
                return None
        else:
            if i >= len(s) or s[i] != "{":
                return None
            i += 1
            while True:
                i = skip_ws(s, i)
                if i < len(s) and s[i] == "}":
                    return None
                kstart, kend = value_span(s, i)  # the key string
                key = json.loads(s[kstart:kend])
                i = skip_ws(s, kend)
                if i >= len(s) or s[i] != ":":
                    return None
                i += 1
                vs, ve = value_span(s, i)
                if key == head:
                    if not rest:
                        return vs, ve
                    return find_in(s, vs, rest)
                i = skip_ws(s, ve)
                if i < len(s) and s[i] == ",":
                    i += 1
                    continue
                return None

    try:
        return find_in(text, 0, parts)
    except (json.JSONDecodeError, ValueError):
        return None


# --------------------------------------------------------------------------
# Public resolver
# --------------------------------------------------------------------------
def resolve(text: str, path: str, *, is_json: bool) -> dict[str, Any] | None:
    """Resolve `path` in `text`. Returns {value, start_line, end_line, snippet}
    or None if the path doesn't exist. Raises ValueError on a malformed path."""
    parts = parse_path(path)
    if is_json:
        span = _json_value_span(text, parts)
        if span is None:
            return None
        start_off, end_off = span
        lineidx = _json_line_index(text)
        start_line = lineidx[start_off]
        end_line = lineidx[min(end_off, len(text))]
        snippet = text[start_off:end_off]
        value = json.loads(snippet) if snippet.strip() else None
        return {
            "value": value,
            "start_line": start_line,
            "end_line": end_line,
            "snippet": snippet,
        }
    node = _yaml_node(text)
    if node is None:
        return None
    target = _descend_yaml(node, parts)
    if target is None:
        return None
    snippet = _node_text(text, target)
    return {
        "value": _yaml_value(target),
        "start_line": target.start_mark.line + 1,
        "end_line": _yaml_end_line(target),
        "snippet": snippet,
    }


def _yaml_value(node: yaml.nodes.Node) -> Any:
    """Construct the Python value for a node (used for the value field)."""
    try:
        return yaml.SafeLoader(yaml.serialize(node)).get_single_data()
    except Exception:  # noqa: BLE001
        return getattr(node, "value", None)


def find(text: str, key_regex: str, *, is_json: bool, max_hits: int = 50) -> list[dict[str, Any]]:
    """Return every node whose KEY matches `key_regex`, with line range.
    For 'where is X defined / how many places set Y'. YAML only walks
    mapping keys; JSON walks object keys."""
    pat = re.compile(key_regex)
    hits: list[dict[str, Any]] = []

    if is_json:
        # Walk decoded structure with offsets via the scanner per match path.
        data = json.loads(text)

        def walk_json(obj: Any, path: list[str | int]) -> None:
            if len(hits) >= max_hits:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if pat.search(str(k)):
                        span = _scan_span(text, [*path, k])
                        if span:
                            li = _json_line_index(text)
                            hits.append({
                                "path": _fmt_path([*path, k]),
                                "start_line": li[span[0]],
                                "end_line": li[min(span[1], len(text))],
                            })
                    walk_json(v, [*path, k])
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    walk_json(v, [*path, i])

        walk_json(data, [])
        return hits

    node = _yaml_node(text)
    if node is None:
        return hits

    def walk_yaml(n: yaml.nodes.Node, path: list[str | int]) -> None:
        if len(hits) >= max_hits:
            return
        if isinstance(n, yaml.MappingNode):
            for k, v in n.value:
                kname = getattr(k, "value", "")
                if pat.search(str(kname)):
                    hits.append({
                        "path": _fmt_path([*path, kname]),
                        "start_line": v.start_mark.line + 1,
                        "end_line": _yaml_end_line(v),
                    })
                walk_yaml(v, [*path, kname])
        elif isinstance(n, yaml.SequenceNode):
            for i, item in enumerate(n.value):
                walk_yaml(item, [*path, i])

    walk_yaml(node, [])
    return hits


def _fmt_path(parts: list[str | int]) -> str:
    out = ""
    for p in parts:
        out += f"[{p}]" if isinstance(p, int) else (f".{p}" if out else str(p))
    return out
