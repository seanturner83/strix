"""LLM-visible tools for line-accurate querying of YAML / JSON config files.

The inverse of code_graph_get_symbol_at: map a structural path to its
value AND line range, so the agent can cite a real file:line for findings
in workflow / IaC / config files instead of falling back to the synthetic
SECURITY.md anchor. Closes the structured-file slice of the
location-quality gap (project_strix_location_quality_audit_20260615).

Backed by tools.structured_query.resolver — PyYAML + stdlib json only,
no new sandbox dependencies.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool
from strix.tools.structured_query import resolver

logger = logging.getLogger(__name__)

_YAML_EXTS = (".yml", ".yaml")
_JSON_EXTS = (".json",)
# Files we know how to line-resolve. .tf/.hcl are NOT JSON/YAML (HCL) — only
# .tf.json is. Keep the set honest so the agent isn't told we can locate
# inside raw HCL when we can't.
_SUPPORTED = _YAML_EXTS + _JSON_EXTS


def _read(file: str) -> tuple[str | None, str | None]:
    """Return (text, error). Path must be relative, in-tree, and supported."""
    if not file or not file.strip():
        return None, "file path cannot be empty"
    p = Path(file)
    if p.is_absolute() or ".." in p.parts:
        return None, f"file path must be relative and in-tree: {file!r}"
    ext = p.suffix.lower()
    if ext not in _SUPPORTED:
        return None, (
            f"unsupported file type {ext!r}; structured_query handles "
            f"{', '.join(_SUPPORTED)} only (HCL/.tf is not YAML/JSON)"
        )
    if not os.path.exists(file):
        return None, f"file not found: {file}"
    try:
        with open(file, encoding="utf-8") as f:
            return f.read(), None
    except OSError as exc:
        return None, f"could not read {file}: {exc}"


def _is_json(file: str) -> bool:
    return Path(file).suffix.lower() in _JSON_EXTS


@register_tool(parallel_safe=True)
def structured_query(file: str, path: str) -> dict[str, Any]:
    """Resolve a YAML/JSON path to its value and 1-based line range.

    Use this to find the exact file:line for a finding in a workflow,
    IaC, or config file so you can cite it in code_locations. Path syntax:
    dotted keys + [n] indices, e.g. 'jobs.build.steps[3].run' or
    'permissions'. Returns start_line/end_line (block scalars like
    'run: |' span all their lines), the parsed value, and the raw snippet.
    """
    text, err = _read(file)
    if err:
        return {"error": err}
    try:
        result = resolver.resolve(text, path, is_json=_is_json(file))
    except ValueError as exc:
        return {"error": f"malformed path {path!r}: {exc}"}
    except Exception as exc:  # noqa: BLE001
        logger.warning("structured_query(%s, %s) failed: %s", file, path, exc)
        return {"error": f"structured_query failed: {exc}"}
    if result is None:
        return {"error": f"path not found in {file}: {path!r}"}
    return {
        "file": file,
        "path": path,
        "start_line": result["start_line"],
        "end_line": result["end_line"],
        "value": result["value"],
        "snippet": result["snippet"],
    }


@register_tool(parallel_safe=True)
def structured_find(file: str, key_regex: str) -> dict[str, Any]:
    """Find every mapping/object KEY in a YAML/JSON file matching a regex,
    with each match's path and line range.

    Use for "where is X configured / how many places set Y" — e.g.
    key_regex='^permissions$' to locate every permissions block, or
    '^run$' to find every run: step. Returns up to 50 matches.
    """
    text, err = _read(file)
    if err:
        return {"error": err}
    try:
        hits = resolver.find(text, key_regex, is_json=_is_json(file))
    except Exception as exc:  # noqa: BLE001
        logger.warning("structured_find(%s, %s) failed: %s", file, key_regex, exc)
        return {"error": f"structured_find failed: {exc}"}
    if not hits:
        return {"output": f"no keys matching /{key_regex}/ in {file}"}
    lines = "\n".join(f"  {h['path']}  (lines {h['start_line']}-{h['end_line']})" for h in hits)
    return {"file": file, "matches": hits, "output": f"{len(hits)} match(es) in {file}:\n{lines}"}
