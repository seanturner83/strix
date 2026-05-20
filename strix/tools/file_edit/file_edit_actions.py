import asyncio
import json
import re
from pathlib import Path
from typing import Any, cast

from strix.tools.registry import register_tool


def _parse_file_editor_output(output: str) -> dict[str, Any]:
    try:
        pattern = r"<oh_aci_output_[^>]+>\n(.*?)\n</oh_aci_output_[^>]+>"
        match = re.search(pattern, output, re.DOTALL)

        if match:
            json_str = match.group(1)
            data = json.loads(json_str)
            return cast("dict[str, Any]", data)
        return {"output": output, "error": None}
    except (json.JSONDecodeError, AttributeError):
        return {"output": output, "error": None}


@register_tool
def str_replace_editor(
    command: str,
    path: str,
    file_text: str | None = None,
    view_range: list[int] | None = None,
    old_str: str | None = None,
    new_str: str | None = None,
    insert_line: int | None = None,
) -> dict[str, Any]:
    from openhands_aci import file_editor

    try:
        path_obj = Path(path)
        if not path_obj.is_absolute():
            path = str(Path("/workspace") / path_obj)

        result = file_editor(
            command=command,
            path=path,
            file_text=file_text,
            view_range=view_range,
            old_str=old_str,
            new_str=new_str,
            insert_line=insert_line,
        )

        parsed = _parse_file_editor_output(result)

        if parsed.get("error"):
            return {"error": parsed["error"]}

        return {"content": parsed.get("output", result)}

    except (OSError, ValueError) as e:
        return {"error": f"Error in {command} operation: {e!s}"}


@register_tool(parallel_safe=True)
def list_files(
    path: str,
    recursive: bool = False,
) -> dict[str, Any]:
    from openhands_aci.utils.shell import run_shell_cmd

    try:
        path_obj = Path(path)
        if not path_obj.is_absolute():
            path = str(Path("/workspace") / path_obj)
            path_obj = Path(path)

        if not path_obj.exists():
            return {"error": f"Directory not found: {path}"}

        if not path_obj.is_dir():
            return {"error": f"Path is not a directory: {path}"}

        cmd = f"find '{path}' -type f -o -type d | head -500" if recursive else f"ls -1a '{path}'"

        exit_code, stdout, stderr = run_shell_cmd(cmd)

        if exit_code != 0:
            return {"error": f"Error listing directory: {stderr}"}

        items = stdout.strip().split("\n") if stdout.strip() else []

        files = []
        dirs = []

        for item in items:
            item_path = item if recursive else str(Path(path) / item)
            item_path_obj = Path(item_path)

            if item_path_obj.is_file():
                files.append(item)
            elif item_path_obj.is_dir():
                dirs.append(item)

        return {
            "files": sorted(files),
            "directories": sorted(dirs),
            "total_files": len(files),
            "total_dirs": len(dirs),
            "path": path,
            "recursive": recursive,
        }

    except (OSError, ValueError) as e:
        return {"error": f"Error listing directory: {e!s}"}


@register_tool(parallel_safe=True)
def search_files(
    path: str,
    regex: str,
    file_pattern: str = "*",
) -> dict[str, Any]:
    from openhands_aci.utils.shell import run_shell_cmd

    try:
        path_obj = Path(path)
        if not path_obj.is_absolute():
            path = str(Path("/workspace") / path_obj)

        if not Path(path).exists():
            return {"error": f"Directory not found: {path}"}

        escaped_regex = regex.replace("'", "'\"'\"'")

        cmd = f"rg --line-number --glob '{file_pattern}' '{escaped_regex}' '{path}'"

        exit_code, stdout, stderr = run_shell_cmd(cmd)

        if exit_code not in {0, 1}:
            return {"error": f"Error searching files: {stderr}"}
        return {"output": stdout if stdout else "No matches found"}

    except (OSError, ValueError) as e:
        return {"error": f"Error searching files: {e!s}"}


@register_tool(parallel_safe=True)
async def batch_list_files(
    paths: list[str],
    recursive: bool = False,
) -> dict[str, Any]:
    """Run list_files for multiple paths concurrently.

    Use this instead of multiple separate list_files calls when exploring
    several directories at once — it issues all the directory listings in
    parallel inside the sandbox and returns them as a single result.
    """
    if not paths:
        return {"error": "paths must be a non-empty list"}

    if not isinstance(paths, list):
        return {"error": f"paths must be a list, got {type(paths).__name__}"}

    results = await asyncio.gather(
        *[asyncio.to_thread(list_files, path=p, recursive=recursive) for p in paths],
        return_exceptions=True,
    )

    out: dict[str, Any] = {}
    for path, result in zip(paths, results, strict=True):
        if isinstance(result, BaseException):
            out[path] = {"error": f"{type(result).__name__}: {result!s}"}
        else:
            out[path] = result
    return {"results": out, "count": len(paths)}


@register_tool(parallel_safe=True)
async def batch_search_files(
    searches: list[dict[str, Any]],
) -> dict[str, Any]:
    """Run search_files for multiple (path, regex) pairs concurrently.

    Each entry in `searches` is a dict with keys: path (required),
    regex (required), file_pattern (optional, default '*').
    Use this to grep across several locations or for several patterns at once.
    """
    if not searches:
        return {"error": "searches must be a non-empty list"}

    if not isinstance(searches, list):
        return {"error": f"searches must be a list, got {type(searches).__name__}"}

    for i, entry in enumerate(searches):
        if not isinstance(entry, dict):
            return {"error": f"searches[{i}] must be a dict"}
        if "path" not in entry or "regex" not in entry:
            return {"error": f"searches[{i}] missing required keys 'path' or 'regex'"}

    results = await asyncio.gather(
        *[
            asyncio.to_thread(
                search_files,
                path=s["path"],
                regex=s["regex"],
                file_pattern=s.get("file_pattern", "*"),
            )
            for s in searches
        ],
        return_exceptions=True,
    )

    out: list[dict[str, Any]] = []
    for entry, result in zip(searches, results, strict=True):
        item = {"path": entry["path"], "regex": entry["regex"]}
        if isinstance(result, BaseException):
            item["error"] = f"{type(result).__name__}: {result!s}"
        else:
            item.update(result if isinstance(result, dict) else {"output": str(result)})
        out.append(item)
    return {"results": out, "count": len(searches)}


# ruff: noqa: TRY300
