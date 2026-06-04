import asyncio
from typing import Any, Literal

from strix.tools.registry import register_tool


RequestPart = Literal["request", "response"]


@register_tool(parallel_safe=True, requires_dynamic_target=True)
async def batch_view_request(
    requests: list[dict[str, Any]],
) -> dict[str, Any]:
    """View multiple captured requests/responses concurrently.

    Each entry in `requests` is a dict with keys: request_id (required),
    part (optional, "request" or "response", default "request"),
    search_pattern (optional), page (optional, default 1),
    page_size (optional, default 50).
    """
    if not requests:
        return {"error": "requests must be a non-empty list"}

    if not isinstance(requests, list):
        return {"error": f"requests must be a list, got {type(requests).__name__}"}

    for i, entry in enumerate(requests):
        if not isinstance(entry, dict):
            return {"error": f"requests[{i}] must be a dict"}
        if "request_id" not in entry:
            return {"error": f"requests[{i}] missing required key 'request_id'"}

    results = await asyncio.gather(
        *[
            asyncio.to_thread(
                view_request,
                request_id=r["request_id"],
                part=r.get("part", "request"),
                search_pattern=r.get("search_pattern"),
                page=r.get("page", 1),
                page_size=r.get("page_size", 50),
            )
            for r in requests
        ],
        return_exceptions=True,
    )

    out: list[dict[str, Any]] = []
    for entry, result in zip(requests, results, strict=True):
        item = {"request_id": entry["request_id"], "part": entry.get("part", "request")}
        if isinstance(result, BaseException):
            item["error"] = f"{type(result).__name__}: {result!s}"
        else:
            item.update(result if isinstance(result, dict) else {"output": str(result)})
        out.append(item)
    return {"results": out, "count": len(requests)}


@register_tool(parallel_safe=True, requires_dynamic_target=True)
def list_requests(
    httpql_filter: str | None = None,
    start_page: int = 1,
    end_page: int = 1,
    page_size: int = 50,
    sort_by: Literal[
        "timestamp",
        "host",
        "method",
        "path",
        "status_code",
        "response_time",
        "response_size",
        "source",
    ] = "timestamp",
    sort_order: Literal["asc", "desc"] = "desc",
    scope_id: str | None = None,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.list_requests(
        httpql_filter, start_page, end_page, page_size, sort_by, sort_order, scope_id
    )


@register_tool(parallel_safe=True, requires_dynamic_target=True)
def view_request(
    request_id: str,
    part: RequestPart = "request",
    search_pattern: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.view_request(request_id, part, search_pattern, page, page_size)


@register_tool(requires_dynamic_target=True)
def send_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 30,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    if headers is None:
        headers = {}
    manager = get_proxy_manager()
    return manager.send_simple_request(method, url, headers, body, timeout)


@register_tool(requires_dynamic_target=True)
def repeat_request(
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    if modifications is None:
        modifications = {}
    manager = get_proxy_manager()
    return manager.repeat_request(request_id, modifications)


@register_tool(requires_dynamic_target=True)
def scope_rules(
    action: Literal["get", "list", "create", "update", "delete"],
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.scope_rules(action, allowlist, denylist, scope_id, scope_name)


@register_tool(parallel_safe=True, requires_dynamic_target=True)
def list_sitemap(
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: Literal["DIRECT", "ALL"] = "DIRECT",
    page: int = 1,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.list_sitemap(scope_id, parent_id, depth, page)


@register_tool(parallel_safe=True, requires_dynamic_target=True)
def view_sitemap_entry(
    entry_id: str,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.view_sitemap_entry(entry_id)
