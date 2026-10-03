"""Shared Jev / Jevstiller HTTP client (TypeSafe System One API).

``TYPESAFE_BASE_URL`` points at the Jev API directly, or at a Jevstiller proxy
that distils a repeated classification into a local model. The call shape is
identical either way, so a high-frequency, domain-specific task (the per-turn
routing) points at Jevstiller — most calls then answer locally and never reach
the remote API — while a low-frequency, general task (dedup/verify) can hit Jev
directly.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any


_DEFAULT_BASE_URL = "https://api.typesafe.ai"
_TIMEOUT_S = 30.0


def api_key() -> str | None:
    return os.environ.get("TYPESAFE_API_KEY", "").strip() or None


def base_url() -> str:
    return (os.environ.get("TYPESAFE_BASE_URL", "").strip() or _DEFAULT_BASE_URL).rstrip("/")


def post(payload: dict[str, Any], timeout: float = _TIMEOUT_S) -> dict[str, Any]:
    """Blocking POST to ``/v1/systemone``; raises on failure."""
    req = urllib.request.Request(  # noqa: S310  # fixed https host + scheme
        f"{base_url()}/v1/systemone",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key()}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))
