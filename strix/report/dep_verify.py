"""Deterministic version-range verify for dependency-CVE findings.

The code-sink verifier (report/verify.py) answers a REASONING question — is the
sink reachable + the control complete. A dependency-CVE false positive is a
different, FACTUAL question: is the installed version actually in the advisory's
vulnerable range? That's deterministic — an OSV.dev range check, no LLM — and
more reliable than any model for this sub-class (version-range containment is
exact). This is the "promote to a deterministic control" pattern.

FP shape this catches: an agent files "CVE-XXXX in pkg@1.2.3" but 1.2.3 is OUT of
the advisory's affected range (already patched, or the CVE was mis-attributed to
the package). OSV.query(package, ecosystem, version) returns exactly the
advisories affecting THAT version; if the finding's CVE isn't among them, the
installed version is not vulnerable → reject.

SAFETY (fail-open, asymmetric — never suppress a real dep finding):
  - reject ONLY when OSV returns a definitive answer AND the finding's CVE/GHSA
    is provably absent from the advisories affecting the installed version;
  - any uncertainty EMITS: OSV unreachable, package/version unparseable, CVE not
    resolvable, ecosystem unknown, or OSV lists the CVE → return None (emit);
  - gated by the same VerifySettings.enabled + a network call, so it only runs
    when the verify pass is on.

No LLM. Pure OSV.dev REST (free, no auth). Fork-internal, upstream-candidate.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_OSV_URL = "https://api.osv.dev/v1/query"

# Map common ecosystem strings (as agents/trivy emit them) to OSV's canonical set.
_ECOSYSTEM = {
    "npm": "npm", "node": "npm", "javascript": "npm", "yarn": "npm",
    "pypi": "PyPI", "pip": "PyPI", "python": "PyPI",
    "go": "Go", "golang": "Go", "gomod": "Go",
    "maven": "Maven", "java": "Maven", "gradle": "Maven",
    "cargo": "crates.io", "rust": "crates.io", "crates.io": "crates.io",
    "rubygems": "RubyGems", "ruby": "RubyGems", "gem": "RubyGems",
    "nuget": "NuGet", "composer": "Packagist", "packagist": "Packagist",
}


def _norm_ecosystem(eco: str | None) -> str | None:
    return _ECOSYSTEM.get((eco or "").strip().lower())


def _ids_for(vuln: dict) -> set[str]:
    """All identifiers an OSV advisory is known by (its id + aliases), upper-cased."""
    ids = {str(vuln.get("id", "")).upper()}
    ids.update(str(a).upper() for a in (vuln.get("aliases") or []))
    return {i for i in ids if i}


def verify_dependency(candidate: dict[str, Any]) -> dict[str, Any] | None:
    """Deterministically check a dep-CVE finding's version is in the CVE's range.

    candidate needs: cve (or ghsa), package_name, installed_version, package_ecosystem.
    Returns a REJECT dict when the installed version is provably NOT affected by
    the cited advisory; None (emit) on any uncertainty (fail-open)."""
    cve = str(candidate.get("cve") or "").strip().upper()
    ghsa = str(candidate.get("ghsa") or "").strip().upper()
    ident = cve or ghsa
    pkg = str(candidate.get("package_name") or "").strip()
    version = str(candidate.get("installed_version") or "").strip()
    eco = _norm_ecosystem(candidate.get("package_ecosystem"))

    # Need all four to make a definitive call; otherwise emit.
    if not (ident and pkg and version and eco):
        return None
    # Only CVE/GHSA identifiers are resolvable in OSV; skip vendor-specific ids.
    if not (ident.startswith("CVE-") or ident.startswith("GHSA-")):
        return None

    try:
        import os
        import requests
        ca = os.environ.get("REQUESTS_CA_BUNDLE")
        resp = requests.post(
            _OSV_URL, timeout=20,
            json={"package": {"name": pkg, "ecosystem": eco}, "version": version},
            verify=ca if ca else True,
        )
        if resp.status_code != 200:
            logger.info("dep-verify: OSV %s for %s@%s; emitting unverified",
                        resp.status_code, pkg, version)
            return None
        vulns = resp.json().get("vulns", []) or []
    except Exception:  # noqa: BLE001 — advisory; OSV hiccup must never suppress a finding
        logger.info("dep-verify: OSV query failed for %s@%s; emitting (fail-open)",
                    pkg, version, exc_info=True)
        return None

    # OSV returned a DEFINITIVE list of advisories affecting THIS exact version.
    affecting = set()
    for v in vulns:
        affecting |= _ids_for(v)

    if ident in affecting:
        return None  # confirmed: installed version IS in the CVE's range → emit (real)

    # The cited advisory is NOT among those affecting the installed version.
    # Distinguish "OSV knows the CVE but not for this version" (out-of-range, a
    # clean FP) from "OSV returned nothing at all" (could be coverage gap → emit).
    if not vulns:
        # OSV has no advisory for this package@version at all. Could be a genuine
        # gap (private/vendored pkg, OSV lag). Fail-open: emit.
        logger.info("dep-verify: OSV lists NO advisories for %s@%s; emitting "
                    "(coverage gap, not a confident FP)", pkg, version)
        return None

    # OSV knows advisories for this version but NOT the cited one → the installed
    # version is out of the cited CVE's range → false positive.
    return {
        "success": False,
        "error": (
            f"Version-range verify rejected this dependency finding: {ident} does "
            f"not affect {pkg}@{version} per OSV.dev (installed version is outside "
            f"the advisory's vulnerable range — likely already patched or the CVE "
            f"is mis-attributed to this package). OSV advisories affecting "
            f"{pkg}@{version}: {sorted(affecting) or 'none of this CVE'}. If you "
            f"believe the version IS vulnerable, cite the exact affected range."
        ),
        "verify_rejected": True,
        "dep_version_out_of_range": True,
        "installed_version": version,
        "cited_advisory": ident,
    }
