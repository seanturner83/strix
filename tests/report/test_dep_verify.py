"""Deterministic dependency version-range verify (OSV-backed).

Load-bearing behaviours (a SAFE FP reducer for dep-CVE findings):
  1. In-range -> emit (real). OSV lists the CVE for the installed version.
  2. Out-of-range -> REJECT. OSV knows advisories for the version but NOT the
     cited CVE (installed version outside the range / mis-attributed).
  3. Fail-open everywhere: OSV empty (coverage gap), OSV error/non-200, missing
     fields, non-CVE/GHSA id, unknown ecosystem -> emit (None). Never suppress a
     real dep finding on uncertainty.
"""

from __future__ import annotations

from strix.report import dep_verify as dv


def _cand(**kw):
    base = {"cve": "CVE-2021-23337", "package_name": "lodash",
            "installed_version": "4.17.20", "package_ecosystem": "npm"}
    base.update(kw)
    return base


class _Resp:
    def __init__(self, status, vulns):
        self.status_code = status
        self._vulns = vulns

    def json(self):
        return {"vulns": self._vulns}


def _patch_osv(monkeypatch, resp):
    import requests
    monkeypatch.setattr(requests, "post", lambda *a, **k: resp)


def test_in_range_emits(monkeypatch):
    # OSV lists the cited CVE as affecting this version -> real, emit (None).
    _patch_osv(monkeypatch, _Resp(200, [{"id": "GHSA-x", "aliases": ["CVE-2021-23337"]}]))
    assert dv.verify_dependency(_cand()) is None


def test_out_of_range_rejects(monkeypatch):
    # OSV knows advisories for this version but NOT the cited CVE -> out of range.
    _patch_osv(monkeypatch, _Resp(200, [{"id": "GHSA-other", "aliases": ["CVE-2020-0000"]}]))
    out = dv.verify_dependency(_cand())
    assert out is not None
    assert out["verify_rejected"] is True
    assert out["dep_version_out_of_range"] is True
    assert "CVE-2021-23337" in out["error"]


def test_osv_empty_fails_open(monkeypatch):
    # No advisories at all for this package@version -> coverage gap, emit.
    _patch_osv(monkeypatch, _Resp(200, []))
    assert dv.verify_dependency(_cand()) is None


def test_osv_non200_fails_open(monkeypatch):
    _patch_osv(monkeypatch, _Resp(503, []))
    assert dv.verify_dependency(_cand()) is None


def test_osv_error_fails_open(monkeypatch):
    import requests
    def _boom(*a, **k): raise requests.RequestException("timeout")
    monkeypatch.setattr(requests, "post", _boom)
    assert dv.verify_dependency(_cand()) is None


def test_matches_via_alias_or_id(monkeypatch):
    # cited a GHSA; OSV advisory keyed by GHSA id directly -> in range, emit.
    _patch_osv(monkeypatch, _Resp(200, [{"id": "GHSA-jf85-cpcp-j695"}]))
    assert dv.verify_dependency(_cand(cve="", ghsa="GHSA-jf85-cpcp-j695")) is None


def test_missing_fields_emit(monkeypatch):
    # any missing field -> can't make a definitive call -> emit (no OSV call needed)
    for miss in ("cve", "package_name", "installed_version", "package_ecosystem"):
        c = _cand(); c[miss] = ""
        if miss == "cve":
            c["ghsa"] = ""
        assert dv.verify_dependency(c) is None, miss


def test_unknown_ecosystem_emits(monkeypatch):
    assert dv.verify_dependency(_cand(package_ecosystem="cocoapods-weird")) is None


def test_non_cve_identifier_emits(monkeypatch):
    # vendor-specific id (not CVE/GHSA) isn't OSV-resolvable -> emit
    assert dv.verify_dependency(_cand(cve="RUSTSEC-2021-0001")) is None


def test_ecosystem_normalization():
    assert dv._norm_ecosystem("PyPI") == "PyPI"
    assert dv._norm_ecosystem("pip") == "PyPI"
    assert dv._norm_ecosystem("golang") == "Go"
    assert dv._norm_ecosystem("node") == "npm"
    assert dv._norm_ecosystem("bogus") is None
