import json
from pathlib import Path
from typing import Any

from strix.telemetry.sarif import (
    build_sarif_document,
    build_sarif_report,
    write_sarif,
    write_sarif_report,
)


def _finding(**overrides: Any) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": "vuln-0001",
        "title": "Unsanitized redirect target",
        "severity": "high",
        "description": "A user-controlled redirect target is trusted without validation.",
        "impact": "Attackers can redirect users to phishing pages.",
        "remediation_steps": "Allow-list trusted redirect destinations.",
        "cvss": 8.1,
        "cwe": "CWE-601",
        "cve": "CVE-2026-0001",
        "target": "./demo-app",
        "endpoint": "/login",
        "method": "GET",
        "code_locations": [
            {
                "file": "src/auth/redirects.py",
                "start_line": 42,
                "end_line": 45,
                "snippet": "return redirect(request.args['next'])",
                "label": "User-controlled redirect sink",
            }
        ],
    }
    finding.update(overrides)
    return finding


def test_build_sarif_maps_code_location_and_metadata() -> None:
    sarif = build_sarif_report([_finding()], tool_version="0.8.3")

    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Strix"
    assert driver["version"] == "0.8.3"
    rule = driver["rules"][0]
    assert rule["id"] == "CWE-601"
    assert rule["fullDescription"]["text"] == (
        "A user-controlled redirect target is trusted without validation."
    )
    assert "Allow-list trusted redirect destinations." in rule["help"]["text"]

    result = run["results"][0]
    assert result["ruleId"] == "CWE-601"
    assert result["level"] == "error"
    assert result["message"]["text"] == "Unsanitized redirect target"
    # ``security-severity`` is the only top-level property GitHub code-scanning
    # reads; Strix-specific fields are namespaced so generic SARIF consumers
    # don't surface finding metadata (notably PoC) to a wide audience.
    assert result["properties"]["security-severity"] == "8.1"
    assert result["properties"]["strix"]["cvss"] == 8.1
    assert result["properties"]["strix"]["cve"] == "CVE-2026-0001"
    assert result["properties"]["strix"]["target"] == "./demo-app"

    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/auth/redirects.py"
    assert location["region"] == {
        "startLine": 42,
        "endLine": 45,
        "snippet": {"text": "return redirect(request.args['next'])"},
    }


def test_build_sarif_maps_severity_levels() -> None:
    findings = [
        _finding(id="vuln-critical", severity="critical"),
        _finding(id="vuln-high", severity="high"),
        _finding(id="vuln-medium", severity="medium"),
        _finding(id="vuln-low", severity="low"),
        _finding(id="vuln-info", severity="info"),
    ]

    levels = [result["level"] for result in build_sarif_report(findings)["runs"][0]["results"]]

    assert levels == ["error", "error", "warning", "note", "note"]


def test_build_sarif_anchors_locationless_findings_synthetically() -> None:
    """Findings without safe code locations are now anchored to
    SECURITY.md and emitted as proper SARIF results so they flow
    through GHAS code-scanning normally — the old run-properties-summary
    path made them invisible to the SEC-6941 partialFingerprints code,
    which meant their alerts re-orphaned every run. The synthetic-anchor
    contract was previously implemented downstream in
    composite-actions/rw-security.yml's `Sanitize SARIF` jq step;
    pulling it upstream consolidates the semantic and ensures
    fingerprints get injected before SARIF leaves Strix."""
    sarif = build_sarif_report([_finding(code_locations=None, cwe=None, cve=None)])

    run = sarif["runs"][0]
    assert len(run["results"]) == 1
    result = run["results"][0]
    # Anchored to SECURITY.md, marked synthetic
    assert (
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "SECURITY.md"
    )
    assert result["properties"]["zh_synthetic_location"] is True
    # Fingerprints flow through the SEC-6941 path the same as
    # source-anchored results
    assert result["partialFingerprints"]["primaryLocationLineHash"]
    assert result["properties"]["zh_strix_vuln_class_hash"]
    # Top-level count remains as observability hook for CI dashboards
    assert run["properties"]["syntheticLocationCount"] == 1
    # The detail-list at run.properties.locationlessFindings is gone
    # — findings are first-class results now, not summaries.
    assert "locationlessFindings" not in run["properties"]


def test_build_sarif_drops_unsafe_code_locations() -> None:
    """When ALL code_locations are rejected as unsafe, the finding falls
    back to the synthetic SECURITY.md anchor (same path as a finding
    with no code_locations at all). The dropped-unsafe-locations
    bookkeeping only kicks in when safe locations remain — see the
    sibling test below."""
    sarif = build_sarif_report(
        [
            _finding(
                code_locations=[
                    {"file": "/tmp/app.py", "start_line": 1, "end_line": 1},
                    {"file": "../app.py", "start_line": 2, "end_line": 2},
                    {"file": "C:\\Users\\app.py", "start_line": 3, "end_line": 3},
                    {"file": "mailto:x", "start_line": 4, "end_line": 4},
                    {"file": "foo:bar.py", "start_line": 5, "end_line": 5},
                    {"file": "src/app.py", "start_line": 0, "end_line": 1},
                    {"file": "src/other.py", "start_line": True, "end_line": True},
                ]
            )
        ]
    )

    run = sarif["runs"][0]
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert (
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "SECURITY.md"
    )
    assert result["properties"]["zh_synthetic_location"] is True
    assert run["properties"]["syntheticLocationCount"] == 1
    # The drop-count is still reported as observability — useful to
    # know HOW the synthetic anchor came about (7 unsafe inputs vs 0
    # provided). The finding is still in results[]; this is just a
    # diagnostic counter at run-properties level.
    assert run["properties"]["droppedUnsafeLocationCount"] == 7


def test_build_sarif_keeps_locations_without_valid_end_line() -> None:
    sarif = build_sarif_report(
        [
            _finding(
                code_locations=[
                    {"file": "src/app.py", "start_line": 10},
                    {"file": "src/reversed.py", "start_line": 20, "end_line": 19},
                ]
            )
        ]
    )

    regions = [
        location["physicalLocation"]["region"]
        for location in sarif["runs"][0]["results"][0]["locations"]
    ]
    assert regions == [{"startLine": 10}, {"startLine": 20}]


def test_build_sarif_summarizes_dropped_unsafe_locations_when_safe_locations_remain() -> None:
    sarif = build_sarif_report(
        [
            _finding(
                code_locations=[
                    {"file": "src/app.py", "start_line": 10, "end_line": 12},
                    {"file": "foo:bar.py", "start_line": 1, "end_line": 1},
                ]
            )
        ]
    )

    run = sarif["runs"][0]
    assert len(run["results"]) == 1
    assert run["properties"]["droppedUnsafeLocationCount"] == 1
    assert run["properties"]["droppedUnsafeLocationFindings"][0] == {
        "id": "vuln-0001",
        "title": "Unsanitized redirect target",
        "droppedLocationCount": 1,
    }


def test_write_sarif_report_creates_parent_directories(tmp_path: Path) -> None:
    output_path = tmp_path / "nested" / "results.sarif"

    write_sarif_report(output_path, [_finding()], tool_version="0.8.3")

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved["runs"][0]["results"][0]["ruleId"] == "CWE-601"


# ---------------------------------------------------------------------------
# Additional coverage — these test surfaces added in the combined PR beyond
# the original #477 scope: CWE normalisation, rule-level GitHub properties,
# PoC namespacing, backwards-compatible write_sarif alias.


def test_cwe_normalisation_unifies_input_variants() -> None:
    """The same weakness expressed three different ways in Strix output
    must collapse to a single rule so dedup across runs works."""
    variants = [
        _finding(id="a", cwe="CWE-306"),
        _finding(id="b", cwe="cwe:306"),
        _finding(id="c", cwe="306"),
    ]
    sarif = build_sarif_report(variants)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "CWE-306"
    for result in sarif["runs"][0]["results"]:
        assert result["ruleId"] == "CWE-306"


def test_cwe_rule_includes_github_code_scanning_properties() -> None:
    """GitHub code-scanning reads rule.properties['security-severity'] +
    rule.properties['tags']. Without them, alerts show up at default severity
    and can't be filtered by security tag."""
    sarif = build_sarif_report([_finding()])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]

    assert rule["properties"]["security-severity"] == "8.1"
    assert "security" in rule["properties"]["tags"]
    assert "CWE-601" in rule["properties"]["tags"]
    assert "CVE-2026-0001" in rule["properties"]["tags"]
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["helpUri"] == "https://cwe.mitre.org/data/definitions/601.html"


def test_non_cwe_rules_omit_help_uri() -> None:
    """A finding with neither CWE nor CVE falls back to a slug rule id;
    helpUri only applies when we can link to a canonical taxonomy."""
    sarif = build_sarif_report([
        _finding(cwe=None, cve=None, code_locations=_finding()["code_locations"]),
    ])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "helpUri" not in rule


def test_poc_content_is_namespaced_under_strix_not_flat_on_properties() -> None:
    """PoC exploitation payloads live under ``properties.strix.poc`` so
    generic SARIF UI consumers don't surface exploit text to triage
    audiences by default."""
    sarif = build_sarif_report([_finding(
        poc_description="curl --request POST …",
        poc_script_code="#!/bin/sh\ncurl -X POST …",
    )])
    result = sarif["runs"][0]["results"][0]
    assert "poc" not in result["properties"]
    assert "poc" in result["properties"]["strix"]
    assert result["properties"]["strix"]["poc"]["description"].startswith("curl")
    assert result["properties"]["strix"]["poc"]["script"].startswith("#!/bin/sh")


def test_security_severity_prefers_cvss_over_label() -> None:
    """When CVSS is present, it drives security-severity; label only used
    as fallback. CVSS ≠ label-mean-score for severity-label-only findings."""
    cvss_only = build_sarif_report([_finding(cvss=9.2, severity="high")])
    assert (
        cvss_only["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
        == "9.2"
    )

    label_only = build_sarif_report([_finding(cvss=None, severity="medium")])
    assert (
        label_only["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
        == "5.5"
    )


def test_backwards_compatible_write_sarif_alias(tmp_path: Path) -> None:
    """``write_sarif`` is the tracer-hook entry point; must keep working so
    internal callers aren't coupled to the CLI-invoked ``write_sarif_report``.
    """
    out = write_sarif(tmp_path, [_finding()], tool_version="1.0.0")
    assert out == tmp_path / "findings.sarif"
    assert out.exists()

    # ``build_sarif_document`` alias equivalent to ``build_sarif_report``.
    a = build_sarif_document([_finding()])
    b = build_sarif_report([_finding()])
    assert a == b


def test_document_shape_matches_sarif_2_1_0_top_level() -> None:
    """Basic structural validation without pulling in jsonschema. Catches
    any regression that would trip schemastore.org validation at CI time."""
    sarif = build_sarif_report([_finding()])

    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert isinstance(sarif["runs"], list)
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Strix"
    assert driver["informationUri"]
    assert isinstance(driver["rules"], list)

    for rule in driver["rules"]:
        assert rule["id"]
        assert rule["shortDescription"]["text"]
        assert rule["fullDescription"]["text"]
        assert rule["defaultConfiguration"]["level"] in {"error", "warning", "note"}

    for result in run["results"]:
        assert result["ruleId"]
        assert result["level"] in {"error", "warning", "note"}
        assert result["message"]["text"]
        assert isinstance(result["locations"], list)
        for location in result["locations"]:
            assert location["physicalLocation"]["artifactLocation"]["uri"]
            assert "startLine" in location["physicalLocation"]["region"]


# ---------------------------------------------------------------------------
# partialFingerprints (SEC-6941)
# ---------------------------------------------------------------------------


def _result_for(finding: dict[str, Any]) -> dict[str, Any]:
    sarif = build_sarif_report([finding])
    return sarif["runs"][0]["results"][0]


def test_partial_fingerprints_emitted_for_findings_with_locations() -> None:
    """Every result with a code location should carry
    partialFingerprints.primaryLocationLineHash so GHAS can reconcile
    alerts across runs even when the SARIF (category, analysis_key)
    namespace drifts. Sibling to composite-actions#1161 (Checkov)."""
    result = _result_for(_finding())
    assert result["partialFingerprints"]["primaryLocationLineHash"]
    assert len(result["partialFingerprints"]["primaryLocationLineHash"]) == 64  # sha256


def test_class_fingerprint_emitted_in_properties() -> None:
    """The file-independent class hash is a sibling property used by the
    orphan-sweep tooling to carry dismissal determinations across file
    renames (see SEC-6941 plan)."""
    result = _result_for(_finding(title="Open redirect on /login GET handler"))
    class_hash = result["properties"]["zh_strix_vuln_class_hash"]
    assert class_hash
    assert len(class_hash) == 64  # sha256


def test_primary_fingerprint_stable_across_cosmetic_title_change() -> None:
    """Same vulnerability class on the same file:line with the same route
    must produce the same primary fingerprint regardless of LLM title
    rephrasing run-over-run. This is the SEC-6941 motivation: titles
    are stochastic; primitives (CWE rule_id, file:line, route) are not.
    """
    a = _result_for(_finding(title="Unsanitized redirect target"))
    b = _result_for(
        _finding(title="Open Redirect via Unvalidated `next` Parameter")
    )
    assert (
        a["partialFingerprints"]["primaryLocationLineHash"]
        == b["partialFingerprints"]["primaryLocationLineHash"]
    )


def test_primary_fingerprint_differs_across_distinct_findings_in_same_file() -> None:
    """Two different findings on the same file:line with different CWEs
    must produce distinct primary fingerprints — otherwise GHAS would
    collapse them into one alert."""
    a = _result_for(_finding(cwe="CWE-601"))
    b = _result_for(_finding(cwe="CWE-918", title="SSRF on the same handler"))
    assert (
        a["partialFingerprints"]["primaryLocationLineHash"]
        != b["partialFingerprints"]["primaryLocationLineHash"]
    )


def test_class_fingerprint_survives_file_rename() -> None:
    """File rename (refactor with no fix): primary fingerprint
    legitimately differs because the location moved, but class
    fingerprint stays stable so the orphan-sweep tooling can carry
    forward a prior dismissal determination."""
    orig = _finding(
        title="Open redirect on /login",
        code_locations=[
            {
                "file": "src/auth/redirects.py",
                "start_line": 42,
                "end_line": 45,
            }
        ],
    )
    renamed = _finding(
        title="Open redirect on /login",
        code_locations=[
            {
                "file": "src/security/redirects.py",  # moved
                "start_line": 42,
                "end_line": 45,
            }
        ],
    )
    a = _result_for(orig)
    b = _result_for(renamed)
    assert (
        a["partialFingerprints"]["primaryLocationLineHash"]
        != b["partialFingerprints"]["primaryLocationLineHash"]
    )
    assert (
        a["properties"]["zh_strix_vuln_class_hash"]
        == b["properties"]["zh_strix_vuln_class_hash"]
    )


def test_primary_fingerprint_distinguishes_locationless_findings_by_class() -> None:
    """Two locationless findings of the same CWE but different vuln
    classes (e.g. both CWE-862 but one missing-authn, one missing-authz)
    must produce distinct primary fingerprints — otherwise GHAS would
    collapse them into a single alert. The class-keyword extraction in
    the synthetic-fingerprint path is what keeps them distinct."""
    a = _result_for(
        _finding(
            cwe="CWE-862",
            title="Missing Authentication on /admin endpoint",
            method="",
            endpoint="",
            code_locations=[],
        )
    )
    b = _result_for(
        _finding(
            cwe="CWE-862",
            title="Missing Authorization on /admin endpoint",
            method="",
            endpoint="",
            code_locations=[],
        )
    )
    # Both are synthetic-anchored
    assert a["properties"]["zh_synthetic_location"] is True
    assert b["properties"]["zh_synthetic_location"] is True
    # Same rule_id (CWE) but different class keywords → distinct
    assert a["ruleId"] == b["ruleId"] == "CWE-862"
    assert (
        a["partialFingerprints"]["primaryLocationLineHash"]
        != b["partialFingerprints"]["primaryLocationLineHash"]
    )


def test_primary_fingerprint_uses_route_when_locations_have_route() -> None:
    """Findings that have BOTH a code location and a route get both in
    the fingerprint composite. Route presence makes BOLA/IDOR findings
    on the same handler file distinguishable from non-routed findings
    in the same file."""
    routed = _result_for(
        _finding(method="POST", endpoint="/admin/delete", title="BOLA on delete")
    )
    unrouted = _result_for(
        _finding(method="", endpoint="", title="Unsanitized redirect target")
    )
    assert (
        routed["partialFingerprints"]["primaryLocationLineHash"]
        != unrouted["partialFingerprints"]["primaryLocationLineHash"]
    )
