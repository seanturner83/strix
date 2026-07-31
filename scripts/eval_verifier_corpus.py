#!/usr/bin/env python3
"""Evaluate the in-scan verify pass over the VLB FP/TP corpus, per model.

Double duty:
  1. Validates strix/report/verify.py beyond the smoke — does the verifier
     correctly REJECT the fixed cases (SUPPRESS) while KEEPING the still-vulnerable
     ones (KEEP, esp static-eval)?
  2. Per-model accuracy is a QUALITY signal for the Path-B orchestrator question
     (sonnet-5 vs opus-4-8): verification is a security-reasoning task, so the
     model that verifies more accurately reasons better about vuln reachability.

Faithful test: verify_finding judges from the candidate's CODE fields (a real
in-scan report carries the sink code in technical_analysis/PoC). So per case we
inject the ACTUAL patched sink source from the cached `_b` tree into
technical_analysis — the verifier then judges real patched code, exactly as it
would mid-scan.

Corpus label meaning (from the verifier's POV):
  SUPPRESS = fix is complete -> verifier SHOULD reject (verdict FALSE_POSITIVE).
  KEEP     = still vulnerable -> verifier should NOT reject (verdict REAL / emit).
So: reject==SUPPRESS is a correct suppression; reject on a KEEP is a FALSE NEGATIVE
(suppressed a real vuln — the cardinal sin); no-reject on a SUPPRESS is a missed-FP
(the residual we're trying to cut). FN must be 0.

Usage:
  STRIX_VERIFY=1 STRIX_VERIFY_MIN_SEVERITY=info AWS_PROFILE=claude-code \
  REQUESTS_CA_BUNDLE=/tmp/combined-ca.pem PYTHONPATH=src \
  uv run python scripts/eval_verifier_corpus.py \
    --model bedrock/converse/us.anthropic.claude-sonnet-5
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

VLB = Path("/Users/seant/code/vlbench-strix")
CORPUS = VLB / "corpus.json"
TREES = VLB / "cache/repos"


def _load_all_cases() -> list[dict]:
    """Unified labeled eval set across every corpus we built this session:
      corpus.json (16: FP/TP calibration) + floor_corpus (5 KEEP reasoning-floor)
      + fam_corpus (4 KEEP famous-CVE incomplete-fix) + NUAN* synthetics (4 KEEP,
      widened-guard) + calib_corpus×calib_labels (33 labeled, DEFER excluded).
    Normalises SUPPRESS-nuanced -> SUPPRESS. Dedups by alpha_id (corpus wins).
    Only cases whose patched sink file is cached are returned."""
    seen: dict[str, dict] = {}

    def add(case: dict, label: str, src: str):
        aid = case.get("alpha_id")
        if not aid or aid in seen:
            return
        lab = "SUPPRESS" if str(label).startswith("SUPPRESS") else label
        if lab not in ("KEEP", "SUPPRESS"):
            return  # DEFER/TBD/unknown — skip
        if not (TREES / f"{aid}_b" / case.get("sink_file", "")).is_file():
            return
        seen[aid] = {**case, "label": lab, "_src": src}

    for c in json.load(open(CORPUS)).get("cases", []):
        add(c, c.get("label"), "corpus")
    for fn in ("floor_corpus.json", "fam_corpus.json"):
        p = VLB / fn
        if p.is_file():
            for c in json.load(open(p)).get("cases", []):
                add(c, c.get("label", "KEEP"), fn.split("_")[0])
    # NUAN* synthetics — all KEEP (widened-guard); synth their case dicts from trees
    _NUAN = {"NUANdjv": ("korzio/djv", "lib/utils/template.js", "code-injection"),
             "NUANmjml": ("mjmlio/mjml", "packages/mjml-parser-xml/src/index.js", "path-traversal"),
             "NUANpickle": ("mmaitre314/picklescan", "src/picklescan/scanner.py", "deser-blocklist-bypass"),
             "NUANghapr": ("gha/pr-target", ".github/workflows/x.yml", "ci-injection")}
    for aid, (repo, sink, cls) in _NUAN.items():
        add({"alpha_id": aid, "repo": repo, "sink_file": sink, "class": cls, "cve": ""},
            "KEEP", "NUAN")
    # calib: labels live in calib_labels.json keyed by alpha_id
    cc, cl = VLB / "calib_corpus.json", VLB / "calib_labels.json"
    if cc.is_file() and cl.is_file():
        labels = json.load(open(cl))
        for c in json.load(open(cc)).get("cases", []):
            lab = (labels.get(c.get("alpha_id"), {}) or {}).get("label")
            if lab:
                add(c, lab, "calib")
    return list(seen.values())


def _read_sink(alpha_id: str, sink_file: str) -> str | None:
    p = TREES / f"{alpha_id}_b" / sink_file
    if p.is_file():
        return p.read_text(errors="ignore")
    return None


def _candidate(case: dict) -> dict | None:
    """Build an in-scan-shaped report candidate carrying the PATCHED sink code."""
    code = _read_sink(case["alpha_id"], case["sink_file"])
    if code is None:
        return None
    # cap very large files — keep head+tail so the sink + context are present
    if len(code) > 12000:
        code = code[:8000] + "\n...[truncated]...\n" + code[-3000:]
    cls = case["class"]
    return {
        "title": f"{cls} in {case['repo']} ({case.get('cve','')})",
        "description": f"A scanner flagged {case['repo']} for {cls} at {case['sink_file']}.",
        "impact": "see class",
        "target": f"{case['repo']}:{case['sink_file']}",
        "technical_analysis": (
            f"vuln_class={cls}. The patched sink file {case['sink_file']} at "
            f"current HEAD is below. Decide whether the {cls} is still exploitable "
            f"in THIS code, or whether a control/fix neutralises it.\n\n"
            f"```\n{code}\n```"
        ),
        "poc_description": f"Exploit the {cls} via {case['sink_file']}.",
        "poc_script_code": "",
        "endpoint": None, "method": None,
    }


async def run(model: str, out_path: str, use_all: bool = False) -> int:
    os.environ.setdefault("STRIX_VERIFY", "1")
    os.environ.setdefault("STRIX_VERIFY_MIN_SEVERITY", "info")  # eval every case
    os.environ["STRIX_VERIFY_MODEL"] = model
    # reset the settings cache so the env above is read
    from strix.config import loader
    loader._cached = None
    from strix.report.verify import verify_finding

    cases = _load_all_cases() if use_all else json.load(open(CORPUS))["cases"]
    if use_all:
        from collections import Counter
        by = Counter((c["label"], c.get("_src")) for c in cases)
        print(f"# unified eval set: {len(cases)} cases "
              f"({sum(1 for c in cases if c['label']=='KEEP')} KEEP / "
              f"{sum(1 for c in cases if c['label']=='SUPPRESS')} SUPPRESS)")
    rows = []
    tp = fn = tn = fp = skip = 0
    for c in cases:
        cand = _candidate(c)
        if cand is None:
            skip += 1
            print(f"  {c['alpha_id']:10} SKIP (no cached sink)")
            continue
        # verifier judges as high severity so min_severity never gates the eval
        verdict = await verify_finding(cand, "critical")
        rejected = verdict is not None
        label = c["label"]
        # scoring: positive class = "real vuln that must be KEPT"
        if label == "KEEP" and not rejected:
            tp += 1; mark = "✓ kept real"
        elif label == "KEEP" and rejected:
            fn += 1; mark = "✗✗ FN — SUPPRESSED A REAL VULN"
        elif label == "SUPPRESS" and rejected:
            tn += 1; mark = "✓ rejected FP"
        else:  # SUPPRESS and not rejected
            fp += 1; mark = "· missed-FP (still emits)"
        rows.append({"alpha_id": c["alpha_id"], "repo": c["repo"], "label": label,
                     "rejected": rejected, "correct": mark.startswith("✓"),
                     "reason": (verdict or {}).get("reason", ""),
                     "confidence": (verdict or {}).get("confidence")})
        json.dump({"model": model, "rows": rows}, open(out_path, "w"), indent=1)
        print(f"  {c['alpha_id']:10} {c['repo']:26} want={label:8} "
              f"rejected={rejected!s:5} {mark}")

    total = tp + fn + tn + fp
    print(f"\n# model={model}")
    print(f"# KEEP kept (TP)={tp}  KEEP suppressed (FN)={fn}  "
          f"SUPPRESS rejected (TN)={tn}  SUPPRESS missed (FP)={fp}  skip={skip}")
    print(f"# FP-suppression rate = {tn}/{tn+fp} = "
          f"{(tn/(tn+fp)*100) if (tn+fp) else 0:.0f}%   FN = {fn} (MUST be 0)")
    print(f"# accuracy = {(tp+tn)}/{total} = {((tp+tn)/total*100) if total else 0:.0f}%")
    return 1 if fn > 0 else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--all", action="store_true", help="sweep all labeled corpora (~61) not just base 16")
    ap.add_argument("--out", default="/Users/seant/code/vlbench-strix/results/verifier_eval.json")
    args = ap.parse_args()
    return asyncio.run(run(args.model, args.out, use_all=args.all))


if __name__ == "__main__":
    raise SystemExit(main())
