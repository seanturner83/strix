# SEC-6848 W4 — SCIP code-graph validation plan

W4 of the Tier-2 code-graph integration validates that the new tools
(W1+W2 shipped, W3 prompt landed on `seedcx-build@2f9a174`) actually
reduce scan cost without hurting finding parity. Methodology, target
SHAs, metrics, success criteria.

## Hypothesis

Pre-indexing the target with SCIP and exposing `find_definition` /
`find_references` / `get_imports` / `get_symbol_at` to the LLM cuts
total input tokens by ≥30% on a structurally-anchored SAST scan, while
finding at least the same vulnerabilities as the no-graph baseline.

The pre-registered prediction: on the trade-api targeted-rescan
analog, the agent reaches the 5 "missing-middleware" findings
(vuln-0006, 0007, 0008, 0010, 0011 from run 26717626470) in fewer
iterations and without grep-walking the routers.

## Validation targets

| Target | Language | SHA | Baseline run | Why |
|---|---|---|---|---|
| seedcx/trade-api | TS | `9cd8931f270c6f850ee3b3b0842a8d0156bb197f` | strix-scan-workflow #26717626470 (2026-05-31) | The 11-finding triage we just did. Same-SHA replay = apples-to-apples comparison. |
| seedcx/funding-service | Go | latest main HEAD at run time | most-recent funding-service targeted-rescan | Go-path coverage. scip-go behaviour at scale. |
| seedcx/portal-api | TS | `c32fc9e4` (post-PR-#1668 / matt's APPSEC-693 fix) | None — fresh scan | Sanity check: does the agent re-derive the structural conclusion that #1668 already validated? |

Same-SHA replay matters: it isolates "what changed when we added graph
tools" from "what changed in the target codebase between runs". Don't
let the trade-api run drift off `9cd8931f` even if main has moved.

## Dispatch shape (controlled one-off)

Per session-end decision (option b: validate before promoting):

1. Trigger `build-sandbox` workflow on strix-scan-workflow with
   `STRIX_REF=2f9a174` to produce a per-SHA-tagged image containing
   the new SCIP indexers + scip CLI. Do NOT promote it to the default
   tag yet.
2. Dispatch `strix-targeted-rescan` (the named workflow per memory
   `feedback_strix_dispatch_workflow.md`) with explicit overrides:
   - `STRIX_REF=2f9a174`
   - sandbox image pinned to the W3.4 build tag
   - target_repo + target_sha per table above
3. Capture run artefact, conversation.jsonl, vulnerabilities/*.md,
   sarif.

## Metrics (extracted from run artefact)

### Cost metrics

| Metric | How extracted | Floor for success |
|---|---|---|
| Total input tokens | sum of `events.jsonl` token-usage entries | -30% vs baseline |
| Wall time | `session_meta.json` end - start | informational; no floor |
| Iteration count | distinct turns in `conversation.jsonl` | informational; no floor |

### Behaviour metrics

| Metric | How extracted | Expected |
|---|---|---|
| `code_graph_*` tool-call count | grep tool-call events in conversation.jsonl | ≥5 (the 5 missing-middleware findings each warrant one find_references) |
| `search_files` + `grep` + `sg run` count | same | proportional reduction |
| code_graph-to-grep ratio | derived | ≥1:2 (graph at least half as common as raw grep when both apply) |
| "code graph not available" outputs | grep tool-result events | 0 for TS+Go targets; non-zero is a regression |

### Quality metrics

| Metric | How extracted | Floor for success |
|---|---|---|
| Finding parity | compare vulnerabilities/*.md titles vs baseline | 11/11 on trade-api |
| New findings | vulnerabilities/*.md count - baseline count | informational; net-positive is win |
| False positive rate | manual review per finding | no FP regression vs baseline |

## Comparison harness

A small Python script under `tests/integration/sec_6848_validation/`
(not shipped to prod runtime) consumes the two `conversation.jsonl`
files (baseline + experiment) and emits:

- Tool-call histogram, side by side
- Token-usage timeline, side by side
- Finding-title diff (set difference)
- Per-finding iteration-cost (rough — count iterations between
  the agent's first mention of the topic and the `create_vulnerability_report` call)

Output is a markdown table + a JSON dump for follow-up analysis. Not
fancy; the run artefacts contain all the structure we need.

## Failure-mode catalogue

Before declaring a run failed, check for these "code-graph degraded"
paths:

| Symptom | Likely cause | Diagnostic |
|---|---|---|
| "code graph not available" output | indexer didn't run at sandbox setup | check container logs for `_build_code_graph_index` stderr |
| "code graph not available" only on TS or only on Go | one of the indexers missing in image | `which scip-typescript scip-go scip` inside the image |
| Indexer ran but query tools return zero results | SQLite schema differs from expected; conversion failed | `sqlite3 /app/runtime/code_graph/*/code_graph.sqlite ".schema"` |
| Tool registry doesn't expose code_graph_* | seedcx-build didn't pick up the merge | check STRIX_REF actually matches 2f9a174 |
| Indexer crashes mid-scan | scip-typescript chokes on a tsconfig variant | check `_build_code_graph_index` exit code, log capture |

## Decision tree post-run

```
trade-api run done
   ├── finding parity ≥11/11
   │     ├── input tokens -30%+ → SUCCESS, proceed to fund-svc + portal-api
   │     ├── input tokens -10..-30% → MIXED, run portal-api to triangulate
   │     └── input tokens -<10%  → FAIL, retro before broader rollout
   └── finding parity <11/11
         ├── all missed are non-structural → flag prompt-side issue
         └── any structural missed → CRITICAL, do not promote
```

## Out of scope for W4

- Multi-language merge — scip-typescript+scip-go single-repo merge is
  W2 follow-up; trade-api validation uses TS only (Go bits in trade-api
  are minimal and not the structural risk surface).
- `find_implementations` — W2 stub; expect 0 useful results, that's
  intentional.
- Repos without supported languages (Rust-only, Python-only) — W5
  scip-python lands first.

## What "promote" looks like (W3.4 + W3.5)

If W4 clears the floors:
1. PR on `strix-scan-workflow` advancing `STRIX_REF` default
   `831df8d → 2f9a174`.
2. PR on `strix-scan-workflow` promoting the W3.4 image tag to the
   default sandbox tag.
3. Update memory: bump `project_strix_anthropic_auth_deferred.md`'s
   STRIX_REF note + `project_strix_pr_pilot.md` if any pilots care.
4. Announce via the usual Slack channel that code_graph tools are
   live; flag the new prompt section so the team knows what changed.

If it doesn't clear: write up the diagnostic from the failure-mode
catalogue, retro the gap on SEC-6848, iterate.

## Refs

- SEC-6848 — Tier-2 code-graph integration parent ticket.
- strix-scan-workflow run 26717626470 — baseline.
- `strix/tools/code_graph/README.md` — module README + W1 smoke data.
- This branch: seedcx-build @ 2f9a174 = sec-6848/scip-indexer-w1.
