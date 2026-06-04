# code_graph — SCIP-backed structural queries for Strix (SEC-6848)

Pre-compute a code-intelligence index per scan so the agent can answer
structural questions (`find_references(X)`, `find_definition(X)`,
`find_implementations(I)`) via a single tool call instead of grepping the
filesystem each iteration.

## Why

The trade-api Strix run 26717626470 produced 11 findings on 2026-05-31, of
which 5 are "this route is missing a middleware mount" (vuln-0006, 0007,
0008, 0010, 0011 — `checkCustomerAccountPermission`,
`checkPayorCodePermission`). Each cost the LLM multiple iterations of
file-read + grep to discover. A `find_references(checkCustomerAccountPermission)`
call returning the 12 mount sites would have produced the answer in one
tool invocation — same shape Hunt uses against Phoenix's graph backend at
~$8/mo vs Strix's $515/mo.

## Phasing (SEC-6848)

| Phase | Scope | Status |
|---|---|---|
| W1 | Indexer install in sandbox + this module skeleton | shipped this branch |
| W2 | SCIP-loader + 5 tools registered to Strix tool registry + unit tests | next |
| W3 | Strix-fork integration on seedcx-build + prompt-side guidance | |
| W4 | E2E validation against trade-api rescan + funding-service + portal-api | |
| W5-6 | scip-python; broader rollout | |

## Sandbox tooling (added W1)

| Binary | Source | Version | Image install line |
|---|---|---|---|
| `scip-typescript` | npm `@sourcegraph/scip-typescript` | 0.4.0 | global npm install |
| `scip-go` | `github.com/scip-code/scip-go/cmd/scip-go` | v0.2.7 | go install |
| `scip` (CLI) | `github.com/sourcegraph/scip` releases | v0.8.0 | tarball into `/usr/local/bin` |

All pinned. Pin bumps must re-validate against the local smoke suite (see
`Smoke validation` below) before landing on `seedcx-build`.

## Smoke validation (local, 2026-06-04)

| Repo | Indexer | Wall time | SCIP size | Symbols | Sample query that worked |
|---|---|---|---|---|---|
| seedcx/portal-api @ HEAD | scip-typescript 0.4.0 | ~500 ms | 3.25 MB | 5,267 | `find_references(authorizeToParticipantAndAdminRole)` → 14 sites across 8 files (incl. the APPSEC-693 fix mount at participant-router.ts) |
| seedcx/payment-orchestrator @ HEAD | scip-go v0.2.7 | ~32 s | 8.9 MB | 5,197 | catalog includes `PlatformApiKey` (APPSEC-698 finding) and `PaymentsServiceValidatePayoutRequest` |

## Module layout

- `indexer.py` — `build_index(target_dir, out_dir)` runs the appropriate
  SCIP indexer(s), converts to SQLite via the `scip` CLI, returns the
  path. `load_index(path)` is a W2 stub.
- `__init__.py` — re-export of the two functions.

## W2 design preview

Tools to be registered (XML schema next to a `code_graph_actions.py` once
W2 lands):

| Tool | Inputs | Returns |
|---|---|---|
| `find_definition` | symbol name | file:line of declaration |
| `find_references` | symbol name | list of (file, line, kind) — kind ∈ {def, ref, write, read} |
| `find_implementations` | interface name | list of (file, line, type) |
| `get_imports` | file path | list of imported modules/symbols |
| `get_symbol_at` | file, line, col | symbol name at that cursor position |

Query layer is a single SQLite handle against the converted index. Tools
should cap results at ~50 rows per call with a `cursor`-style paginator
for the long-tail case (e.g. high-fanout utility imports).
