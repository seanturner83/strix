# seedcx/strix: v1.x Migration + Forward-Port Plan

Status: draft, 2026-07-02. Companion to `origin/seedcx/v1.0.4-integration`.

## Context

`seedcx-build` forked from upstream `usestrix/strix` before upstream's
~130-commit SDK-harness migration (orchestration rewritten onto the OpenAI
Agents SDK; `strix/llm/` + `strix/sessions/` replaced by `strix/core/` +
`strix/report/`). Our fork stayed on the old architecture and grew ~150
commits of its own customization on top of it.

Goal: migrate seedcx onto upstream v1.x, porting whichever fork features
still earn their place, dropping whatever the new SDK harness now provides
natively, and upstreaming whatever is generalizable rather than
ZeroHash/seedcx-internal.

`origin/seedcx/v1.0.4-integration` (currently v1.0.4 + 3 commits: PR #626's
SARIF emitter + 2 Bedrock fixes) is the concrete integration branch this
plan targets.

## SARIF — already done, one loose thread

Upstream `usestrix/strix#626` ("feat(report): SARIF 2.1.0 emitter") is not a
third-party feature to catch up to — it's authored by us (`seanturner83`,
co-authored Claude Opus 4.8), and is the port of our own fork's SARIF work
(`strix/telemetry/sarif.py`, built across SEC-6635/SEC-6802/SEC-6941) into
upstream's new `strix/report/` layout. v1.0.4 had no SARIF emitter before
this. PR #626's tip (`c04f2ab`) is already *better* than our fork's original
in two places: PoC-script redaction (`poc.script_available` bool instead of
leaking the raw exploit code) and atomic writes (temp-file + `Path.replace`).

Loose thread: our merge commit `0ffa72b` ("Merge feat/sarif-combined")
silently dropped STRIDE-leg CWE tagging (10 `stride` hits → 0) during
conflict resolution — a regression, independent of the migration. PR #626
doesn't carry it either.

**Action:** re-add STRIDE CWE→tag mapping to PR #626 (or a fast-follow). No
other SARIF work is missing.

## Tier 1 — do first (small, upstream-worthy, unblocked)

| Item | What | Why now |
|---|---|---|
| STRIDE CWE→tag mapping | Re-add the dropped mapping to `sarif.py` | Regression fix, logic already written (see `5684f1d`, `498d594`) |
| STRIDE threat-modeling skill | Drop `strix/skills/methodologies/threat_modeling.md` (Shostack 4QF + STRIDE, MIT-licensed provenance intact) | Matches upstream's existing skill-contribution pattern, zero code changes |
| Evil-user-story prompt lens | Small edit to `scan_modes/deep.md`/`standard.md` — "As a `<actor>`, I want to `<action>`..." framing to suppress speculative-attacker-pedigree inflation | Generalizable prompt-quality win, pairs with the STRIDE skill PR; strip internal ticket/OKR framing from the commit message only |
| Sandbox image slimming | Drop man-db/docs/locales, `go clean -modcache` (~2GB) from `containers/Dockerfile` | Pure Docker hygiene, zero fork coupling, cherry-pick as-is |
| `Tracer.cleanup()` idempotency | The old `Tracer` class is gone, but `ReportState.cleanup()`/`save_run_data()` has the same unguarded re-entrancy hazard (atexit + signal handler + normal exit all call cleanup, 7+ call sites) | File as a fresh upstream finding against v1.0.4, not a diff port — re-implement the guard-flag pattern against the new class |

## Tier 2 — port the concept, not the code (moderate effort, real gaps in v1.x)

| Item | Gap in v1.0.4 | Port target | OSS candidacy |
|---|---|---|---|
| `retract_finding` primitive | Resume/rehydrate has no way to remove a finding re-verified as fixed — same fail-closed bug we fixed is still latent | `strix/report/state.py` / `writer.py`, reuse the groundedness guard | Strong — any resumable-scan user hits this |
| Per-role LLM config (orchestrator/sub-agent/compressor) | Zero per-agent model concept; no memory compressor exists upstream at all | Thread a role-scoped model resolver through `RunConfig` at each `spawn_child_agent` call | Strong — common cost-tiering ask, upstream has nothing here |
| `batch_*` server-side tools (`batch_terminal_execute`, `batch_view_files`, ...) | v1.0.4 hardcodes `parallel_tool_calls=False`; our old client-side parallel mode is obsolete once that flag flips, but sandbox-side true concurrency still needs dedicated tools | Reimplement as SDK `function_tool`s | Good, once ported |
| Bedrock retry/error-mapping hardening | SDK's native retry policy (`agents.retry.retry_policies.http_status`) matches only on status code, no body-string inspection — Bedrock 5xx-mis-mapped-to-400 still slips through | Custom `RetryPolicy` callback (SDK supports policy composition via `retry_policies.any(...)`); `seedcx/v1.0.4-integration` already has 2 live ports (`a950bad`, `3573b43`) — build on that, don't reimplement | Strong — frame as opt-in `bedrock_retry_policy()` |
| Memory-compressor module | Doesn't exist upstream | Fairly self-contained, ports close to as-is | The Bedrock `content_filtered` enum-mismatch fix specifically is a good small standalone PR |
| SCIP code-graph indexing (SEC-6848) | No code-intelligence layer at all upstream — biggest capability gap on this list | ~1700 LOC, shallow coupling (only touches old tool-registry + `docker_runtime.py` sandbox exec, both replaced). Swap to `@function_tool` + SDK `session.exec()` | Highest-leverage upstream PR candidate on the whole list |
| `--scope-paths` / diff-scope preload | Generically useful for any PR-triggered scan | Same files exist in similar shape in v1.0.4; straightforward re-port once the `strix-scan-workflow`-specific calling convention is genericized | Yes, once decoupled from our composite action |

## Drop / deprioritize

- **Cache-TTL tuning** — portable but pure cost-tuning specific to our scan-shape heuristics; not upstream-PR material.
- **Adaptive-thinking Opus 4.7+ patch** — a LiteLLM version-lag workaround, time-boxed relevance, low upstream value; recheck once LiteLLM catches up.
- **Container-name-collision fix** — moot for now; the fork's current SDK-based `docker_client.py` has no retry loop to patch until/unless retry logic gets added.

## Already superseded (don't re-suggest)

- Resume UX (`--resume`, status-bar hint, always-on agent-graph resume) — upstream's native SDK resume covers this; only the retract primitive (Tier 2) is a real gap on top of it.
- Cost ledger / LiteLLM-observed cost — different shape, equivalent coverage.
- Reasoning-effort registry gating + xhigh + Bedrock/Opus-4.7+ adaptive thinking — ours is more mature (Bedrock-specific), keep ours.
- Pluggable sandbox backend registry — same shape on both sides, just unpopulated.
- Vision-image-stripping, sandbox SIGKILL/container-race handling on quit — fork's existing mechanisms are equivalent or better.
- `web_search` error-leak, PyInstaller `gql` exclude, broader ANSI/control-byte stripping, `LLM_API_KEY` env mirroring — small upstream v1.0.4 fixes worth pulling into the fork regardless of migration sequencing, tracked separately from this plan.
