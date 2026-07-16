# seedcx/v1.1-integration — Fork Delta & Disposition

> **Current-state analysis of what this fork carries on top of stock upstream Strix `v1.1.0`.**
> Supersedes the v1.0-era `MIGRATION_PLAN.md` (that plan targeted v1.0.4; v1.1 landed
> fast and the plan is stale). This is the delta as of **2026-07-16**, computed from
> `git log upstream/main..seedcx/v1.1-integration` (base = upstream `v1.1.0`, `91d9a84`).
>
> **Bottom line:** ZH runs v1.1 in CI today on this build — nothing external gates
> *running* it. The fork is **16 commits / 28 files / +3595-1502** over stock. This
> doc gives each a verdict: **CONTRIBUTED** (PR in flight), **CONTRIBUTE** (candidate),
> **MEASURE-FIRST** (unproven lever), **RETIRE-ON-DEP** (delete when a dependency
> releases), or **KEEP-FORK** (deliberately ours). Upstream convergence only makes the
> fork *thinner*; it is not an adoption blocker.

## Summary table

| Commit | Change | Files | Verdict |
|---|---|---|---|
| `e0619cd` | Bedrock/Anthropic prompt caching (`cache_control_injection_points`) | inputs.py | **CONTRIBUTED** — usestrix #772 (open; hardened 2026-07-16 for unmapped-Bedrock models) |
| `67b1032` | `retract_vulnerability_report` primitive (resume-gated) | state.py, retract_tool.py | **CONTRIBUTED** — usestrix #773 (open) |
| `47de348` | wire sandbox reader into retract groundedness guard | runner.py, retract_tool.py | **CONTRIBUTED** — #773 |
| `69d68ee` | decode sandbox-reader bytes for retract guard | runner.py | **CONTRIBUTED** — #773 |
| `bbed19e` | Bedrock explicit clamped output ceiling | models.py, inputs.py | **CONTRIBUTED** — usestrix #625 (open) |
| `bfb4c07` | `batch_view_files` / `batch_terminal_execute` sandbox-side concurrency | tools/batch/ | **CONTRIBUTE** — evidence-backed (see below) |
| `ae6108c` | per-role model config (orchestrator/sub-agent/compressor/reporting) | models.py, runner.py, execution.py | **CONTRIBUTE** — candidate, no PR yet |
| `b594b08` | `--run-name` deterministic, resumable run dirs | main.py | **CONTRIBUTE** — part of resume/CLI contract |
| `0918df4` | boto3 as a CORE dep (not `[bedrock]` extra) | pyproject.toml, uv.lock | **CONTRIBUTE** — trivial; or moot if upstream folds bedrock into core |
| `e877378` | STRIDE threat-modeling skill + scan-mode framing | skills/ | **KEEP-FORK** — skill is derivative-licensed (wshobson/Shostack), stays fork-local by decision; the SARIF-CWE half already merged as #708 |
| `80b7ba4` | `STRIX_LLM_DEDUP` cheap-model dedup role | settings.py, dedupe.py | **MEASURE-FIRST** — unproven lever (see below) |
| `9e38097` | shim: strip `toolSpec.strict` for Bedrock Claude | litellm_bedrock_strict_patch.py | **RETIRE-ON-DEP** — delete when litellm ships #32455/#32605 |
| `3ffa65c` | refusal fallback + bounded recovery for content-filtered turns | inputs.py, execution.py | **RETIRE-ON-DEP** — backed by merged openai-agents #3769; crutch until a litellm release carries it |
| `0a42c4e`,`d1f26e4`,`2c1a082` | tests for the above (resume/SARIF/retract, per-role, cred-boundary) | tests/, validate_resume_handoff.sh | ride with their features |

**Not in this delta anymore:** SCIP code-graph. The v1.0 plan called it "the highest-leverage single port." It is now an **external addon** (`seanturner83/strix-code-graph`, published 2026-07-16), plugging in via the `register_session_setup` hook (usestrix #781). It is no longer fork-carried code — that migration item is closed by extraction, not port.

## Evidence & rationale for the non-obvious verdicts

### `bfb4c07` batch tools → CONTRIBUTE (evidence-backed)

The v1.0 plan flagged batch tools as "port concept not code — v1.x batches natively via
`parallel_tool_calls`, but sandbox-side batch tools still valuable." **Confirmed valuable,
with data.** Across 2026-07-16's real multi-repo scans, both models invoked the batch
tools **unprompted** (no instruction mentioned "batch"):

| Scan | Model | `batch_view_files` | `batch_terminal_execute` |
|---|---|---|---|
| scan-1a25c6ee | sonnet-5 | 11 | 19 |
| scan-d73af163 | sonnet-5 | 4 | 4 |
| scan-79ecbb29 | sonnet-5 | 3 | 0 |
| scan-a321f8c9 | opus-4-8 | 7 | 0 |
| scan-1829af72 | opus-4-8 | 5 | 0 |

Both tiers adopt them natively; they are a clean, model-agnostic sandbox-concurrency
capability with no ZH-specific coupling → good upstream PR.

### `80b7ba4` STRIX_LLM_DEDUP → MEASURE-FIRST (do not contribute or keep until measured)

`report/dedupe.py:329` makes its **own** LLM call; `STRIX_LLM_DEDUP` (settings.py:37)
routes it to a separate, cheaper model, falling back to base. The premise — dedup is
high-volume + low-judgment, so a cheap model saves cost without hurting quality — is
**unmeasured on v1.1**. Both sides of the trade are currently unknown:

1. **Benefit unknown:** is dedup a material share of scan spend? With prompt-caching now
   restored (0→57% cache-read), the dedup call may be noise against the main agent loop.
2. **Cost unknown:** a dedup error is asymmetric — a false *split* files a duplicate
   (noise); a false *merge* collapses a real finding into a dupe (a **miss**). Needs a
   measured false-merge / false-split rate for the cheap model vs. the orchestrator model.

Gate any disposition on: (a) dedup's % of scan cost, (b) cheap-model dedup accuracy vs.
base. Same discipline as the L1/L2 cost-lever measurement work — measure the lever before
pulling it. Until then: **hold** (keep the knob, default it OFF / to base model).

## What "waiting for upstream" actually buys (shim deletion, not capability)

- litellm #32455 (strict-tools drop) + #32605 (parallel-tool-choice `type`) ship in a
  release → delete `9e38097` (and the fork's `litellm_bedrock_strict_patch.py`).
- usestrix #772 / #773 / #625 / #781 merge → drop the corresponding fork commits and
  rebase onto stock.
- None of the above blocks running v1.1. They reduce fork divergence on upstream's
  review timeline, with zero dependency from ZH's side.

## Net state (2026-07-16)

- **Run v1.1 in CI: yes, today, on this build.** Resume/cred-refresh contract is in CI;
  retract contributed; SCIP externalized.
- **Fork = thin shim over v1.1**, not a divergent branch: 16 commits, most already
  contributed or on a clear retire-on-release path.
- **Open analysis work:** measure the dedup-LLM lever; decide `ae6108c`/`bfb4c07`/`b594b08`
  contribution timing.
