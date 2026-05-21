# Strix tool-call parallelism — design memo

Codebase: `usestrix/strix` @ `dc39531..feat/per-role-llm-config`.
Author: Sean Turner / SecOps Ltd.
Phase 1.5 of the Strix-efficiency programme. Goal: let agents emit and execute multiple independent tool calls in a single turn. Backwards compatible. Aim upstream PR.

## Why this matters

Strix today executes **one tool per agent turn**, even when the work is structurally parallel. On scans we just measured:

| Scan | Tools | Wall-clock | Tools/min |
|---|---|---|---|
| Juice Shop (per-role) | 11 | 4 min | 2.7 |
| MyMir Funnel (per-role) | 58 | 30 min | 1.9 |
| tf-k8s-app-addons (per-role) | 75 | 74 min | 1.0 |

Each tool invocation costs 1 LLM round-trip (typically 5-15 s of orchestrator wall-clock on Bedrock cached). With strict serialisation, scan duration is **bounded below by tools × LLM-RTT**. On the tf-k8s scan, that's a 75-tool × ~10 s lower bound = **12.5 minutes of pure LLM wait**, even with infinitely fast tool execution.

Many tools are **trivially independent and side-effect-free**: `list_files`, `search_files`, `str_replace_editor` (read-mode), `view_request`, `view_sitemap_entry`. Other categories (HTTP probes, `terminal_execute`-style readonly commands) are also typically safe to parallelise within a turn. Letting one LLM turn batch N of these into one round-trip cuts that lower bound by ~Nx.

**Realistic gain estimate:** 30-50% wall-clock reduction on probe-heavy / file-heavy scans. The funnel scan with 58 tools at avg-batch-of-2 would drop ~10 min → ~5 min on pure round-trip savings.

## Surface area — where serialisation is enforced today

There are **four enforcement points** that make today's behaviour serial. All of them must be loosened to permit parallel tool calls.

### 1. Streaming-side early termination (`strix/llm/llm.py:217-228`)

```python
if "</function>" in check_content or "</invoke>" in check_content:
    end_tag = "</function>" if "</function>" in check_content else "</invoke>"
    pos = _find_end_tag_outside_thinking(accumulated, end_tag)
    accumulated = accumulated[: pos + len(end_tag)]
    yield LLMResponse(content=accumulated)
    done_streaming = 1
    continue
```

The moment the LLM closes its first function call, the streamer freezes the content at that point and starts winding down. The LLM physically cannot emit a second tool call.

This is a **defensive truncation** — the LLM was being trained/prompted to emit one call but would sometimes hallucinate into a second. The fix is to make this conditional on either a config flag or a model-capability check.

### 2. Belt-and-braces parse-step truncation (`strix/llm/utils.py:74-87`)

```python
def _truncate_to_first_function(content: str) -> str:
    function_starts = [
        match.start() for match in re.finditer(r"<function=|<invoke\s+name=", content)
    ]
    if len(function_starts) >= 2:
        second_function_start = function_starts[1]
        return content[:second_function_start].rstrip()
    return content
```

Even when the streaming-side somehow lets a second function call through (e.g. multiple `<function=…>` blocks already buffered in the same chunk), this regex strips them out at parse time.

Same fix: gate behind config / capability.

### 3. System prompt instruction (`strix/agents/StrixAgent/system_prompt.jinja`)

Two places explicitly tell the LLM to emit exactly one tool call:

- `EVERY message while working MUST contain exactly one tool call`
- `EVERY message you output MUST be a single tool call`

Even with the parser/streamer relaxed, the LLM won't emit multiple tool calls unless told it can. The prompt needs a parallel-aware variant for capable models.

### 4. Sequential executor (`strix/tools/executor.py:313-342`)

```python
async def process_tool_invocations(tool_invocations, conversation_history, agent_state):
    ...
    for tool_inv in tool_invocations:                      # ← serial
        observation_xml, images, tool_should_finish = await _execute_single_tool(...)
        observation_parts.append(observation_xml)
        ...
```

Already takes a list, just iterates serially. Replacing the for-loop with `asyncio.gather(...)` is the core executor change. Modest — except for the safety considerations below.

## What's *not* in scope for Phase 1.5

- **Tool dependency analysis.** The LLM picks which tools to batch, not us. We do not attempt to infer "tool A depends on tool B's output."
- **Cross-turn parallelism.** Agents still produce one assistant message per turn; we just allow that message to contain multiple tool calls.
- **Sub-agent parallelism.** Already exists via `parallel_create_agent`; this PR is about within-agent parallelism, orthogonal axis.
- **Mid-execution cancellation.** If one tool errors, we still wait for siblings to complete. Cleaner semantics than partial-cancel.

## Proposed design

### Tool category taxonomy

Tools fall into three classes for parallelism purposes:

| Class | Description | Examples | Parallel-safe? |
|---|---|---|---|
| **Read-only / side-effect-free** | Inspect external state, no mutation | `list_files`, `search_files`, `view_request`, `view_sitemap_entry`, `view_agent_graph` | Yes |
| **External I/O with no shared state** | HTTP/network probes, command exec, terminal | `send_request`, `terminal_execute` (readonly), `python_action`, `repeat_request` | Yes — sandbox isolation handles it |
| **Mutating / order-sensitive** | Tools that modify shared state, file edits, finish/agent-finish | `str_replace_editor` (write mode), `create_agent`, `agent_finish`, `finish_scan`, `send_message_to_agent`, `create_note`, `load_skill`, `update_todo` | **No** — must execute sequentially or alone in a batch |

### Tool registry: `parallel_safe` flag

Add a `parallel_safe: bool = False` parameter to `register_tool`:

```python
@register_tool(parallel_safe=True)
def list_files(...): ...

@register_tool(parallel_safe=True)
def search_files(...): ...

@register_tool  # default False; mutating tools stay safe
def create_agent(...): ...
```

Default to `False` to preserve current behaviour for any tool not explicitly opted in. **Allowlist, not blocklist** — safer rollout.

### Executor: batch with safety guard

```python
async def process_tool_invocations(tool_invocations, conversation_history, agent_state):
    tracer, agent_id = _get_tracer_and_agent_id(agent_state)

    if _all_parallel_safe(tool_invocations) and len(tool_invocations) > 1:
        results = await asyncio.gather(
            *[
                _execute_single_tool(inv, agent_state, tracer, agent_id)
                for inv in tool_invocations
            ],
            return_exceptions=True,
        )
    else:
        results = []
        for inv in tool_invocations:
            results.append(await _execute_single_tool(inv, agent_state, tracer, agent_id))

    # Aggregate results in invocation order (preserves observation ordering)
    ...
```

Safety properties:

- If *any* invocation in the batch is not `parallel_safe`, fall back to sequential.
- `return_exceptions=True` so one failing tool doesn't kill siblings; failures are reported individually in the observation block.
- Observations are aggregated in *invocation order*, not completion order — preserves deterministic conversation state.

### Streaming + parser: gate on tool mode

Add `STRIX_TOOL_MODE` (default `serial`). Values:

| Value | Meaning |
|---|---|
| `serial` (default) | Today's behaviour — one tool per turn, all enforcement on |
| `parallel` | Allow multiple `parallel_safe` tools per turn; mutating tools still serial-only |
| `unrestricted` *(reserved)* | Future tier — no safety guard. Not implemented in 1.5a; raises NotImplementedError if set. |

When mode is `parallel`:

- `_stream` doesn't early-exit on first `</function>` — keeps reading until natural stream end.
- `_truncate_to_first_function` no-ops.
- System prompt branches to a parallel-aware variant.
- Executor groups `parallel_safe` invocations through `asyncio.gather`.

Implementation: store on `LLMConfig` (constructor param `tool_mode: str = "serial"`, reads `STRIX_TOOL_MODE`). Stream/parser read `self.config.tool_mode`.

### System prompt: parallel-aware variant

New template branch (in `system_prompt.jinja`):

```jinja
{% if tool_mode == "parallel" %}
- You MAY emit multiple independent tool calls in a single message when they are mutually independent and can run in parallel (e.g. multiple file reads, multiple HTTP probes against different endpoints).
- Do NOT batch tool calls if the second depends on the first's output — emit those sequentially over multiple turns.
- Do NOT batch mutating tools (file writes, agent creation, finish_scan) with anything — emit each on its own turn.
- For independent reads, batching 2-5 calls per message is encouraged. Do not exceed 8.
{% else %}
- EVERY message while working MUST contain exactly one tool call ...
{% endif %}
```

Capability gate: only enable for models known to handle multi-tool emission well (Claude 3.5+, GPT-4o+, Opus 4.x+). Models that struggle (smaller local models) keep the single-tool prompt. Use `litellm.supports_function_calling()` plus a curated allowlist.

### LLMConfig: new field

```python
_VALID_TOOL_MODES = ("serial", "parallel")  # "unrestricted" reserved

class LLMConfig:
    def __init__(self, ..., tool_mode: str | None = None):
        if tool_mode is None:
            tool_mode = Config.get("strix_tool_mode") or "serial"
        if tool_mode not in _VALID_TOOL_MODES:
            raise ValueError(
                f"Invalid tool_mode: {tool_mode!r}. Expected one of {_VALID_TOOL_MODES}."
            )
        self.tool_mode = tool_mode
```

Default: `serial` (full backwards compatibility — explicit opt-in to parallel).

### Tracer: per-tool span IDs, batch grouping

Already invokes `tracer.log_tool_execution_start` per tool — that's per-tool span. Need to add a `batch_id` to group spans that fired in the same agent turn so OTel queries can answer "how often does the agent batch tools?" Trivial: pass `batch_id=uuid4()` from `process_tool_invocations` into each `log_tool_execution_start`.

## Migration / rollout

1. **Phase 1.5a (this PR):** Land the executor change + mode + prompt variant. **Default `serial`.** Mark a small set of obviously-safe tools as `parallel_safe=True` (file reads, HTTP probes, view-only proxy actions). Anyone who sets `STRIX_TOOL_MODE=parallel` gets parallelism for those tools; everyone else is unaffected.

2. **Phase 1.5b:** Telemetry-driven safety expansion. Once 1.5a has been in production for a fortnight and OTel shows no regressions, expand `parallel_safe=True` to more tools (proxy `send_request`, terminal readonly commands).

3. **Phase 1.5c:** *Not* a default flip. Stays opt-in. The `parallel` mode is a deliberate user choice, not a silent upgrade — same posture as `--scan-mode deep` (you don't get it unless you ask). Default flip would only be considered after Phase 2 (embedding memory) lands and removes the few remaining failure modes for parallel batches.

## Risk register

| Risk | Mitigation |
|---|---|
| LLM emits parallel calls that *aren't* actually independent (e.g. write-then-read of same file) | Allowlist of `parallel_safe=True` tools — write tools are not in the list, so any batch involving a write falls back to serial. |
| Sandbox concurrency limits (Docker exec, terminal sessions) | Cap parallel batch size per sandbox; if under-resourced, fall back to serial transparently. |
| Order-dependent observations confuse the LLM | Observation block always presented in invocation order, not completion order. LLM sees what it asked for. |
| Tracer / OTel double-emit spans | Each tool execution is its own span with its own execution_id; batch_id ties them together for analysis but spans remain independent. |
| Token-cost reasoning becomes harder to predict | Stats aggregation already per-`LLM` instance, parallelism doesn't change billing — only wall-clock. |
| Cancellation semantics | Already handled today via `_current_task` on BaseAgent. Replace single task with task-group; cancellation propagates to all siblings. |

## Effort estimate

| Step | Effort |
|---|---|
| 1 — Add `parallel_safe` flag to `register_tool` + decorate ~5-8 obvious tools | 30 min |
| 2 — `process_tool_invocations` batch-with-fallback + `asyncio.gather` | 30 min |
| 3 — `STRIX_TOOL_MODE` env var + `LLMConfig.parallel_tools` field | 20 min |
| 4 — Loosen `_stream` early-exit + `_truncate_to_first_function` (gated) | 20 min |
| 5 — System-prompt parallel-aware template branch | 15 min |
| 6 — — *(removed: capability auto-detect not needed — mode is explicit user opt-in)* | 0 min |
| 7 — Tracer `batch_id` plumbing | 10 min |
| Tests (parallel-safe enforcement, fallback on mixed batch, env-var resolution, multi-tool parse) | 90 min |
| Smoke scan with flag on (juice-shop A/B against current main) | 20 min |
| PR description + before/after numbers | 30 min |

**Total: ~4.5 hours focused work.**

## What this enables next

- **Phase 1.5 follow-up:** Per-sub-agent-type roles (`STRIX_LLM_CODE`, `STRIX_LLM_VISION`, `STRIX_LLM_TRIAGE`) — parallelism makes specialised cheap-model classifiers more attractive (latency was the blocker before).
- **Phase 2 prep:** Embedding memory's vector-retrieval is itself a "tool call" that benefits from being parallel with other recon tools.
- **Tool-output streaming:** Once batched, tool results can be streamed back to the LLM as they complete (rather than holding the whole batch). Future work.

## Open questions

1. Should `parallel_safe` be a tool-property or a per-invocation runtime check (e.g. `str_replace_editor` is safe in `view` mode but not `create`)? **Current proposal: tool-property only.** Mode-aware would require the registry to inspect args, complicating safety reasoning.
2. Should the cap on batch size (8 in proposal) be a config knob? **Current proposal: hardcoded.** Empirically motivated; revisit if real demand surfaces.
3. Does the parallel-aware system prompt need the same care as scan-mode-conditional skills? **Current proposal: simple jinja branch.** Sufficient for v1.
4. Should `STRIX_TOOL_MODE` be a per-role var (orchestrator-only, sub-agent-only)? **Current proposal: global mode.** Per-role can be added later if telemetry shows differential behaviour. Natural extension once telemetry shows where parallelism actually pays off — sub-agent orchestrators may want it more than root orchestrators.

## Validation plan

A/B comparison on **juice-shop quick scan** (the smallest reliable workload):

- **Arm A (control):** `STRIX_TOOL_MODE=serial` (today's behaviour, also the default). Run 3 times, record wall-clock + total cost.
- **Arm B (parallel):** `STRIX_TOOL_MODE=parallel`. Run 3 times, record wall-clock + total cost + max batch size observed in OTel.

Hypothesis: B saves 20-40% wall-clock with no quality regression. If wall-clock saving is <10% the feature isn't worth shipping.

If A/B passes: extend to **funnel scan** (web target, more independent probes — should show larger gains) and **tf-k8s scan** (large file enumeration phase — should show very large gains).
