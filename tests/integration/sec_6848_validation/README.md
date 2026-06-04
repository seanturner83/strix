# SEC-6848 W4 validation harness

Compares two Strix run artefacts (baseline vs experiment) to measure
the impact of the W1-W3 code-graph integration.

## Usage

```bash
# Inside the strix repo, with uv-managed env:
uv run python -m tests.integration.sec_6848_validation.compare_runs \
  --baseline   /path/to/baseline/run_dir/target_xxxx \
  --experiment /path/to/experiment/run_dir/target_yyyy \
  --output     /path/to/report.md \
  --json-output /path/to/metrics.json
```

`run_dir/target_xxxx` is the directory containing `conversation.jsonl`,
`events.jsonl`, `session_meta.json`, `vulnerabilities.csv` and
`vulnerabilities/*.md` — i.e. the contents of the artefact zip that
strix-scan-workflow uploads.

## What it measures (from artefact only)

- **Iterations**: max iteration index in conversation.jsonl.
- **Wall time**: `run.completed` − `run.started` from events.jsonl.
- **Findings**: count + title-set diff + severity distribution.
- **Tool-call histogram**: extracted by regex from assistant messages
  (`<function=NAME>`). Side-by-side with delta column.
- **`code_graph_*` calls**: filtered out of the histogram for the
  headline integration-live metric.
- **Shell-grep proxies**: count of `grep` / `rg` / `ast-grep` / `sg` /
  `semgrep` / `find -name` patterns inside `terminal_execute` /
  `batch_terminal_execute` commands. Approximate signal for "how
  much grep-walking did the agent do" — code_graph should displace
  most of these.
- **'code graph not available' responses**: count of degraded-path
  outputs in user-role tool result messages. Non-zero on a
  supported-language run = sandbox image is missing the indexers.

## What it does NOT measure

- **Input/output tokens**: not in the artefact; pull from Bedrock
  CloudWatch separately if needed.
- **Cost in dollars**: requires LLM-provider billing data, same.
- **Code-quality of findings**: this is a quantitative comparison;
  manual review per finding still needed for the promote decision.

## Baseline reference (run 26717626470, trade-api @9cd8931f)

For sanity calibration:

| Metric | Value |
|---|---:|
| Iterations | 80 |
| Wall time | ~100 min |
| Findings | 11 (4 CRIT, 6 HIGH, 1 MED) |
| `terminal_execute` calls | 21 |
| `str_replace_editor` calls | 22 |
| `create_agent` (sub-agents) | 17 |
| Shell-grep proxies | 27 |
| `search_files` | 1 |
| `code_graph_*` | 0 (pre-integration) |

The W4 experiment against the same SHA + new STRIX_REF should keep
all 11 findings (no regression) and show:

- non-zero `code_graph_*` calls (≥5 per W4 plan hypothesis)
- reduced shell-grep proxies
- reduced or constant iteration count

## Output

Markdown report to `--output` (or stdout); JSON metrics dump to
`--json-output` if specified.
