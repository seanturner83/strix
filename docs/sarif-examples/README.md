# SARIF example outputs

Real SARIF 2.1.0 files produced by the combined SARIF emitter against
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (a deliberately
vulnerable web application). All three files are native strix output with no
hand-editing.

## The three runs

| File | Scan mode | Target | Findings | Results w/ locations | Locationless |
|---|---|---|---|---|---|
| `juice-shop-sast.sarif` | White-box | Source on disk | 13 | 13 | 0 |
| `juice-shop-dast.sarif` | Black-box | `http://localhost:3002` | 11 | 0 | 11 |
| `juice-shop-crystalbox.sarif` | Crystal-box | Source + live target | 13 | 13 | 0 |

Crystal-box is the interesting one: the agent has both source access AND a
live target, and it ties every finding to a source location while also
confirming runtime reachability. SAST alone finds 13 but cannot confirm
reachability; DAST alone finds 11 but cannot link them to source.

## How these SARIF outputs demonstrate the combined emitter

Open any of the files and you'll see:

- **Rule-level GitHub code-scanning properties** — `rule.properties.security-severity`,
  `rule.properties.tags`, `rule.helpUri` to the relevant `cwe.mitre.org` page.
- **Stable CWE-normalised rule IDs** — the same weakness expressed as
  `CWE-89`, `cwe:89`, or `89` in the underlying finding metadata all resolve
  to rule ID `CWE-89` in the SARIF.
- **PoC content namespaced** under `result.properties.strix.poc` rather than
  flat on `result.properties` so generic SARIF UI consumers don't surface
  exploit text to triage audiences by default.
- **Locationless findings summarised** in `run.properties.locationlessFindings`
  (see `juice-shop-dast.sarif` for all 11 entries) rather than emitted as
  invalid code-scanning alerts.

## How to upload to GitHub code-scanning

```yaml
- name: Run strix
  run: strix --target ./app --scan-mode quick --sarif

- name: Upload SARIF to code-scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: strix_runs/*/findings.sarif
    category: strix
```

## How they were generated

```bash
# SAST
strix --target /path/to/juice-shop-src --scan-mode quick -n --sarif \
      --sarif-output sast.sarif

# DAST
strix --target http://localhost:3002 --scan-mode quick -n --sarif \
      --sarif-output dast.sarif

# Crystal-box (both targets; agent uses source to target live probes)
strix --target http://localhost:3002 --target /path/to/juice-shop-src \
      --scan-mode quick -n --sarif --sarif-output crystalbox.sarif
```

The tracer-sidecar path writes `findings.sarif` into the run dir regardless
of the `--sarif-output` flag — these three files came from the tracer hook.
