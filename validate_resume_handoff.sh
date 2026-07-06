#!/usr/bin/env bash
# Local proof of the Path-B resume-handoff mechanic the CI cred-refresh loop
# depends on: run with --run-name, KILL after real agent turns (simulating the
# 50-min STS-boundary timeout), then --resume the same name and confirm it
# picks up prior history and reaches run.json status=completed.
#
# No `timeout` binary on this Mac — use a kill -0 poll loop (same pattern the
# connect-ios monitor used).
set -uo pipefail
# Run from the strix repo root (override with STRIX_REPO to point elsewhere).
cd "${STRIX_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

# Overridable so this runs on any checkout, not just the author's machine.
RUN="${RUN:-resume-handoff}"
TARGET="${TARGET:?set TARGET to a local repo/dir to scan (e.g. a checkout to review)}"
MODEL="${MODEL:-bedrock/us.anthropic.claude-sonnet-5}"
export STRIX_LLM="$MODEL"
export CLAUDE_CODE_USE_BEDROCK="${CLAUDE_CODE_USE_BEDROCK:-1}"
export AWS_PROFILE="${AWS_PROFILE:-claude-code}"

rm -rf "strix_runs/$RUN"

status() { python3 -c "import json;print(json.load(open('strix_runs/$RUN/run.json'))['status'])" 2>/dev/null || echo "no-runjson"; }
# grep -c prints "0" AND exits 1 on no-match; capturing then defaulting an
# empty result gives a single clean integer (the naive `grep -c || echo 0`
# emits two lines and breaks the integer test).
turns()  { local n; n=$(grep -c "next_step type=NextStep" "strix_runs/$RUN/strix.log" 2>/dev/null); echo "${n:-0}"; }
snap()   { test -f "strix_runs/$RUN/.state/agents.json" && echo yes || echo no; }

echo "=== ITER 1: fresh run, kill after >=6 agent turns (mimics STS-boundary TERM) ==="
uv run --with boto3 strix --run-name "$RUN" -t "$TARGET" -m standard -n \
  --instruction "Review the WebView native JS bridge (NativeIOSMessageHandler): origin/host validation, navigation policy, evaluateJavaScript construction, JWT handling. Report CWE + code_locations." \
  >/tmp/${RUN}_i1.log 2>&1 &
PID=$!
echo "iter1 pid=$PID"
killed=0
for i in $(seq 1 120); do   # up to 10 min
  kill -0 $PID 2>/dev/null || { echo "iter1 exited on its own at ~$((i*5))s (status=$(status))"; break; }
  t=$(turns); s=$(snap)
  if [ "$t" -ge 6 ] && [ "$s" = yes ]; then
    echo "iter1: $t turns + agents.json present at ~$((i*5))s — sending SIGTERM (simulated cred boundary)"
    kill -TERM $PID 2>/dev/null
    sleep 8; kill -KILL $PID 2>/dev/null
    killed=1
    break
  fi
  sleep 5
done

echo ""
echo "=== state after kill ==="
echo "  status:      $(status)"
echo "  turns:       $(turns)"
echo "  agents.json: $(snap)"
echo "  killed:      $killed"

if [ "$(snap)" != yes ]; then
  echo "ABORT: no agents.json snapshot — cannot resume (run never reached first agent turn)"; exit 3
fi
if [ "$(status)" = completed ]; then
  echo "NOTE: iter1 already completed before we could kill it — resume path not exercised, but flag+dir OK"; exit 0
fi

echo ""
echo "=== ITER 2: --resume the SAME run-name (mimics post-refresh continue) ==="
uv run --with boto3 strix --resume "$RUN" -n >/tmp/${RUN}_i2.log 2>&1 &
PID2=$!
echo "iter2 pid=$PID2"
for i in $(seq 1 180); do   # up to 15 min to complete
  kill -0 $PID2 2>/dev/null || { echo "iter2 exited at ~$((i*5))s"; break; }
  [ "$(status)" = completed ] && { echo "iter2 reached status=completed at ~$((i*5))s"; break; }
  sleep 5
done
kill -TERM $PID2 2>/dev/null; sleep 3; kill -KILL $PID2 2>/dev/null

echo ""
echo "=== FINAL VERDICT ==="
echo "  status:  $(status)"
echo "  turns:   $(turns)  (should exceed iter1's count if resume continued)"
python3 -c "import json;v=json.load(open('strix_runs/$RUN/vulnerabilities.json'));print('  findings:',len(v))" 2>/dev/null || echo "  findings: (none/no file)"
echo ""
echo "iter2 tail:"; tail -4 /tmp/${RUN}_i2.log
