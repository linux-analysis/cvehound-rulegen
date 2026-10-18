#!/usr/bin/env bash
# Oracle feedback against self-critique: the fixed validate-repair loop with oracle
# feedback, its self-critique control, and the single-shot sampling baseline both are
# compared against -- on the eligible val CVEs, P-H and P-M, one cell after another.
# The loop cells come from experiments/pipeline.yaml, the baselines from
# experiments/sample.yaml (scripts/cells.sh).
#
# Two models: the anchor (Qwen3.8-27B) and the agent-tuned base (Devstral-Small-2-24B).
# Six cells each -- four loop cells plus the two n=20 sampling baselines.
#
#   scripts/repair_loop.sh                  # both models, then the combined reports
#   scripts/repair_loop.sh qwen3.8-27b      # one model only
#   scripts/repair_loop.sh reports          # just rebuild the combined reports
#   JOBS=64 HEAVY=16 scripts/repair_loop.sh # oracle sizing (default: from this host)
#
# Strictly sequential: generate + in-loop scoring, then the -full rescore (T4, T5 at
# suite parity, T6 and head scans at the backports, the cost probe), then the per-run
# report, before the next cell touches the oracle. Every step resumes: `rulegen run
# --resume` skips attempts already in samples.jsonl, and a repeated rescore is served
# by the verdict store. The server comes from the registry (scripts/serve.sh).
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/cells.sh
. scripts/cells.sh

default_sizing
LOGS=runs/logs
mkdir -p "$LOGS"

MODELS=(qwen3.8-27b devstral-24b)
case ${1:-} in
reports) MODELS=() ;;
'')      ;;
*)       MODELS=("$@") ;;
esac

# The tiers the loop did not run (cells.sh).
RESCORE_FULL=("${SUITE_PARITY[@]}" --jobs "$JOBS" --heavy-slots "$HEAVY")

# The loop cells and the sampling baselines they are read against, in the order
# they are compared in: template, run id, policy, feedback (- for sampling).
cells_for() {
    local m=$1
    cat <<EOF
pipeline pipeline-$m-ph-val-oracle   ph oracle
pipeline pipeline-$m-ph-val-critique ph critique
pipeline pipeline-$m-pm-val-oracle   pm oracle
pipeline pipeline-$m-pm-val-critique pm critique
sample   sample-$m-ph-val            ph -
sample   sample-$m-pm-val            pm -
EOF
}

for model in ${MODELS[@]+"${MODELS[@]}"}; do
    scripts/serve.sh "$model" --wait
    sets=()
    local_model_sets "$model" sets
    while read -r template run policy feedback; do
        [ -n "${run:-}" ] || continue
        lock_run "$run" || { echo "another writer holds runs/.$run.lock; skipping $run" >&2; continue; }
        extra=(--set "prompt.policy=$(policy_name "$policy")" --set data.split=val)
        [ "$feedback" = - ] || extra+=(--set "pipeline.feedback=$feedback")
        echo "=== $run ($(ts))"
        run_cell "$template" "$run" "${sets[@]}" "${extra[@]}" 2>&1 | tee -a "$LOGS/$run.log"
        uv run rulegen rescore --run "runs/$run" --out "runs/$run-full" \
            "${RESCORE_FULL[@]}" 2>&1 | tee -a "$LOGS/$run-full.log"
        uv run rulegen report --run "runs/$run" --run "runs/$run-full" --out "reports/$run" \
            >>"$LOGS/$run-full.log" 2>&1
        copy_manifests "$run" "reports/$run"
    done <<<"$(cells_for "$model")"
done

echo "=== combined reports ($(ts))"
base=(); full=()
for model in qwen3.8-27b devstral-24b; do
    while read -r _template run _policy _feedback; do
        [ -n "${run:-}" ] || continue
        [ -d "runs/$run" ] || { echo "  skipping $run: not run yet"; continue; }
        base+=(--run "runs/$run")
        [ -d "runs/$run-full" ] && full+=(--run "runs/$run-full")
    done <<<"$(cells_for "$model")"
done
# Strict-contract reading: valid@b, valid@tokens, per class, funnel.
uv run rulegen report "${base[@]}" --out "reports/repair-loop" \
    >>"$LOGS/repair-loop-report.log" 2>&1
# Strong reading over the -full runs: T4/T5/T6 survivors, head fires, cost vs gold.
uv run rulegen report "${full[@]}" --key s_strong_valid --out "reports/repair-loop-strong" \
    >>"$LOGS/repair-loop-report.log" 2>&1
echo "done: reports/repair-loop and reports/repair-loop-strong ($(ts))"
