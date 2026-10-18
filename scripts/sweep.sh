#!/usr/bin/env bash
# The cross-model sampling sweep over the gold rules: every sample-* cell, then the
# merged rows and the cross-model reports. Each cell is experiments/sample.yaml with
# the model, the policy and the split set on the command line (scripts/cells.sh).
#
#   scripts/sweep.sh cells                 # the 46 generation cells, in schedule order
#   scripts/sweep.sh cells 1               # phase 1 only (every val+test cell)
#   scripts/sweep.sh cells 1 qwen2.5-coder-7b     # one model inside a phase
#   scripts/sweep.sh merge                 # the merged train+val+test rows + cross-model reports
#   scripts/sweep.sh schedule              # print the matrix and stop
#   scripts/sweep.sh smoke qwen2.5-coder-7b       # serve one model and sample 2 CVEs x n=1
#
#   JOBS=64 HEAVY=16 scripts/sweep.sh cells   # oracle sizing (default: from this host)
#
# Phase order puts a usable table first: every val+test cell -- that alone is the
# whole cross-model comparison -- then the five non-anchor P-M train cells, then
# the anchor's three train cells. Inside a phase the work is grouped by model, so
# the server is started once per model per phase (scripts/serve.sh).
#
# Strictly one cell at a time: generation runs on the GPU and the oracle (spatch +
# git grep, on CPU) is the wall clock, so two cells at once would only contend for
# the same cores -- and each oracle job may claim 8 GiB.
#
# Everything resumes: `rulegen run --resume` skips attempts already in
# samples.jsonl and a repeated rescore is served by the verdict store, so a killed
# sweep is restarted with the same command line.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/cells.sh
. scripts/cells.sh

# One sweep at a time: a second driver on the same cell would add a second
# generation pass to its samples.jsonl.
mkdir -p runs
exec 9>runs/.sweep.lock
if ! flock -n 9; then
    echo "another sweep.sh holds runs/.sweep.lock; refusing to run a second" >&2
    exit 1
fi

default_sizing
LOGS=runs/logs
TIMING=$LOGS/sample-timing.tsv
mkdir -p "$LOGS" reports
# Generation wall and oracle wall per cell, separately: the schedule the matrix
# is extrapolated from.
[ -s "$TIMING" ] || printf 'utc\trun\tgen_s\toracle_s\ttotal_s\n' >"$TIMING"

# T5 stays at the sweep's own setting (--range default: tags, 16 points), not the
# suite parity (--range-mode commits --range-max-points 0) that the repair-loop
# drivers use: the sweep yields thousands of valid rules and uncapped T5 would eat
# the whole CPU budget, so strong_valid here is a weaker gate than suite parity.
# --heads is skipped: informational only, one whole-tree scan per valid rule.
RESCORE_COMMON=(--selectivity --range --tree --cost --tree-jobs 2 --jobs "$JOBS" --heavy-slots "$HEAVY")

# phase model policy split -- 46 cells
SCHEDULE=$(cat <<'EOF'
1 qwen2.5-coder-7b       pm test
1 qwen2.5-coder-7b       pm val
1 qwen2.5-coder-7b       pb test
1 qwen2.5-coder-7b       pb val
1 qwen2.5-coder-7b       ph test
1 qwen2.5-coder-7b       ph val
1 qwen2.5-coder-14b      pm test
1 qwen2.5-coder-14b      pm val
1 qwen2.5-coder-14b      pb test
1 qwen2.5-coder-14b      pb val
1 qwen2.5-coder-14b      ph test
1 qwen2.5-coder-14b      ph val
1 qwen3.8-27b            pm test
1 qwen3.8-27b            pm val
1 qwen3.8-27b            pb test
1 qwen3.8-27b            pb val
1 qwen3.8-27b            ph test
1 qwen3.8-27b            ph val
1 devstral-24b           pm test
1 devstral-24b           pm val
1 devstral-24b           pb test
1 devstral-24b           pb val
1 devstral-24b           ph test
1 devstral-24b           ph val
1 qwen3-coder-30b-a3b    pm test
1 qwen3-coder-30b-a3b    pm val
1 qwen3-coder-30b-a3b    pb test
1 qwen3-coder-30b-a3b    pb val
1 qwen3-coder-30b-a3b    ph test
1 qwen3-coder-30b-a3b    ph val
1 qwen2.5-coder-32b      pm test
1 qwen2.5-coder-32b      pm val
1 qwen2.5-coder-32b      pb test
1 qwen2.5-coder-32b      pb val
1 qwen2.5-coder-32b      ph test
1 qwen2.5-coder-32b      ph val
1 qwen3-coder-next-80b   pm test
1 qwen3-coder-next-80b   pm val
2 qwen2.5-coder-7b       pm train
2 qwen2.5-coder-14b      pm train
2 devstral-24b           pm train
2 qwen3-coder-30b-a3b    pm train
2 qwen2.5-coder-32b      pm train
3 qwen3.8-27b            pm train
3 qwen3.8-27b            pb train
3 qwen3.8-27b            ph train
EOF
)

# Model x policy combinations that have all three splits, for the merged rows.
MERGES=$(cat <<'EOF'
qwen3.8-27b            pb
qwen3.8-27b            pm
qwen3.8-27b            ph
devstral-24b           pm
qwen2.5-coder-32b      pm
qwen2.5-coder-14b      pm
qwen2.5-coder-7b       pm
qwen3-coder-30b-a3b    pm
EOF
)

one_cell() {
    local model=$1 policy=$2 split=$3
    local run="sample-$model-$policy-$split" sets
    sets=()
    local_model_sets "$model" sets

    echo "=== $run ($(ts))"
    local t0 t1 t2
    t0=$(secs)
    run_cell sample "$run" "${sets[@]}" \
        --set "prompt.policy=$(policy_name "$policy")" --set "data.split=$split" \
        2>&1 | tee -a "$LOGS/$run.log"
    t1=$(secs)

    # The strict row is the run itself (transform: null); the canonicalized row is
    # the -canon sibling. -full adds the tiers the run did not, over what it scored.
    uv run rulegen rescore --run "runs/$run" --out "runs/$run-canon" \
        --canonicalize canon "${RESCORE_COMMON[@]}" 2>&1 | tee -a "$LOGS/$run-canon.log"
    uv run rulegen rescore --run "runs/$run" --out "runs/$run-full" \
        --canonicalize auto "${RESCORE_COMMON[@]}" 2>&1 | tee -a "$LOGS/$run-full.log"
    t2=$(secs)

    uv run rulegen report --run "runs/$run" --run "runs/$run-canon" --run "runs/$run-full" \
        --out "reports/$run" >>"$LOGS/$run.log" 2>&1
    copy_manifests "$run" "reports/$run"

    printf '%s\t%s\t%d\t%d\t%d\n' "$(ts)" "$run" "$((t1 - t0))" "$((t2 - t1))" \
        "$((t2 - t0))" >>"$TIMING"
    echo "--- $run: generation $((t1 - t0))s, oracle $((t2 - t1))s ($(ts))"
}

ACTION=${1:-cells}
shift || true
case $ACTION in
schedule)
    printf 'phase model policy split\n'; printf '%s\n' "$SCHEDULE"
    printf '\n%s cells\n' "$(printf '%s\n' "$SCHEDULE" | grep -c .)"
    exit 0
    ;;
smoke)
    model=${1:?usage: $0 smoke <model-key>}
    scripts/serve.sh "$model" --wait
    sets=()
    local_model_sets "$model" sets
    run_cell sample "smoke-$model" "${sets[@]}" --set data.limit=2 --set sampling.n=1
    exit 0
    ;;
merge)
    # One row over every gold rule per model x policy, strict and canonicalized.
    while read -r model policy; do
        [ -n "$model" ] || continue
        runs=(); canon=()
        for split in train val test; do
            runs+=(--run "runs/sample-$model-$policy-$split")
            canon+=(--run "runs/sample-$model-$policy-$split-canon")
        done
        echo "=== merge sample-$model-$policy-gold ($(ts))"
        uv run rulegen report "${runs[@]}" --merge "sample-$model-$policy-gold" \
            --out "reports/sample-$model-$policy-gold" >>"$LOGS/sample-merge.log" 2>&1
        uv run rulegen report "${canon[@]}" --merge "sample-$model-$policy-gold-canon" \
            --out "reports/sample-$model-$policy-gold-canon" >>"$LOGS/sample-merge.log" 2>&1
        for split in train val test; do
            copy_manifests "sample-$model-$policy-$split" "reports/sample-$model-$policy-gold"
        done
    done <<<"$MERGES"

    # One side-by-side cross-model table, and the same read canonicalized. Built
    # over val+test, which every model in the matrix has (the 80B has only those),
    # so the comparison spans all seven. The per-class policy table is part of
    # each report, so the cross-model report carries it too.
    echo "=== cross-model reports ($(ts))"
    cross=(); crossc=()
    while read -r model policy; do
        [ -n "$model" ] || continue
        for split in val test; do
            [ -d "runs/sample-$model-$policy-$split" ] \
                && cross+=(--run "runs/sample-$model-$policy-$split")
            [ -d "runs/sample-$model-$policy-$split-canon" ] \
                && crossc+=(--run "runs/sample-$model-$policy-$split-canon")
        done
    done <<<"$(printf '%s\n%s\n' "$MERGES" 'qwen3-coder-next-80b   pm')"
    uv run rulegen report "${cross[@]}" --out "reports/sample-cross-model" \
        >>"$LOGS/sample-merge.log" 2>&1
    uv run rulegen report "${crossc[@]}" --out "reports/sample-cross-model-canon" \
        >>"$LOGS/sample-merge.log" 2>&1
    echo "done: reports/sample-cross-model{,-canon} and the merged gold rows ($(ts))"
    exit 0
    ;;
cells) ;;
*) echo "usage: $0 {cells [phase [model...]]|merge|schedule|smoke <model-key>}" >&2; exit 2 ;;
esac

WANT_PHASE=${1:-}
shift || true
WANT_MODELS=("$@")

served=''
while read -r phase model policy split; do
    [ -n "${phase:-}" ] || continue
    [ -z "$WANT_PHASE" ] || [ "$phase" = "$WANT_PHASE" ] || continue
    if [ ${#WANT_MODELS[@]} -gt 0 ]; then
        printf '%s\n' "${WANT_MODELS[@]}" | grep -qx "$model" || continue
    fi
    if [ "$served" != "$model" ]; then
        scripts/serve.sh "$model" --wait
        served=$model
    fi
    one_cell "$model" "$policy" "$split"
done <<<"$SCHEDULE"

echo "=== cells done ($(ts)); timing in $TIMING"
