#!/usr/bin/env bash
# What every later table is read against, before any GPU time: the full gold replay
# and the mechanical floor. Neither needs a model.
#
#   scripts/reference.sh               # the gold replay, then the mechanical floor
#   scripts/reference.sh replay        # only the replay
#   scripts/reference.sh mechanical    # only the floor
#   JOBS=64 HEAVY=16 scripts/reference.sh   # oracle sizing (default: from this host)
#
# 1. The gold replay with every tier on writes reports/gold-replay-full.json, the
#    default --gold-cost source of `rulegen report`: the cost-vs-gold table of every
#    report is read against it. CPU seconds depend on the host, so it is rebuilt on
#    the host the cells run on.
# 2. The mechanical floor, mechanical-{train,val,test} and their merged row: the
#    floor row of the same tables, and an end-to-end check of run -> rescore ->
#    report on this host.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/cells.sh
. scripts/cells.sh

default_sizing
LOGS=runs/logs
mkdir -p "$LOGS" reports

WHAT=${1:-all}

if [ "$WHAT" = all ] || [ "$WHAT" = replay ]; then
    echo "=== gold replay ($(ts))"
    uv run rulegen replay-gold --jobs "$JOBS" --heavy-slots "$HEAVY" \
        --selectivity --range --tree --cost --tree-jobs 2 \
        --report reports/gold-replay-full.json 2>&1 | tee "$LOGS/gold-replay.log"
    echo "=== replay done ($(ts))"
fi

if [ "$WHAT" = all ] || [ "$WHAT" = mechanical ]; then
    base=()
    for split in train val test; do
        run="mechanical-$split"
        echo "=== $run ($(ts))"
        run_cell mechanical "$run" --set "data.split=$split" 2>&1 | tee -a "$LOGS/$run.log"
        uv run rulegen rescore --run "runs/$run" --out "runs/$run-full" \
            --canonicalize auto --selectivity --range --tree --cost --tree-jobs 2 \
            --jobs "$JOBS" --heavy-slots "$HEAVY" 2>&1 | tee -a "$LOGS/$run-full.log"
        uv run rulegen report --run "runs/$run" --run "runs/$run-full" --out "reports/$run" \
            >>"$LOGS/$run.log" 2>&1
        copy_manifests "$run" "reports/$run"
        base+=(--run "runs/$run")
    done
    # The floor as one row over every gold rule, the way the model rows are merged.
    uv run rulegen report "${base[@]}" --merge "mechanical-gold" \
        --out "reports/mechanical-gold" >>"$LOGS/mechanical-gold.log" 2>&1
    echo "=== mechanical floor done ($(ts))"
fi
