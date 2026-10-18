#!/usr/bin/env bash
# Expert iteration: the teacher over the clean pool, in resumable shards, then the
# selection of the rules the oracle accepted. Every shard is experiments/teach.yaml
# with the teacher model, the policy and the shard's id list set on the command line.
#
#   scripts/teach.sh [first_shard] [last_shard]
#   ROUND=1                                     the round: run ids teach-r<ROUND>-..., dataset round<ROUND>
#   MODEL=qwen3.8-27b-gguf                      the teacher (experiments/models.yaml key)
#   POLICY=ph                                   the input policy (pb pc pm ph)
#   CONFIG=experiments/teach.yaml               the teacher cell
#   PREFIX=teach-r$ROUND-$MODEL-$POLICY-pool    run id per shard: <PREFIX><i>
#   POOL=data/pool-clean                        shard id lists: <POOL>.<i>.txt
#   DATASET=data/synthetic/round$ROUND.parquet  where the accepted rules go
#   JOBS=16 HEAVY=4                             oracle sizing (default: from this host)
#
# A run id that already has runs/<id>/samples.jsonl is resumed, not restarted: to
# redo a round from scratch, give the shards a new PREFIX.
#
# Per shard: generate + score (GPU + the oracle workers), then the -full rescore for
# the cost probe at nice while the next shard generates, so at most two CPU-heavy
# jobs run at once. Every step resumes (`rulegen run --resume` skips attempts
# already in samples.jsonl, and the verdict store makes a repeated rescore cheap).
#
# Prerequisites: the data tables, <POOL>.<i>.txt (rulegen clean-pool) and
# data/examples/pool.parquet (rulegen build-dataset --split pool --subset
# data/pool-clean.txt), which scripts/bootstrap.sh setup builds in order, and the
# teacher's model served on the config's endpoint (scripts/serve.sh qwen3.8-27b-gguf
# prints the llama-server command).
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/cells.sh
. scripts/cells.sh

FIRST=${1:-0}
LAST=${2:-3}
ROUND=${ROUND:-1}
MODEL=${MODEL:-qwen3.8-27b-gguf}
POLICY=${POLICY:-ph}
CONFIG=${CONFIG:-experiments/teach.yaml}
PREFIX=${PREFIX:-teach-r$ROUND-$MODEL-$POLICY-pool}
POOL=${POOL:-data/pool-clean}
DATASET=${DATASET:-data/synthetic/round$ROUND.parquet}

# Every shard list up front, so a missing one stops the round before it starts.
for i in $(seq "$FIRST" "$LAST"); do
    [ -f "$POOL.$i.txt" ] || {
        echo "missing $POOL.$i.txt: rulegen clean-pool writes the shards, and" \
            "scripts/bootstrap.sh setup builds them with everything they need" >&2
        exit 1
    }
done

default_sizing
LOGS=runs/logs
mkdir -p "$LOGS"
sets=()
local_model_sets "$MODEL" sets

rescore_pid=

wait_for_rescore() {
    if [ -n "$rescore_pid" ]; then
        echo "waiting for the previous shard's rescore (pid $rescore_pid)"
        # A failed rescore costs one shard's cost probe, not the round: the
        # generation it followed is already logged and the step is resumable.
        wait "$rescore_pid" || echo "WARNING: that rescore failed; see $LOGS"
        rescore_pid=
    fi
}

for i in $(seq "$FIRST" "$LAST"); do
    run="$PREFIX$i"
    subset="$POOL.$i.txt"
    if ! lock_run "$run"; then
        echo "another writer holds runs/.$run.lock; refusing to run shard $i" >&2
        exit 1
    fi

    echo "=== shard $i: $(grep -vc '^#' "$subset") CVEs -> runs/$run"
    uv run rulegen run --config "$CONFIG" --resume --set "run_id=$run" "${sets[@]}" \
        --set "prompt.policy=$(policy_name "$POLICY")" --set "data.subset=$subset" \
        --set "oracle.jobs=$JOBS" --set "oracle.heavy_slots=$HEAVY" \
        2>&1 | tee -a "$LOGS/$run.log"

    # The cost probe is the only tier the loop did not run; add it (and the report)
    # in the background while the next shard occupies the GPU.
    wait_for_rescore
    (
        nice -n 10 uv run rulegen rescore --run "runs/$run" --out "runs/$run-full" \
            "${SUITE_PARITY[@]}" --jobs "$(((JOBS + 1) / 2))" --heavy-slots "$(((HEAVY + 1) / 2))"
        uv run rulegen report --run "runs/$run-full" --key s_strong_valid \
            --out "reports/$run"
    ) >> "$LOGS/$run-full.log" 2>&1 &
    rescore_pid=$!
    echo "shard $i scored; rescore running as pid $rescore_pid"
done

wait_for_rescore

echo "=== selecting the accepted rules"
runs=()
for i in $(seq "$FIRST" "$LAST"); do runs+=(--run "runs/$PREFIX$i-full"); done
uv run rulegen select-synthetic "${runs[@]}" --out "$DATASET" \
    2>&1 | tee -a "$LOGS/select-$(basename "$DATASET" .parquet).log"
echo "done: $DATASET + ${DATASET%.parquet}.md"
echo "audit: rulegen export-synthetic --dataset $DATASET --out <dir> && scripts/audit_rules.sh <dir>"
