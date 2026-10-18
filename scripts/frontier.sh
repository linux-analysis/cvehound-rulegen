#!/usr/bin/env bash
# The frontier baselines, one cell after another, in budget tiers: the frontier-* cells
# through the vendors' CLIs, the local anchor on the same panels, the agent runs, and
# the leakage probes. Every CLI cell is experiments/frontier.yaml with the model and the
# variant set on the command line; the anchor cells come from experiments/sample.yaml
# and experiments/pipeline.yaml (scripts/cells.sh).
#
#   scripts/frontier.sh smoke        # 2-CVE live smoke of each CLI adapter, then the reports
#   scripts/frontier.sh 1            # tier 1: astra/sol/fable/opus sampling + loop, probes, anchor panels
#   scripts/frontier.sh 2            # tier 2: luna/sonnet, effort ablations, new-rule cells, agent (Claude Code)
#   scripts/frontier.sh 3            # tier 3: self-critique controls, agent (codex)
#   scripts/frontier.sh anthropic    # every claude cell, generation only, in priority order
#   scripts/frontier.sh openai       # the same for codex
#   scripts/frontier.sh post         # the -full / -canon / report (and agent audit) of every run that lacks them
#   STEPS=gen|post|all               # which half of each cell to run (default all)
#   CONCURRENCY=6                    # requests in flight for the CLI cells (not part of the cell identity)
#   CHUNK=12                         # CVEs per scoring chunk; a loop round is a barrier per chunk, so
#                                    # bigger chunks keep more requests in flight (not identity; resume is per CVE)
#   ANCHOR=http://127.0.0.1:8080/v1  # the llama-server serving the GGUF anchor (scripts/serve.sh qwen3.8-27b-gguf)
#   JOBS=16 HEAVY=4                  # oracle sizing (default: from this host)
#   WAIT=1                           # wait for another rulegen job to finish instead of refusing
#
# Every cell: `rulegen run --resume` (generation with in-loop scoring), then the
# -full rescore (T4, T5 at suite parity, T6 + heads at the backports, cost), then
# the -canon sibling, then the per-run report with the $ table. Strictly sequential
# -- one oracle at a time -- and codex/claude cells alternate so one vendor's usage
# window recovers while the other's cell runs. A usage-limit reply pauses the
# adapter until the window resets; a wait past the cap aborts the cell, which
# `--resume` picks up on the next invocation.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/cells.sh
. scripts/cells.sh

TIER=${1:?tier: smoke | 1 | 2 | 3 | anthropic | openai | post}
STEPS=${STEPS:-all}
CONCURRENCY=${CONCURRENCY:-}
CHUNK=${CHUNK:-}
ANCHOR=${ANCHOR:-http://127.0.0.1:8080/v1}
default_sizing
LOGS=runs/logs
mkdir -p "$LOGS" reports
export CVEHOUND_CONTENT=none

wait_idle() { # one oracle at a time: wait for (or refuse) another rulegen job
    while pgrep -f 'rulegen (ru[n]|resco[r]e|agent-ru[n]) ' >/dev/null; do
        if [ "${WAIT:-0}" != 1 ]; then
            echo "another rulegen job is running; one oracle at a time (WAIT=1 to wait)" >&2
            exit 1
        fi
        sleep 60
    done
}

need() { # need <cli>...: refuse a tier whose vendor CLI is not installed
    local cli
    for cli in "$@"; do
        command -v "$cli" >/dev/null || { echo "tier $TIER needs the $cli CLI on PATH" >&2; exit 1; }
        "$cli" --version
    done
}

frontier_model() { # frontier_model <short name>: "<adapter> <model id>" for the schedule's names
    case $1 in
    fable|opus|sonnet) echo "claude-cli $1" ;;
    astra|sol|luna)    echo "codex-cli gpt-6-$1" ;;
    *) echo "unknown frontier model '$1'" >&2; return 1 ;;
    esac
}

post_cell() { # -full, -canon, report of a finished run
    local run=$1
    [ -f "runs/$run/samples.jsonl" ] || { echo "no run at runs/$run" >&2; return 0; }
    echo "=== post $run ($(ts))"
    wait_idle
    uv run rulegen rescore --run "runs/$run" --out "runs/$run-full" \
        "${SUITE_PARITY[@]}" --jobs 8 --heavy-slots 2 2>&1 | tee -a "$LOGS/$run-full.log"
    uv run rulegen rescore --run "runs/$run" --out "runs/$run-canon" --canonicalize canon --jobs 8 \
        2>&1 | tee -a "$LOGS/$run-canon.log"
    uv run rulegen report --run "runs/$run" --run "runs/$run-full" --run "runs/$run-canon" \
        --out "reports/$run" >> "$LOGS/$run-full.log" 2>&1
}

cell() { # cell <run id> <template> [--set ...]: generate + score (in-loop legs only), then the post half unless STEPS=gen
    local run=$1 template=$2 extra=("${@:3}")
    [ -n "$CONCURRENCY" ] && extra+=(--set "model.concurrency=$CONCURRENCY")
    [ -n "$CHUNK" ] && extra+=(--set "chunk_cves=$CHUNK")
    if [ "$STEPS" != post ]; then
        echo "=== $run ($(ts))"
        wait_idle
        # A failed cell (an aborted run: a logout, a limit past the cap, a run of
        # identical errors) is retried once after 10 minutes, then left for a later
        # `--resume`; the tier moves on either way.
        local try
        for try in 1 2; do
            if run_cell "$template" "$run" "${extra[@]}" 2>&1 | tee -a "$LOGS/$run.log"; then
                break
            fi
            echo "!!! $run failed (try $try, $(ts)); see $LOGS/$run.log"
            [ "$try" = 1 ] && sleep 600
        done
    fi
    [ "$STEPS" != gen ] && post_cell "$run"
    return 0
}

fcell() { # fcell <model> <variant>: one frontier cell, frontier-<model>-<variant>
    local short=$1 variant=$2 adapter model
    read -r adapter model < <(frontier_model "$short")
    local sets=(--set "model.adapter=$adapter" --set "model.model=$model")
    case $variant in
    s8)              sets+=(--set mode=sample --set sampling.n=8) ;;
    o4)              ;;
    c4)              sets+=(--set pipeline.feedback=critique) ;;
    o4-low|o4-xhigh) sets+=(--set "model.effort=${variant#o4-}" --set data.subset=data/panel-half.txt) ;;
    o4-nothink)      sets+=(--set model.thinking=false --set data.subset=data/panel-half.txt) ;;
    o4-new)          sets+=(--set data.split=newrule200 --set data.subset=data/panel-newrule.txt) ;;
    *) echo "unknown variant '$variant'" >&2; return 1 ;;
    esac
    cell "frontier-$short-$variant" frontier "${sets[@]}"
}

smoke_cli() { # smoke_cli <model>: 2 val CVEs x n=1 through the CLI; checks auth, JSON shape, tool-free replies
    local adapter model
    read -r adapter model < <(frontier_model "$1")
    cell "smoke-$1-cli" frontier --set "model.adapter=$adapter" --set "model.model=$model" \
        --set mode=sample --set sampling.n=1 --set data.split=val --set data.subset=null --set data.limit=2
}

anchor_cell() { # anchor_cell <run id> <template> [--set ...]: the GGUF anchor; skipped when its server is down
    if ! curl -sf -m 5 "${ANCHOR%/v1}/health" >/dev/null; then
        echo "no server at $ANCHOR; skipping $1" >&2
        return 0
    fi
    local sets
    local_model_sets qwen3.8-27b-gguf sets
    cell "$1" "$2" "${sets[@]}" --set "model.endpoint=$ANCHOR" --set model.concurrency=4 "${@:3}"
}

anchor_panels() { # the anchor on the frontier panel, sampled and in the loop, and on the new-rule panel
    anchor_cell sample-qwen3.8-27b-ph-panel sample --set sampling.n=8 --set oracle.run_selectivity=false \
        --set data.split=gold --set data.subset=data/panel-frontier.txt
    anchor_cell pipeline-qwen3.8-27b-ph-panel-oracle pipeline \
        --set data.split=gold --set data.subset=data/panel-frontier.txt
    [ "${1:-}" = new ] && anchor_cell pipeline-qwen3.8-27b-ph-newrule-oracle pipeline \
        --set data.split=newrule200 --set data.subset=data/panel-newrule.txt
    return 0
}

probe() { # membership probe of one model, 50 rules
    local adapter=$1 model=$2 out="runs/probe-$3"
    echo "=== probe $model ($(ts))"
    uv run rulegen probe --adapter "$adapter" --model "$model" --effort medium --sample 50 --seed 0 \
        --out "$out" 2>&1 | tee -a "$LOGS/probe-$3.log" || echo "!!! probe $model failed"
}

post_agent() { # -full, report, export and the suite audit of a finished agent run
    local run=$1
    [ -f "runs/$run/samples.jsonl" ] || { echo "no run at runs/$run" >&2; return 0; }
    echo "=== post $run ($(ts))"
    wait_idle
    uv run rulegen rescore --run "runs/$run" --out "runs/$run-full" \
        "${SUITE_PARITY[@]}" --jobs 8 --heavy-slots 2 2>&1 | tee -a "$LOGS/$run-full.log"
    uv run rulegen report --run "runs/$run" --run "runs/$run-full" --out "reports/$run" \
        >> "$LOGS/$run-full.log" 2>&1
    uv run rulegen export-rules --run "runs/$run" --column agent_rule_text --out "runs/$run/rules"
    AUDIT_HEADS="runs/$run/manifest.json" AUDIT_LOG="reports/audit-$run.log" \
        scripts/audit_rules.sh "runs/$run/rules" 8 || echo "audit of $run reported failures (see reports/audit-$run.log)"
}

agent() { # agent <cli> <model> <panel name> <id list>: one agent session per CVE
    local cli=$1 model=$2 name=$3 subset=$4 run="agent-$1-$3" agents=${CONCURRENCY:-2}
    [ "$agents" -gt 3 ] && agents=3  # each session runs the suite on the shared kernel clone
    if [ "$STEPS" != post ]; then
        echo "=== $run ($(ts))"
        wait_idle
        uv run rulegen agent-run --run-id "$run" --cli "$cli" --model "$model" --effort medium \
            --split "$( [ "$name" = new ] && echo newrule || echo gold )" --subset "$subset" \
            --agents "$agents" --max-wall-s 2700 --max-tool-calls 200 --jobs 4 --resume \
            2>&1 | tee -a "$LOGS/$run.log" || echo "!!! $run failed ($(ts)); resume later"
    fi
    [ "$STEPS" != gen ] && post_agent "$run"
    return 0
}

newrule_examples() { # the new-rule cells read data/examples/newrule200.parquet
    if [ ! -f data/examples/newrule200.parquet ] || [ data/examples/newrule200.parquet -ot data/cves.parquet ]; then
        echo "=== building data/examples/newrule200.parquet ($(ts))"
        wait_idle
        uv run rulegen build-dataset --split newrule --subset data/newrule200.txt --name newrule200 --jobs 8 \
            2>&1 | tee -a "$LOGS/build-newrule200.log"
    fi
}

preflight() {
    for f in data/panel-frontier.txt data/panel-half.txt data/panel-agent.txt data/panel-newrule.txt; do
        [ -f "$f" ] || { echo "missing $f (rulegen sample-panel; see README.md)" >&2; exit 1; }
    done
    wait_idle
}

preflight
case "$TIER" in
    smoke)
        need claude codex
        smoke_cli fable
        smoke_cli astra
        ;;
    1)
        need claude codex
        for m in fable astra opus sol; do fcell "$m" s8; done
        for m in fable astra opus sol; do fcell "$m" o4; done
        probe claude-cli fable fable; probe codex-cli gpt-6-astra astra
        probe claude-cli opus opus;   probe codex-cli gpt-6-sol sol
        anchor_panels
        ;;
    2)
        need claude codex
        newrule_examples
        for m in sonnet luna; do fcell "$m" s8; fcell "$m" o4; done
        probe claude-cli sonnet sonnet; probe codex-cli gpt-6-luna luna
        for e in low xhigh; do fcell fable "o4-$e"; fcell astra "o4-$e"; done
        fcell fable o4-nothink
        fcell fable o4-new
        fcell astra o4-new
        anchor_cell pipeline-qwen3.8-27b-ph-newrule-oracle pipeline \
            --set data.split=newrule200 --set data.subset=data/panel-newrule.txt
        agent claude fable new data/panel-newrule.txt
        agent claude fable gold data/panel-agent.txt
        ;;
    3)
        need claude codex
        fcell fable c4
        fcell astra c4
        agent codex gpt-6-astra new data/panel-newrule.txt
        agent codex gpt-6-astra gold data/panel-agent.txt
        ;;
    anthropic) # spend the Anthropic usage window: generation only, tier 1 first, then tiers 2 and 3
        # The flagship has its own cap on top of the plan's window, so the opus and
        # sonnet cells go first and the fable cells resume whenever that cap lifts.
        need claude
        STEPS=${STEPS:-gen}; [ "$STEPS" = all ] && STEPS=gen
        for m in opus sonnet fable; do fcell "$m" s8; fcell "$m" o4; done
        probe claude-cli opus opus; probe claude-cli sonnet sonnet
        newrule_examples
        for e in xhigh low; do fcell fable "o4-$e"; done
        fcell fable o4-nothink
        fcell fable o4-new
        probe claude-cli fable fable
        agent claude fable new data/panel-newrule.txt
        agent claude fable gold data/panel-agent.txt
        fcell fable c4
        ;;
    openai) # the same for the OpenAI usage window: every astra cell first, then sol and luna
        need codex
        STEPS=${STEPS:-gen}; [ "$STEPS" = all ] && STEPS=gen
        fcell astra s8; fcell astra o4
        for e in xhigh low; do fcell astra "o4-$e"; done
        newrule_examples
        fcell astra o4-new
        probe codex-cli gpt-6-astra astra
        fcell astra c4
        agent codex gpt-6-astra new data/panel-newrule.txt
        agent codex gpt-6-astra gold data/panel-agent.txt
        fcell sol s8; fcell sol o4
        fcell luna s8; fcell luna o4
        probe codex-cli gpt-6-sol sol; probe codex-cli gpt-6-luna luna
        ;;
    post) # the oracle-heavy half of every finished run that lacks it
        for d in runs/frontier-*; do
            [ -f "$d/samples.jsonl" ] || continue
            case "$d" in *-full|*-canon) continue ;; esac
            [ -f "$d-full/samples.parquet" ] && continue
            post_cell "$(basename "$d")"
        done
        for d in runs/agent-*; do
            [ -f "$d/samples.jsonl" ] || continue
            case "$d" in *-full|*-canon) continue ;; esac
            [ -f "$d-full/samples.parquet" ] && continue
            post_agent "$(basename "$d")"
        done
        anchor_panels new
        ;;
    *) echo "unknown tier $TIER" >&2; exit 1 ;;
esac

echo "=== combined panel report ($(ts))"
runs=()
for d in runs/frontier-*-s8 runs/frontier-*-o4 runs/sample-qwen3.8-27b-ph-panel runs/pipeline-qwen3.8-27b-ph-panel-oracle; do
    [ -f "$d/samples.jsonl" ] && runs+=(--run "$d")
done
[ ${#runs[@]} -gt 0 ] && uv run rulegen report "${runs[@]}" --out "reports/frontier-panel" \
    >> "$LOGS/frontier-report.log" 2>&1
echo "done tier $TIER ($(ts))"
