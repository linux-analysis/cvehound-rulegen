# shellcheck shell=bash
# Shared by the driver scripts that run one experiment cell after another.
# Sourced, not executed.

ts() { date -u +%FT%TZ; }
secs() { date +%s; }

# Oracle sizing for this host, unless JOBS / HEAVY say otherwise. The oracle is
# CPU-bound (spatch + git), and every whole-tree scan runs under an 8 GiB
# address-space cap, so HEAVY (whole-tree scans at once) follows the memory:
#   JOBS  ~ cores, a few left for the server and for git
#   HEAVY ~ min(cores / 4, (RAM_GB - 16) / 10)
default_sizing() {
    local threads mem_gb heavy mem_slots
    threads=$(nproc)
    mem_gb=$(awk '/MemTotal/ {printf "%d", $2 / 1024 / 1024}' /proc/meminfo)
    heavy=$((threads / 4))
    mem_slots=$(((mem_gb - 16) / 10))
    [ "$mem_slots" -lt "$heavy" ] && heavy=$mem_slots
    [ "$heavy" -lt 1 ] && heavy=1
    JOBS=${JOBS:-$((threads > 12 ? threads - 12 : 1))}
    HEAVY=${HEAVY:-$heavy}
}

# The tiers a cell's own scoring leaves out, at suite parity: T5 over every
# distinct signature in commits mode, whole-tree scans at each backport, the
# informational head scans and the cost probe. Callers add --jobs/--heavy-slots.
# shellcheck disable=SC2034  # read by the drivers that source this file
SUITE_PARITY=(--selectivity --range --range-mode commits --range-max-points 0
              --tree --heads --cost --tree-jobs 2)

# policy_name <code>: the prompt policy a cell name abbreviates.
policy_name() {
    case $1 in
    pb) echo P-B ;;
    pc) echo P-C ;;
    pm) echo P-M ;;
    ph) echo P-H ;;
    *) echo "unknown policy code '$1' (pb pc pm ph)" >&2; return 1 ;;
    esac
}

# local_model_sets <registry key> <array name>: the --set pairs that put one local
# model into a cell -- its wire id and thinking switch from experiments/models.yaml,
# and its weights, whose revision the manifest records.
local_model_sets() {
    local key=$1 served thinking
    local -n sets_ref=$2
    read -r served thinking < <(uv run --no-sync python -c "
import yaml
m = yaml.safe_load(open('experiments/models.yaml'))['models'].get('$key')
if m:
    print(m['served_model_name'], 'false' if m.get('thinking') is False else 'null')" 2>/dev/null) || true
    [ -n "${served:-}" ] || { echo "no model '$key' in experiments/models.yaml" >&2; return 1; }
    # shellcheck disable=SC2034  # assigned through the nameref
    sets_ref=(--set "model.model=$served" --set "model.thinking=$thinking"
         --set "model.model_file=$(scripts/serve.sh path "$key")")
}

# run_cell <template> <run id> [--set key=value ...]: one cell composed from a
# template, resumable, with the oracle sized for this host. The run id names the
# cell; its manifest records the effective config and its sha.
run_cell() {
    local template=$1 run=$2
    shift 2
    uv run rulegen run --config "experiments/$template.yaml" --resume --set "run_id=$run" \
        --set "oracle.jobs=$JOBS" --set "oracle.heavy_slots=$HEAVY" "$@"
}

# One writer per run directory. samples.jsonl is append-only and `--resume`
# dedups on read, so a second driver on the same run would not corrupt a line --
# it would silently add a second generation pass. Holds the lock on fd 8 until
# the shell exits.
lock_run() {
    local run=$1
    mkdir -p runs
    exec 8>"runs/.$run.lock"
    flock -n 8
}

# runs/ is git-ignored: copy a cell's manifests next to its report so the
# tables stay attributable (config and its sha, git SHAs, kernel heads, spatch
# build, oracle epochs, weights revision). The rescore siblings carry their own
# oracle settings, so they travel too.
copy_manifests() {
    local run=$1 out=$2 suffix
    mkdir -p "$out"
    [ -f "runs/$run/manifest.json" ] && cp "runs/$run/manifest.json" "$out/manifest.json"
    for suffix in canon full; do
        [ -f "runs/$run-$suffix/manifest.json" ] \
            && cp "runs/$run-$suffix/manifest.json" "$out/manifest-$suffix.json"
    done
    return 0
}
