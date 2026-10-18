#!/usr/bin/env bash
# Bring a fresh host to the point where the experiment drivers can run.
#
#   scripts/bootstrap.sh check    # report every prerequisite; change nothing (default)
#   scripts/bootstrap.sh setup    # do the idempotent steps that are missing
#   scripts/bootstrap.sh verify   # the sanity runs: unit tests, a short gold replay, smoke runs
#
# Layout, side by side (override with CVEHOUND_REPO, CVEHOUND_KERNEL, CVEHOUND_CACHE):
#   <parent>/cvehound               the cvehound checkout (its test suite audits rules)
#   <parent>/cvehound/tests/linux   the kernel clone, remotes origin / next / stable
#   <parent>/cvehound-rulegen       this repository
# MODEL names the registry entry the model-server step checks (default qwen3.8-27b).
#
# Nothing here is destructive, and every setup step is skipped when its output
# already exists.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)

MODE=${1:-check}
CVEHOUND=$(cd "${CVEHOUND_REPO:-../cvehound}" 2>/dev/null && pwd || echo "${CVEHOUND_REPO:-../cvehound}")
KERNEL=${CVEHOUND_KERNEL:-$CVEHOUND/tests/linux}
CACHE=${CVEHOUND_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/cvehound}
MODEL=${MODEL:-qwen3.8-27b}
JOBS=${JOBS:-$(nproc)}
export CVEHOUND_CONTENT=none

TORVALDS=https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
NEXT=https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git
STABLE=https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
# The refs the oracle asks for (rulegen.schema.DEFAULT_BRANCHES + the decoy/cost tag).
REFS=(origin/master next/master stable/linux-6.18.y stable/linux-6.12.y stable/linux-6.6.y
      stable/linux-6.1.y stable/linux-5.15.y stable/linux-5.10.y v6.6)

missing=0
ok()   { printf '  ok    %s\n' "$*"; }
miss() { printf '  MISS  %s\n' "$*"; missing=$((missing + 1)); }
warn() { printf '  warn  %s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
run()  { printf '  >> %s\n' "$*"; "$@"; }
setup() { [ "$MODE" = setup ]; }

# ---------------------------------------------------------------- 1. host
# The oracle is CPU-bound spatch + git grep, each whole-tree scan runs under an
# 8 GiB RLIMIT_AS, and a generation server needs a GPU big enough for its weights.
step "host"
threads=$(nproc)
mem_gb=$(awk '/MemTotal/ {printf "%d", $2 / 1024 / 1024}' /proc/meminfo)
# Suggested sizing, the two knobs every driver script passes on:
#   oracle.jobs   ~ cores, a few left for the server and for git
#   heavy_slots   ~ min(cores / 4, (RAM_GB - 16) / 10)   (8 GiB per scan, headroom)
jobs_hint=$((threads > 12 ? threads - 12 : 1))
heavy_hint=$((threads / 4))
mem_slots=$(((mem_gb - 16) / 10))
[ "$mem_slots" -lt "$heavy_hint" ] && heavy_hint=$mem_slots
[ "$heavy_hint" -lt 1 ] && heavy_hint=1
[ "$threads" -ge 8 ] && ok "$threads cores" \
    || warn "$threads cores; the oracle is CPU-bound and a sweep at this width will be the wall clock"
[ "$mem_gb" -ge 32 ] && ok "${mem_gb} GB RAM" \
    || warn "${mem_gb} GB RAM; a whole-tree scan may claim 8 GiB, so heavy_slots must stay very low here"
echo "  hint  oracle.jobs $jobs_hint, heavy_slots $heavy_hint (raise heavy_slots only after watching RSS through a real cell)"
if command -v nvidia-smi >/dev/null; then
    while IFS=, read -r idx free; do
        printf '  ok    gpu %s: %s MiB free\n' "${idx// /}" "${free// /}"
    done < <(nvidia-smi --query-gpu=index,memory.free --format=csv,noheader,nounits)
else
    warn "nvidia-smi not found: no GPU visible (the oracle side still works)"
fi
for tool in git uv curl; do
    command -v "$tool" >/dev/null && ok "$tool" || miss "$tool is not installed"
done
free_gb=$(df -BG --output=avail "$ROOT" | tail -1 | tr -dc '0-9')
[ "${free_gb:-0}" -ge 60 ] && ok "${free_gb} GB free under $ROOT" || warn "${free_gb} GB free; clone + blob store + AST cache + weights need ~60 GB"

# ---------------------------------------------------------------- 2. code
step "code"
if [ -f "$CVEHOUND/pyproject.toml" ]; then
    ok "cvehound checkout at $CVEHOUND ($(git -C "$CVEHOUND" describe --tags --always 2>/dev/null))"
else
    miss "no cvehound checkout at $CVEHOUND (clone https://github.com/linux-analysis/cvehound beside this repo, or set CVEHOUND_REPO)"
fi
if [ -x .venv/bin/python ] && uv run --no-sync python -c 'import cvehound, rulegen' 2>/dev/null; then
    ok "uv environment"
elif setup; then
    run uv sync --extra gen && ok "uv sync"
else
    miss "uv environment not built: uv sync --extra gen"
fi
if spatch=$(uv run --no-sync python -c 'from cvehound.util import find_spatch; print(find_spatch(None))' 2>/dev/null) && [ -x "$spatch" ]; then
    ok "spatch $spatch ($("$spatch" --version 2>/dev/null | head -1))"
else
    miss "no spatch: the cvehound-spatch wheel comes with uv sync (cvehound's 'spatch' extra)"
fi

# ---------------------------------------------------------------- 3. kernel clone
step "kernel clone at $KERNEL"
if [ ! -d "$KERNEL/.git" ]; then
    if setup; then
        run git clone --origin origin "$TORVALDS" "$KERNEL" || miss "git clone failed"
    else
        miss "no clone (setup clones torvalds/linux.git; copying an existing clone is faster: ~4.5 GB packed)"
    fi
fi
if [ -d "$KERNEL/.git" ]; then
    for remote in "next=$NEXT" "stable=$STABLE"; do
        name=${remote%%=*}; url=${remote#*=}
        if git -C "$KERNEL" remote get-url "$name" >/dev/null 2>&1; then
            ok "remote $name"
        elif setup; then
            run git -C "$KERNEL" remote add "$name" "$url" && ok "remote $name added"
        else
            miss "remote $name missing ($url)"
        fi
    done
    unresolved=()
    for ref in "${REFS[@]}"; do
        git -C "$KERNEL" rev-parse --verify -q "$ref^{commit}" >/dev/null || unresolved+=("$ref")
    done
    if [ ${#unresolved[@]} -gt 0 ] && setup; then
        run git -C "$KERNEL" fetch --all --tags --prune
        unresolved=()
        for ref in "${REFS[@]}"; do
            git -C "$KERNEL" rev-parse --verify -q "$ref^{commit}" >/dev/null || unresolved+=("$ref")
        done
    fi
    if [ ${#unresolved[@]} -eq 0 ]; then
        ok "all ${#REFS[@]} refs resolve (${REFS[*]})"
    else
        miss "refs missing: ${unresolved[*]} (git -C $KERNEL fetch --all --tags)"
    fi
    if [ "$(git -C "$KERNEL" rev-parse --is-shallow-repository)" = true ]; then
        miss "the clone is shallow; the oracle walks fixes..fix~ and every backport's parent (git fetch --unshallow)"
    fi
    # Not an optimisation -- a prerequisite. Ancestry is how the metadata
    # agreement rule decides eligibility (one mainline fix, one introducing
    # commit that is an ancestor of it), and `merge-base --is-ancestor` over
    # 1.5M commits takes seconds without a commit-graph and milliseconds with
    # one: build-cvemeta takes hours instead of minutes on a clone without it.
    if [ -e "$KERNEL/.git/objects/info/commit-graph" ] \
        || [ -d "$KERNEL/.git/objects/info/commit-graphs" ]; then
        ok "commit-graph present (ancestry queries are cheap)"
    elif setup; then
        # Minutes, multi-threaded, and purely additive: it writes a cache file
        # and touches no object or ref.
        run git -C "$KERNEL" commit-graph write --reachable \
            && ok "commit-graph written"
    else
        miss "no commit-graph: build-cvemeta will take hours instead of minutes (git -C $KERNEL commit-graph write --reachable)"
    fi
fi

# ---------------------------------------------------------------- 4. metadata sources
step "metadata sources in $CACHE"
if [ -d "$CACHE/kernel-vulns/cve/published" ] && [ -d "$CACHE/cip-kernel-sec/issues" ]; then
    ok "vulns.git and CIP kernel-sec clones ($(ls "$CACHE/cip-kernel-sec/issues" | wc -l) CIP issues)"
elif setup && [ -d "$KERNEL/.git" ]; then
    # Clones both sources into $CACHE and writes a fresh archive there (minutes:
    # it resolves every commit of every record against the clone).
    mkdir -p "$CACHE"
    run uv run --no-sync cvehound_update_metadata "$KERNEL" "$CACHE/kernel_cves.json.gz" \
        && ok "sources cloned, archive at $CACHE/kernel_cves.json.gz" \
        || miss "cvehound_update_metadata failed"
else
    miss "run: uv run cvehound_update_metadata $KERNEL $CACHE/kernel_cves.json.gz (clones both sources)"
fi

# ---------------------------------------------------------------- 5. data
step "data (git-ignored; built in this order)"
build() {  # build <output> <cost note> <command...>
    local out=$1 note=$2; shift 2
    if [ -e "$out" ]; then
        ok "$out"
    elif setup; then
        printf '  building %s (%s)\n' "$out" "$note"
        run "$@" && ok "$out" || miss "$out failed"
    else
        miss "$out ($note): $*"
    fi
}
build data/cvemeta.parquet   "minutes"  uv run --no-sync rulegen build-cvemeta
build data/cves.parquet      "seconds"  uv run --no-sync rulegen build-corpus
build data/shapes.parquet    "git-bound, tens of minutes" uv run --no-sync rulegen shape-corpus --split pool --split train --split val --split test --split newrule --jobs "$JOBS"
build data/tiers.parquet     "minutes"  uv run --no-sync rulegen tier-corpus --jobs "$JOBS"
for split in train val test; do
    build "data/examples/$split.parquet" "minutes" uv run --no-sync rulegen build-dataset --split "$split" --jobs "$JOBS"
done
if [ -e data/cves.parquet ]; then
    rp=$(uv run --no-sync python -c "
from rulegen import corpus
print(next((r.rule_path for r in corpus.load_corpus('data/cves.parquet') if r.rule_path), ''))" 2>/dev/null)
    if [ -n "$rp" ] && [ ! -e "$rp" ]; then
        miss "data/cves.parquet points at $rp, which does not exist here; rebuild (rm data/cvemeta.parquet data/cves.parquet, then setup)"
    fi
fi

# ---------------------------------------------------------------- 6. oracle work root
step "oracle work root runs/oracle (nothing required; warm caches are optional)"
if [ -e runs/oracle/oracle_cache/verdicts.sqlite ]; then
    ok "verdict store present ($(du -sh runs/oracle/oracle_cache | cut -f1); hits only under the same spatch build)"
else
    warn "no verdict store yet: cold start"
fi
[ -d runs/oracle/astcache ] && ok "AST cache present" || warn "no AST cache yet (built as rules are scored)"

# ---------------------------------------------------------------- 7. model server
step "model server ($MODEL)"
read -r served engine image port < <(uv run --no-sync python -c "
import yaml; m = yaml.safe_load(open('experiments/models.yaml'))
a = m['models']['$MODEL']
engine = a.get('engine', 'vllm')
print(a['served_model_name'], engine, m['vllm']['image'], (m['llama_cpp'] if engine == 'llama.cpp' else m['vllm'])['port'])" 2>/dev/null)
weights=$(scripts/serve.sh path "$MODEL" 2>/dev/null)
if [ -e "${weights:-}" ]; then
    ok "weights $weights"
else
    miss "no weights for $MODEL at ${weights:-?} (hf download, see scripts/serve.sh)"
fi
if [ "$engine" = vllm ]; then
    if command -v docker >/dev/null && docker image inspect "$image" >/dev/null 2>&1; then
        ok "serving image $image"
    elif command -v docker >/dev/null; then
        warn "serving image $image not pulled yet (docker pull $image)"
    else
        warn "no docker: serve the weights some other way on 127.0.0.1:$port"
    fi
fi
# An open port is not a model server: ask the wire protocol the run will speak, and
# require the config's id in the list.
models_json=$(curl -s -m 5 "http://127.0.0.1:$port/v1/models" 2>/dev/null || true)
if printf '%s' "$models_json" | grep -q '"'"$served"'"'; then
    ok "$served served at 127.0.0.1:$port"
elif printf '%s' "$models_json" | grep -q '"object"'; then
    warn "127.0.0.1:$port answers /v1/models but does not serve '$served' (the served name must match the config)"
else
    warn "no OpenAI-compatible server at 127.0.0.1:$port yet (scripts/serve.sh $MODEL)"
fi

# ---------------------------------------------------------------- 8. verify
if [ "$MODE" = verify ]; then
    step "verify (each step must pass before a sweep)"
    run uv run --no-sync pytest -q || miss "unit tests"
    run uv run --no-sync rulegen replay-gold --jobs 8 --limit 20 --selectivity --range --range-mode commits \
        --range-max-points 0 --tree --heads --heavy-slots 2 || miss "gold replay (20 rules): spatch, clone or metadata disagree with the oracle's expectations"
    run uv run --no-sync rulegen run --config experiments/smoke.yaml || miss "fake-adapter smoke"
    cve=$(uv run --no-sync python -c "
from rulegen import extract
print(extract.load_examples('data/examples/val.parquet')[0].cve)" 2>/dev/null)
    run uv run --no-sync rulegen show-prompt --cve "$cve" --policy P-H >/dev/null || miss "show-prompt on $cve"
fi

step "summary"
if [ "$missing" -eq 0 ]; then
    echo "  everything needed is in place; next: $0 verify"
else
    echo "  $missing item(s) missing (see MISS above); '$0 setup' does the idempotent ones"
    exit 1
fi
