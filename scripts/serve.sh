#!/usr/bin/env bash
# Serve one model from experiments/models.yaml over the OpenAI-compatible wire the
# runs speak: vLLM in a container for the HF checkpoints, llama-server for GGUF.
#
#   scripts/serve.sh qwen3.8-27b          # start (idempotent: a healthy one is reused)
#   scripts/serve.sh qwen3.8-27b --wait   # ... and block until /v1/models answers
#   scripts/serve.sh path qwen3.8-27b     # the weights in the HF cache (for model.model_file)
#   scripts/serve.sh stop                 # stop the container this script started
#   scripts/serve.sh status
#
# The registry decides the image, the port, the server flags, the weights (repo at a
# pinned revision) and -- the point of `--served-model-name` -- the wire id, which is
# exactly what the experiment configs name. Weights come from the Hugging Face cache
# ($HF_HOME, default ~/.cache/huggingface) and are never downloaded here:
#   hf download <repo> --revision <revision>
#
# SERVE_GPU picks the GPU (default 0). The memory slice taken on it is computed per
# model from the registry's `size_gb` and `kv_gb` rather than set as a fixed fraction,
# and the script refuses to start when the GPU has less free memory than that.
set -euo pipefail
cd "$(dirname "$0")/.."

CMD=${1:?usage: serve.sh <model-key|path <model-key>|stop|status> [--wait]}
shift || true
WAIT=0
for a in "$@"; do [ "$a" = --wait ] && WAIT=1; done

NAME=${SERVE_NAME:-rulegen-vllm}
GPU=${SERVE_GPU:-0}
HF_HOME_HOST=${HF_HOME:-$HOME/.cache/huggingface}

reg() {  # reg <python expression over m>: one value from the registry
    uv run --no-sync python -c "
import yaml
m = yaml.safe_load(open('experiments/models.yaml'))
print($1)"
}

weights() {  # weights <model-key>: the snapshot directory (or GGUF file) in the HF cache
    local key=$1 repo rev file
    read -r repo rev file < <(reg "' '.join([m['models']['$key']['repo'], m['models']['$key']['revision'], m['models']['$key'].get('file', '')])")
    local dir="$HF_HOME_HOST/hub/models--${repo//\//--}/snapshots/$rev"
    if [ -n "$file" ]; then echo "$dir/$file"; else echo "$dir"; fi
}

PORT=$(reg "m['vllm']['port']")
ENDPOINT=http://127.0.0.1:$PORT/v1

case "$CMD" in
status)
    docker ps --filter "name=^${NAME}$" --format '{{.Names}}  {{.Image}}  {{.Status}}' || true
    curl -s -m 5 "$ENDPOINT/models" | head -c 400; echo
    exit 0
    ;;
stop)
    docker rm -f "$NAME" >/dev/null 2>&1 && echo "stopped $NAME" || echo "no $NAME running"
    exit 0
    ;;
path)
    weights "${1:?usage: serve.sh path <model-key>}"
    exit 0
    ;;
esac

KEY=$CMD
WEIGHTS=$(weights "$KEY")
if [ ! -e "$WEIGHTS" ]; then
    echo "no weights at $WEIGHTS" >&2
    echo "  hf download $(reg "m['models']['$KEY']['repo']") --revision $(reg "m['models']['$KEY']['revision']")" >&2
    exit 1
fi
read -r engine served size_gb kv_gb < <(reg "' '.join(str(x) for x in (
    m['models']['$KEY'].get('engine', 'vllm'), m['models']['$KEY']['served_model_name'],
    m['models']['$KEY']['size_gb'], m['models']['$KEY'].get('kv_gb', m['vllm']['kv_gb'])))")

if [ "$engine" = llama.cpp ]; then
    flags=$(reg "m['llama_cpp']['server_flags']")
    port=$(reg "m['llama_cpp']['port']")
    echo "$KEY is a GGUF: serve it with llama.cpp's server, for example"
    echo "  llama-server -m $WEIGHTS --alias $served $flags --port $port"
    exit 2
fi

# Already serving what we want? Then this is a no-op and the sweep keeps going.
if curl -s -m 5 "$ENDPOINT/models" 2>/dev/null | grep -q "\"$served\""; then
    echo "$served already served at $ENDPOINT"
    exit 0
fi
docker rm -f "$NAME" >/dev/null 2>&1 || true

image=$(reg "m['vllm']['image']")
flags=$(reg "m['vllm']['server_flags'].strip()")
# --gpu-memory-utilization is a fraction of the card's TOTAL memory, claimed by
# vLLM for itself. Size the slice from the model: its weights plus overhead, plus
# a KV pool, as a fraction of the card.
read -r util want_mib < <(uv run --no-sync python -c "
total = $(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits -i "$GPU")
want = $size_gb * 1.12 + $kv_gb          # weights + activations, then the KV pool
print(f'{min(want * 1024 / total, 0.95):.3f} {int(want * 1024)}')")
free_mib=$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits -i "$GPU")
if [ "$want_mib" -gt "$free_mib" ]; then
    echo "gpu $GPU has ${free_mib} MiB free, $KEY wants ~${want_mib} MiB" >&2
    echo "  (lower kv_gb in experiments/models.yaml, or pick another GPU with SERVE_GPU)" >&2
    exit 1
fi

echo "== serving $KEY as '$served' on gpu $GPU, port $PORT"
echo "   slice: ~${want_mib} MiB of ${free_mib} MiB free (--gpu-memory-utilization $util)"
# --ipc=host: vLLM's workers need more than the default 64 MB /dev/shm.
# The HF cache is mounted read-only: a run must never mutate the weights it is
# measuring. The port is bound to loopback only.
docker run -d --name "$NAME" \
    --gpus "\"device=$GPU\"" \
    --ipc=host \
    -v "$HF_HOME_HOST:/hf:ro" \
    -e HF_HOME=/hf \
    -e HF_HUB_OFFLINE=1 \
    -e VLLM_LOGGING_LEVEL=WARNING \
    -p "127.0.0.1:$PORT:8000" \
    "$image" \
    "/hf${WEIGHTS#"$HF_HOME_HOST"}" \
    --served-model-name "$served" \
    --gpu-memory-utilization "$util" \
    $flags >/dev/null
echo "   container $NAME up; logs: docker logs -f $NAME"

if [ "$WAIT" = 1 ]; then
    printf '   waiting for %s' "$served"
    for _ in $(seq 1 180); do   # weights of this size take minutes to load
        if curl -s -m 5 "$ENDPOINT/models" 2>/dev/null | grep -q "\"$served\""; then
            echo " -- up"
            exit 0
        fi
        if ! docker ps --filter "name=^${NAME}$" --format '{{.Names}}' | grep -q .; then
            echo " -- container exited:"; docker logs --tail 40 "$NAME"; exit 1
        fi
        printf '.'; sleep 10
    done
    echo " -- timed out"; docker logs --tail 40 "$NAME"; exit 1
fi
