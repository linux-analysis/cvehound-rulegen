"""The run manifest: everything needed to reproduce a number from a run.

Written once at run start (so an interrupted run still says what it was) and
again at the end with totals.
"""

import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import time
from typing import Any

from rulegen import corpus, extract, promptbuild, sources, tiers
from rulegen.oracle import reward

SHA_CACHE = os.path.expanduser('~/.cache/rulegen/sha.jsonl')
_QUANT_RE = re.compile(r'(UD-)?(IQ\d_\w+|Q\d_[A-Z0-9_]+|Q\d_\d|F16|BF16|F32)', re.IGNORECASE)


def _run(cmd: list[str], cwd: str | None = None) -> str:
    try:
        return subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, check=True, timeout=60
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return ''


def git_state(repo_path: str) -> dict[str, Any]:
    sha = _run(['git', 'rev-parse', 'HEAD'], cwd=repo_path)
    dirty = bool(_run(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=repo_path))
    return {'path': os.path.abspath(repo_path), 'sha': sha, 'dirty': dirty}


def branch_heads(kernel: str, refs: tuple[str, ...] | list[str]) -> dict[str, str]:
    heads = {}
    for ref in refs:
        heads[ref] = _run(['git', 'rev-parse', '--verify', '-q', f'{ref}^{{commit}}'], cwd=kernel)
    return heads


def file_sha256(path: str, cache_path: str = SHA_CACHE) -> str:
    """sha256 of a (possibly huge) file, memoized on (path, size, mtime)."""
    st = os.stat(path)
    key = f'{os.path.abspath(path)}|{st.st_size}|{st.st_mtime_ns}'
    if os.path.exists(cache_path):
        with open(cache_path) as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get('key') == key:
                    return str(rec['sha256'])
    digest = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(8 << 20), b''):
            digest.update(chunk)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    # Append-only: two runs starting together must not drop each other's
    # entries, or the next run re-hashes a multi-GB weights file for nothing.
    with open(cache_path, 'a') as fh:
        fh.write(json.dumps({'key': key, 'sha256': digest.hexdigest()}) + '\n')
    return digest.hexdigest()


def _hf_precision(snapshot_dir: str) -> str | None:
    """The precision a HF checkpoint is stored at, from its config.json.

    A quantized release names its method (`fp8`); an unquantized one names its
    dtype, at the top level or inside `text_config` for a multimodal config.
    """
    path = os.path.join(snapshot_dir, 'config.json')
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        return None
    quant = cfg.get('quantization_config') or {}
    if quant.get('quant_method'):
        return str(quant['quant_method']).upper()
    for scope in (cfg, cfg.get('text_config') or {}):
        dtype = scope.get('torch_dtype') or scope.get('dtype')
        if dtype:
            return str(dtype).upper()
    return None


def quant_from_name(path: str | None) -> str | None:
    if not path:
        return None
    match = _QUANT_RE.search(os.path.basename(path))
    return match.group(0).upper() if match else None


def host_info() -> dict[str, Any]:
    gpu = _run(
        ['nvidia-smi', '--query-gpu=name,memory.total,driver_version', '--format=csv,noheader']
    )
    return {
        'hostname': socket.gethostname(),
        'cpu_count': os.cpu_count(),
        'gpu': gpu,
        'python': platform.python_version(),
        'platform': platform.platform(),
    }


def model_info(model_cfg: dict[str, Any], adapter_desc: dict[str, Any]) -> dict[str, Any]:
    info: dict[str, Any] = dict(model_cfg)
    info['adapter_describe'] = adapter_desc
    path = model_cfg.get('model_file')
    if path and os.path.isfile(path):
        info['file_sha256'] = file_sha256(path)
        info['file_size'] = os.path.getsize(path)
        info['quant'] = quant_from_name(path)
    elif path and os.path.isdir(path):
        # HF snapshot weights: the directory name *is* the revision, so it pins
        # the bytes as well as a digest would, and hashing tens of GB of shards
        # on every run start buys nothing. (file_sha256 would open the directory.)
        real = os.path.realpath(path)
        info['snapshot_dir'] = real
        info['revision'] = os.path.basename(real)
        info['quant'] = _hf_precision(real)
    return info


def data_info(data_dir: str, split: str) -> dict[str, Any]:
    info: dict[str, Any] = {'data_dir': os.path.abspath(data_dir)}
    parts = extract.MERGED_SPLITS.get(split, (split,))
    examples = [
        (
            f'examples_{part}' if len(parts) > 1 else 'examples',
            extract.examples_path(data_dir, part),
        )
        for part in parts
    ]
    for name, path in (
        ('cves', os.path.join(data_dir, corpus.CORPUS)),
        ('cvemeta', os.path.join(data_dir, sources.CVEMETA)),
        *examples,
        ('tiers', os.path.join(data_dir, tiers.TIERS)),
    ):
        if os.path.exists(path):
            info[f'{name}_sha256'] = file_sha256(path)
    return info


def spatch_info() -> dict[str, str]:
    """The spatch build the oracle runs: its path and --version banner (with the build id)."""
    try:
        from cvehound.util import find_spatch, spatch_identity

        path, _, banner = spatch_identity(find_spatch(None)).partition('\x00')
    except Exception:  # noqa: BLE001 — provenance must not fail a run
        return {}
    return {'path': path, 'banner': banner}


def package_version(name: str) -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version(name)
    except PackageNotFoundError:
        return ''


def cvehound_path(kernel: str) -> str:
    """The cvehound checkout holding this kernel clone (<cvehound>/tests/linux)."""
    # The kernel clone lives at <cvehound>/tests/linux by convention.
    guess = os.path.dirname(os.path.dirname(os.path.abspath(kernel)))
    return (
        guess
        if os.path.exists(os.path.join(guess, 'pyproject.toml'))
        else os.path.abspath('../cvehound')
    )


def build_manifest(
    cfg_dict: dict[str, Any],
    config_sha: str,
    oracle_cfg: Any,
    adapter_desc: dict[str, Any],
    data_dir: str,
    prompt_extra: dict[str, Any],
    cvehound_repo: str,
) -> dict[str, Any]:
    """The opening manifest of a run; `oracle_cfg` is the OracleConfig it scores with."""
    from cvehound.oracle.resultcache import HARNESS_EPOCH

    from rulegen.oracle import antigaming

    kernel = oracle_cfg.kernel
    return {
        'run_id': cfg_dict['run_id'],
        'created_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'config': cfg_dict,
        'config_sha': config_sha,
        'host': host_info(),
        'git': {
            'rulegen': git_state(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
            'cvehound': git_state(cvehound_repo),
        },
        'kernel': {
            'path': os.path.abspath(kernel),
            'heads': branch_heads(kernel, oracle_cfg.branches),
            'decoy_tag': antigaming.DECOY_TAG,
            'decoy_tag_sha': branch_heads(kernel, (antigaming.DECOY_TAG,))[antigaming.DECOY_TAG],
        },
        'oracle': {
            **reward.EPOCHS,
            'HARNESS_EPOCH': HARNESS_EPOCH,
            # Which legs defined acceptance: a run whose gate later gains a leg
            # (the initial-commit silence, say) must not read like an older one.
            'legs': list(reward.WEIGHTS),
            'core_legs': list(reward.CORE_LEGS),
            'spatch': spatch_info(),
            'work_root': oracle_cfg.work_root,
            'branches': list(oracle_cfg.branches),
        },
        'versions': {
            'PROMPTBUILD_VERSION': promptbuild.PROMPTBUILD_VERSION,
            'EXTRACTOR_VERSION': extract.EXTRACTOR_VERSION,
            'cvehound': package_version('cvehound'),
            'cvehound-rulegen': package_version('cvehound-rulegen'),
        },
        'prompt': prompt_extra,
        'model': model_info(cfg_dict['model'], adapter_desc),
        'data': data_info(data_dir, cfg_dict['data']['split']),
        'totals': {},
    }


def write_manifest(run_dir: str, manifest: dict[str, Any]) -> str:
    os.makedirs(run_dir, exist_ok=True)
    path = os.path.join(run_dir, 'manifest.json')
    tmp = f'{path}.{os.getpid()}'
    with open(tmp, 'w') as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True, default=str)
    os.replace(tmp, path)
    return path


def read_manifest(run_dir: str) -> dict[str, Any]:
    """The run's manifest, or {} when it was never written (an aborted run)."""
    path = os.path.join(run_dir, 'manifest.json')
    if not os.path.exists(path):
        return {}
    with open(path) as fh:
        return json.load(fh)
