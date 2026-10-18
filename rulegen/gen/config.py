"""Run configuration: one YAML file is one experiment cell.

Every knob that changes what a run measures lives here and is hashed into
config_sha, which every sample row carries. Unknown keys are errors — a typo
must never silently turn into a default. `--set a.b=c` overrides are applied
to the raw mapping before validation, so they are hashed like the file.
"""

import copy
import dataclasses
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

import yaml

from rulegen import tables, tiers
from rulegen.oracle import reward
from rulegen.oracle.service import OracleConfig
from rulegen.promptbuild import POLICIES
from rulegen.schema import DEFAULT_BRANCHES

MODES = ('sample', 'pipeline', 'mechanical')
ADAPTERS = ('openai-compat', 'fake', 'mechanical', 'claude-cli', 'codex-cli')
# Vendor CLIs: no sampling knobs, an effort level instead of a thinking switch,
# and a context far beyond any prompt budget.
CLI_ADAPTERS = ('claude-cli', 'codex-cli')
EFFORTS = ('low', 'medium', 'high', 'xhigh', 'max', 'ultra')
CLI_CONTEXT_TOKENS = 200_000
FEEDBACK_KINDS = ('oracle', 'critique')
ACCEPT_KINDS = ('valid', 'strong')  # what ends a repair chain


@dataclass(frozen=True)
class ModelConfig:
    adapter: str = 'openai-compat'
    endpoint: str = 'http://127.0.0.1:8080/v1'
    model: str = ''  # id sent on the wire (llama-server ignores it; vLLM/OpenAI need it)
    model_file: str | None = None  # local weights, hashed into the manifest
    api_key_env: str | None = None  # name of the env var holding a bearer token
    thinking: bool | None = None  # None: server default; else chat_template_kwargs.enable_thinking
    extra_body: dict[str, Any] = field(default_factory=dict)  # passthrough request fields
    tokenizer_json: str | None = None  # exact counter; its id enters the prompt hash
    # The server's per-slot context (llama-server -c / -np). Every request is
    # checked against it before it is sent: prompt.budget_tokens x the counter's
    # safety factor + sampling.max_tokens must fit.
    context_tokens: int = 16384
    concurrency: int = 4  # <= llama-server --parallel
    timeout_s: float = 600.0
    max_retries: int = 3
    # Vendor-CLI adapters only (claude-cli / codex-cli).
    effort: str | None = None  # reasoning effort; every cell states it explicitly
    cli_args: tuple[str, ...] = ()  # extra CLI flags; part of the cell identity
    config_dir: str | None = None  # CLAUDE_CONFIG_DIR / CODEX_HOME for the child
    cli_bin: str | None = None  # the executable, when not on PATH under its own name
    usage_wait_cap_s: float = 21600.0  # a usage-limit pause longer than this aborts the run


@dataclass(frozen=True)
class PromptConfig:
    policy: str = 'P-M'
    budget_tokens: int = 8192
    system_prompt: str = 'sys-v1'  # key into gen.prompts.SYSTEM_PROMPTS
    hide_cve_id: bool = True  # showing the id is itself a leakage probe; hide by default


@dataclass(frozen=True)
class SamplingConfig:
    n: int = 20
    temperature: float = 0.7
    top_p: float = 0.95
    max_tokens: int = 2048
    seed: int = 0  # request seed = seed * 1000 + sample_index + 7 * round (log.attempt_seed)


@dataclass(frozen=True)
class PipelineConfig:
    rounds: int = 3  # repair rounds after round 0
    attempts: int = 8  # b: independent attempt chains per CVE
    feedback: str = 'oracle'  # oracle | critique (the self-critique control)
    # What counts as done: acceptance (T0-T3 + decoys) or strong acceptance
    # (also selective, fires across the range, silent on whole trees). Rules
    # meant for a training set want 'strong', so those failures are repaired
    # instead of merely recorded.
    accept: str = 'valid'


@dataclass(frozen=True)
class DataConfig:
    split: str = 'val'
    subset: str | list[str] | None = None  # id-list file, 'tiers:<cls>', or a list
    limit: int = 0


@dataclass(frozen=True, kw_only=True)
class OracleRunConfig(reward.OracleOptions):
    jobs: int = 12
    work: str = 'runs/oracle'
    run_selectivity: bool = True  # T4 on every VALID rule (degenerate% and strong_valid need it)
    branches: tuple[str, ...] | None = None
    use_cache: bool = True
    zygote: str | None = None
    worktrees: str | None = None  # default <work>/worktrees
    heavy_slots: int = 0  # concurrent whole-tree scans across workers; 0 = unbounded
    # RLIMIT_AS per oracle worker, inherited by every spatch it spawns; 0 = off.
    address_space_limit: int = reward.SPATCH_ADDRESS_SPACE_LIMIT


@dataclass(frozen=True)
class RunConfig:
    run_id: str
    mode: str = 'sample'
    model: ModelConfig = field(default_factory=ModelConfig)
    prompt: PromptConfig = field(default_factory=PromptConfig)
    sampling: SamplingConfig = field(default_factory=SamplingConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    data: DataConfig = field(default_factory=DataConfig)
    oracle: OracleRunConfig = field(default_factory=OracleRunConfig)
    # Mechanical rewriting applied to every parsed rule before it is scored
    # (canon.TRANSFORMS keys, e.g. 'canon'); None scores what the model wrote.
    transform: str | None = None
    out: str = 'runs'
    notes: str = ''
    chunk_cves: int = 8  # CVEs generated per scoring batch


# The byte-count estimator undercounts on trace-heavy text: on P-H prompts the
# server's count over the estimate is p95 1.45, max 1.97 (Qwen3.8 tokenizer).
# An exact tokenizer needs no margin.
APPROX_SAFETY = 1.5


def counter_safety(tokenizer_json: str | None) -> float:
    return 1.0 if tokenizer_json else APPROX_SAFETY


def context_error(estimate: int, safety: float, max_tokens: int, limit: int) -> str | None:
    """Why a request of `estimate` prompt tokens must not be sent, or None when it fits.

    The one formula every fit check uses: the harness before each request,
    the config at load time (with the budget as the estimate) and
    `show-prompt` when predicting a run.
    """
    need = int(estimate * safety) + max_tokens
    if need <= limit:
        return None
    return f'context: {need} tokens ({estimate} prompt x {safety} + {max_tokens} reply) > {limit}'


def context_needed(cfg: 'RunConfig') -> int:
    """Tokens a request may take at most: the budget under the safety factor plus the reply."""
    return int(cfg.prompt.budget_tokens * counter_safety(cfg.model.tokenizer_json)) + (
        cfg.sampling.max_tokens
    )


SECTIONS: dict[str, type] = {
    'model': ModelConfig,
    'prompt': PromptConfig,
    'sampling': SamplingConfig,
    'pipeline': PipelineConfig,
    'data': DataConfig,
    'oracle': OracleRunConfig,
}


def _build(cls: type, data: dict[str, Any], where: str) -> Any:
    names = {f.name for f in dataclasses.fields(cls)}
    unknown = sorted(set(data) - names)
    if unknown:
        raise ValueError(f'{where}: unknown keys {unknown}; known: {sorted(names)}')
    return cls(**data)


def from_dict(raw: dict[str, Any], source: str = 'config') -> RunConfig:
    raw = dict(raw)
    sections = {}
    for name, cls in SECTIONS.items():
        section = raw.pop(name, None) or {}
        if not isinstance(section, dict):
            raise ValueError(f'{source}: section {name!r} must be a mapping')
        if name == 'oracle' and isinstance(section.get('branches'), list):
            section = {**section, 'branches': tuple(section['branches'])}
        if name == 'model':
            if isinstance(section.get('cli_args'), list):
                section = {**section, 'cli_args': tuple(section['cli_args'])}
            if section.get('adapter') in CLI_ADAPTERS and 'context_tokens' not in section:
                section = {**section, 'context_tokens': CLI_CONTEXT_TOKENS}
        sections[name] = _build(cls, section, f'{source}.{name}')
    if 'run_id' not in raw:
        stem = os.path.splitext(os.path.basename(source))[0] or 'run'
        raw['run_id'] = f'{stem}-{time.strftime("%Y%m%dT%H%M%S", time.gmtime())}'
    cfg = _build(RunConfig, {**raw, **sections}, source)
    validate(cfg)
    return cfg


def validate(cfg: RunConfig) -> None:
    if cfg.mode not in MODES:
        raise ValueError(f'mode must be one of {MODES}, got {cfg.mode!r}')
    if cfg.model.adapter not in ADAPTERS:
        raise ValueError(f'model.adapter must be one of {ADAPTERS}, got {cfg.model.adapter!r}')
    if cfg.prompt.policy not in POLICIES:
        raise ValueError(f'prompt.policy must be one of {sorted(POLICIES)}')
    from rulegen.gen.prompts import SYSTEM_PROMPTS

    if cfg.prompt.system_prompt not in SYSTEM_PROMPTS:
        raise ValueError(f'prompt.system_prompt must be one of {sorted(SYSTEM_PROMPTS)}')
    why = context_error(
        cfg.prompt.budget_tokens,
        counter_safety(cfg.model.tokenizer_json),
        cfg.sampling.max_tokens,
        cfg.model.context_tokens,
    )
    if why:
        raise ValueError(f'prompt.budget_tokens exceeds model.context_tokens: {why}')
    if cfg.pipeline.feedback not in FEEDBACK_KINDS:
        raise ValueError(f'pipeline.feedback must be one of {FEEDBACK_KINDS}')
    if cfg.pipeline.accept not in ACCEPT_KINDS:
        raise ValueError(f'pipeline.accept must be one of {ACCEPT_KINDS}')
    if cfg.oracle.range_mode not in reward.RANGE_MODES:
        raise ValueError(f'oracle.range_mode must be one of {reward.RANGE_MODES}')
    from rulegen.gen.canon import transform_fn

    transform_fn(cfg.transform)  # raises on an unknown name
    if cfg.sampling.n < 1 or cfg.model.concurrency < 1 or cfg.chunk_cves < 1:
        raise ValueError('sampling.n, model.concurrency and chunk_cves must be >= 1')
    if cfg.model.adapter in CLI_ADAPTERS:
        m = cfg.model
        if not m.model:
            raise ValueError(f'{m.adapter} needs model.model (the vendor model id or alias)')
        if m.effort not in EFFORTS:
            raise ValueError(f'{m.adapter} needs model.effort in {EFFORTS}, got {m.effort!r}')
        if m.effort == 'ultra' and m.adapter != 'codex-cli':
            raise ValueError("effort 'ultra' exists only on codex-cli")
        if m.adapter == 'codex-cli' and m.thinking is not None:
            raise ValueError('codex-cli has no thinking switch; use model.effort')
        for key in ('extra_body', 'model_file', 'tokenizer_json', 'api_key_env'):
            if getattr(m, key):
                raise ValueError(f'model.{key} does not apply to {m.adapter}')
    elif cfg.model.effort is not None or cfg.model.cli_args:
        raise ValueError('model.effort and model.cli_args apply to claude-cli / codex-cli only')
    if cfg.mode == 'mechanical' and cfg.model.adapter != 'mechanical':
        raise ValueError("mode 'mechanical' requires model.adapter 'mechanical'")
    if cfg.model.adapter == 'mechanical' and cfg.mode != 'mechanical':
        raise ValueError("model.adapter 'mechanical' requires mode 'mechanical'")
    if cfg.mode == 'pipeline' and (cfg.pipeline.attempts < 1 or cfg.pipeline.rounds < 0):
        raise ValueError('pipeline.attempts >= 1 and pipeline.rounds >= 0 required')
    strong_tiers = cfg.oracle.run_selectivity or cfg.oracle.run_range or cfg.oracle.run_tree
    if cfg.mode == 'pipeline' and cfg.pipeline.accept == 'strong' and not strong_tiers:
        # Without a post-acceptance tier, strong_valid == valid and the setting
        # would silently promise a stricter gate than it delivers.
        raise ValueError(
            "pipeline.accept 'strong' needs at least one of "
            'oracle.run_selectivity / run_range / run_tree'
        )


def apply_overrides(raw: dict[str, Any], overrides: list[str] | tuple[str, ...]) -> dict[str, Any]:
    """`section.key=value` (value parsed as YAML, so 5 is an int and true a bool)."""
    out = json.loads(json.dumps(raw))  # deep copy of plain data
    for item in overrides:
        if '=' not in item:
            raise ValueError(f'override {item!r} is not key=value')
        dotted, _, value = item.partition('=')
        keys = dotted.split('.')
        node = out
        for key in keys[:-1]:
            node = node.setdefault(key, {})
            if not isinstance(node, dict):
                raise ValueError(f'override {item!r}: {key!r} is not a mapping')
        node[keys[-1]] = yaml.safe_load(value)
    return out


def load_config(path: str, overrides: list[str] | tuple[str, ...] = ()) -> RunConfig:
    with open(path) as fh:
        raw = yaml.safe_load(fh) or {}
    if not isinstance(raw, dict):
        raise ValueError(f'{path}: top level must be a mapping')
    return from_dict(apply_overrides(raw, overrides), source=path)


def to_dict(cfg: RunConfig) -> dict[str, Any]:
    return dataclasses.asdict(cfg)


# Config keys that label a run or tune the machine it ran on, not what it measured.
_NON_IDENTITY_KEYS: tuple[tuple[str, ...], ...] = (
    ('run_id',),
    ('notes',),
    ('out',),
    ('chunk_cves',),
    ('oracle', 'work'),
    ('oracle', 'jobs'),
    ('oracle', 'use_cache'),
    ('oracle', 'zygote'),
    ('oracle', 'worktrees'),
    ('oracle', 'heavy_slots'),
    ('model', 'endpoint'),
    ('model', 'model_file'),
    ('model', 'concurrency'),
    ('model', 'timeout_s'),
    ('model', 'max_retries'),
    ('model', 'config_dir'),
    ('model', 'cli_bin'),
    ('model', 'usage_wait_cap_s'),
)


def cell_identity(cfg_dict: dict[str, Any]) -> dict[str, Any]:
    """A config dict (RunConfig or a manifest's) reduced to what defines its experimental cell."""
    data = copy.deepcopy(cfg_dict)
    for *parents, key in _NON_IDENTITY_KEYS:
        node: Any = data
        for parent in parents:
            node = node.get(parent) if isinstance(node, dict) else None
        if isinstance(node, dict):
            node.pop(key, None)
    return data


def config_sha(cfg: RunConfig) -> str:
    """Identity of the experimental cell: everything except labels and paths."""
    data = cell_identity(to_dict(cfg))
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':'), default=list)
    return hashlib.sha256(canonical.encode()).hexdigest()


# Everything the run config and the oracle service call by the same name: a knob
# added to one dataclass reaches the other without editing this function.
_ORACLE_SHARED = tuple(
    f.name
    for f in dataclasses.fields(OracleConfig)
    if f.name not in ('kernel', 'work_root', 'branches')
)


def to_oracle_config(ocfg: OracleRunConfig, kernel: str) -> OracleConfig:
    shared = {name: getattr(ocfg, name) for name in _ORACLE_SHARED}
    return OracleConfig(
        kernel=os.path.abspath(kernel),
        work_root=os.path.abspath(ocfg.work),
        branches=tuple(ocfg.branches) if ocfg.branches else DEFAULT_BRANCHES,
        **shared,
    )


def resolve_subset(dcfg: DataConfig, data_dir: str) -> set[str] | None:
    """The CVE ids a run is restricted to, or None for the whole split."""
    subset = dcfg.subset
    if subset is None:
        return None
    if isinstance(subset, list):
        return set(subset)
    if subset.startswith('tiers:'):
        wanted = subset.partition(':')[2]
        classes = tiers.load_classes(data_dir, missing_ok=False)
        return {cve for cve, cls in classes.items() if cls == wanted}
    return tables.read_ids(subset)
