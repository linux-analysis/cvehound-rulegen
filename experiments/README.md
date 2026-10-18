# Experiment configs

One YAML file is one kind of experiment cell: `rulegen run --config experiments/<name>.yaml`
runs it as written, and `--set section.key=value` makes it any other cell of its kind. The
drivers in `scripts/` compose the published cells this way, from the model registry and the
schedules they carry, and name every run after what it varies. Unknown keys are errors.
Every run writes `runs/<run_id>/manifest.json` (the effective config and its sha, git SHAs
of rulegen and cvehound, package versions, kernel branch heads, the spatch build, oracle
epochs, the model's weights digest or revision), `samples.jsonl` (append-only, resumable
with `--resume`) and `samples.parquet`.

## Templates

| file | what it measures | the drivers vary |
| --- | --- | --- |
| `sample.yaml` | a local model sampled n=20 per CVE on the gold rules of one split | model, policy, split |
| `pipeline.yaml` | the validate-repair loop: b=8 chains, ≤3 rounds, oracle feedback or the self-critique control | model, policy, feedback, panel |
| `mechanical.yaml` | the mechanical baseline: no model, the floor every model row must clear | split |
| `frontier.yaml` | a frontier model through its vendor CLI in the loop, b=4, on the gold panel | model, effort, thinking, feedback, panel; or sampling n=8 |
| `teach.yaml` | expert iteration: the anchor's oracle loop at suite parity over unruled CVEs | the id list: a pool shard, or any batch of CVEs |
| `smoke.yaml` | an end-to-end smoke test of the harness with a scripted adapter and the real oracle | — |

`models.yaml` is the model registry: the local models by Hugging Face repo and revision,
with the wire id the cells send (`served_model_name`) and whether they have a thinking
switch (`thinking: false`: the cells turn it off), and the frontier models with dated list
prices for the $/rule tables.

## Cells

Run ids follow the template and what the cell varies; the drivers write them, and
`reports/<run_id>/` holds each cell's tables and manifest. `<model>` is the registry key
(`qwen3.8-27b`, `devstral-24b`, ...) for a local model and the short name of a frontier
model (`fable`, `astra`, ...); `<policy>` is `pb`, `pm` or `ph`.

| run id | cells | driver |
| --- | --- | --- |
| `sample-<model>-<policy>-<split>` | every local model x {P-B, P-M, P-H} x {train, val, test}; `-gold` merges the splits | `scripts/sweep.sh` |
| `mechanical-<split>` | the floor on each split; `mechanical-gold` merges them | `scripts/reference.sh` |
| `pipeline-<model>-<policy>-val-{oracle,critique}` | the loop against its self-critique control, on val, read against `sample-<model>-<policy>-val` | `scripts/repair_loop.sh` |
| `frontier-<model>-s8` | sampling n=8 on the gold panel | `scripts/frontier.sh` |
| `frontier-<model>-o4`, `-c4` | the loop (oracle feedback) and its self-critique control, b=4 | `scripts/frontier.sh` |
| `frontier-<model>-o4-low`, `-xhigh`, `-nothink` | effort and thinking ablations of the loop on the half panel | `scripts/frontier.sh` |
| `frontier-<model>-o4-new` | the loop on the new-rule panel: CVEs no published rule exists for | `scripts/frontier.sh` |
| `sample-qwen3.8-27b-ph-panel`, `pipeline-qwen3.8-27b-ph-{panel,newrule}-oracle` | the local anchor on the same panels, paired per CVE with the frontier cells | `scripts/frontier.sh` |
| `agent-<cli>-{gold,new}` | one agent session per CVE (`rulegen agent-run`) on the agent panel and the new-rule panel | `scripts/frontier.sh` |
| `teach-r<round>-<model>-<policy>-pool<shard>` | the teacher, one run per pool shard | `scripts/teach.sh` |
| `smoke`, `smoke-<model>`, `smoke-<model>-cli` | smoke tests: the scripted adapter, a served model (`sweep.sh smoke`), a vendor CLI (`frontier.sh smoke`) | |

Input policies (`prompt.policy`, rulegen/promptbuild.py): **P-B** the `-U3` diff; **P-C**
the `-W` (whole-function) diff; **P-M** P-C plus the commit message; **P-H** P-M plus
history: the files' earlier names, identifiers seen only in older versions of the code,
and in which release tags the fix's symbols exist.

Splits (`data.split`): `train` / `val` / `test` are the gold rules by fix date (< 2023,
2023, ≥ 2024), `gold` all three, `pool` the unruled CVEs before 2023, and `newrule200`
the examples built from a `newrule` id list (`rulegen build-dataset --split newrule
--subset data/newrule200.txt --name newrule200`). The panels (`data.subset`) are id lists
written by `rulegen sample-panel` and `rulegen sample-newrule`; see the README for the
exact commands.

## Schema

```yaml
run_id: sample-qwen3.8-27b-pm-val   # the drivers set it; default: <file stem>-<UTC timestamp>
mode: sample                         # sample | pipeline | mechanical
model:
  adapter: openai-compat             # openai-compat | mechanical | fake | claude-cli | codex-cli
  endpoint: http://127.0.0.1:8080/v1 # llama-server, vLLM or any OpenAI-compatible server
  model: qwen3.8-27b-bf16            # id sent on the wire (experiments/models.yaml: served_model_name)
  model_file: null                   # local weights: hashed (a file) or read for its revision (an HF snapshot)
  api_key_env: null                  # env var holding a bearer token; local servers need none
  thinking: false                    # null = server default; else chat_template_kwargs.enable_thinking
  extra_body: {}                     # passthrough request fields
  tokenizer_json: null               # exact token counter (its id enters the prompt hash)
  context_tokens: 16384              # the server's per-slot context; every request is checked against it
  concurrency: 4                     # requests in flight (<= the server's slots)
  timeout_s: 600
  max_retries: 3
  # claude-cli / codex-cli only (the vendors' CLIs, under the invoking user's login):
  effort: null                       # low | medium | high | xhigh | max (| ultra, codex); required
  cli_args: []                       # extra CLI flags; part of the cell identity
  config_dir: null                   # CLAUDE_CONFIG_DIR / CODEX_HOME for the child
  cli_bin: null                      # executable, when not `claude` / `codex` on PATH
  usage_wait_cap_s: 21600            # a usage-limit pause longer than this aborts (resume later)
prompt:
  policy: P-M                        # P-B P-C P-M P-H
  budget_tokens: 8192                # bounds the whole request, system turn included
  system_prompt: sys-v1              # key in rulegen/gen/prompts.py
  hide_cve_id: true
sampling:
  n: 20
  temperature: 0.7
  top_p: 0.95
  max_tokens: 2048
  seed: 0                            # request seed = seed*1000 + sample_index + 7*round
pipeline:                            # mode: pipeline only
  rounds: 3
  attempts: 8
  feedback: oracle                   # oracle | critique
  accept: valid                      # valid | strong: what ends a repair chain
data:
  split: val                         # train | val | test | gold | pool | <name of an examples parquet>
  subset: null                       # id-list file, "tiers:E", or a list of CVE ids
  limit: 0
oracle:
  jobs: 12                           # oracle worker processes
  work: runs/oracle                  # verdict store, blob store, AST cache, worktrees
  run_decoys: true
  run_selectivity: true              # T4 on every valid rule
  run_range: false                   # T5, only on valid rules
  run_tree: false                    # T6 at each backport, only on valid rules
  run_heads: false                   # informational scans at today's branch heads
  run_cost: false                    # one whole-tree scan per valid rule, for the cost tables
  tree_jobs: 1                       # spatch -j for whole-tree scans
  range_mode: tags                   # T5 enumeration: tags | commits (the suite's --between-mode)
  range_max_points: 16               # 0 = every distinct signature
  heavy_slots: 0                     # whole-tree scans at once across workers; 0 = unbounded
  address_space_limit: 8589934592    # RLIMIT_AS headroom per worker; 0 = off
  branches: null                     # default: the suite's branch list
  use_cache: true
  zygote: null                       # cvehound's spatch server mode; null = auto
  worktrees: null                    # default <work>/worktrees
transform: null                      # canon | patch-to-detect | polish: rewrite rules before scoring
chunk_cves: 8                        # CVEs generated per scoring batch
out: runs
notes: ''
```

`--set section.key=value` overrides any field (values parse as YAML). The cell identity
(`config_sha`, carried by every row) covers everything except labels and machine knobs:
`run_id`, `notes`, `out`, `chunk_cves`, `model.endpoint`, `model.model_file`,
`model.concurrency`, `model.timeout_s`, `model.max_retries`, `model.config_dir`,
`model.cli_bin`, `model.usage_wait_cap_s`, `oracle.work`, `oracle.jobs`,
`oracle.use_cache`, `oracle.zygote`, `oracle.worktrees` and `oracle.heavy_slots`. So the
same cell can run on another host, or resume with different sizing, and still merge.

Vendor-CLI cells: `context_tokens` defaults to 200000, sampling runs at the provider
default (rows carry `sampling_honored=false`, the manifest `sampling: provider-default`),
and every row records `request_id`, `tokens_cached`, `cost_usd`, `tool_calls` and
`tool_attempts_denied`. A reply after a tool call the CLI refused is kept (the attempt is
recorded on the row); a reply after a tool that actually ran is discarded and the request
re-sent (the manifest's `tool_retries` counts them). `rulegen report --prices
experiments/models.yaml` adds the $ table from the `frontier:` price map.

Rows in `samples.parquet` carry the Score flattened as `s_*` columns (`s_valid`,
`s_strong_valid`, `s_reward`, `s_fail_class`, `s_legs` as JSON, ...).
