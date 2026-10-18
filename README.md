# cvehound-rulegen

Generate [CVEhound](https://github.com/linux-analysis/cvehound) detection rules for
Linux kernel CVEs with language models, and judge every candidate by running it
against the kernel's git history.

A CVEhound rule is a Coccinelle semantic patch that reports the vulnerable code of one
CVE. Given a kernel fix commit -- its diff, its message and the history around it -- a
model writes one `.cocci` rule that must match the code before the fix and not after.
This repository is the testbench and the pipeline around that task. It builds the CVE
corpus and the model inputs, runs generation through local or hosted models, and scores
every rule with an oracle. The accepted rules become new cvehound rules. Three ways to
generate are supported:

- sampling;
- a validate-repair loop driven by the oracle's feedback;
- an agent working in a cvehound checkout.

The oracle is built on `cvehound.oracle`, the mini-tree and verdict-cache machinery
CVEhound's own test suite runs on, so a verdict here cannot drift from what the suite
would say. The unmodified suite remains the final authority: every accepted rule is
audited with it (`scripts/audit_rules.sh`).

## How a rule is judged

The model writes only the `/// Files:` line and the pattern, in the cvehound rule format
(no `virtual` declaration, no `exists` in a rule header); the `Fix:`/`Fixes:` header
lines are inserted programmatically.

A rule is **valid** when it

- passes the structural checks the suite runs before spatch (T0) and parses (T1);
- fires at `Fix~` and is silent at `Fix`, fires at `Fixes` and is silent at `Fixes~`
  (T2, the suite's `test_03`/`test_04`), and is silent at the start of git history
  (`v2.6.12-rc2`) unless the bug dates from there (`test_02`);
- on every stable branch whose backport of the fix vulns.git or CIP names, fires just
  before that backport and is silent at it (T3);
- stays silent on decoys: unrelated kernel code served at the rule's own paths.

Valid rules are then checked for **strong validity**, which is what a rule must earn to
be kept: T4 prefilter selectivity (no unrelated `lib/` file survives spatch's grep
query), T5 the range sweep (the rule fires at every distinct state of its files in
`Fixes..Fix~`, the suite's `test_05` in either `--between-mode`), and T6 whole-tree
silence at each backport commit (the question of `test_06`, answered over a mini-tree
of the files spatch's own grep query selects). Today's branch heads are scanned too,
but only as information: a fire there is a regression or a missing backport to look at,
never a verdict.

Every score also carries a **reward**: graded partial credit for ranking and RL, in two
bands, so every invalid rule scores below 0.75 and every valid one at or above it. A
silence earns only next to the fire that gives it meaning, so a rule that matches
nothing scores below an over-broad one. Two text terms (a literal name somewhere in the
rule; no metavariable where a starred callee or the reporting anchor belongs) and T4-T6,
when they ran, shape the reward without changing `valid`. Timeouts, truncated scans and
spatch errors are their own verdicts and are never scored as silence.

The oracle judges only CVEs whose metadata sources agree. `rulegen build-cvemeta` reads
the raw vulns.git and CIP clones side by side and requires one mainline fix and one
introducing commit that is its ancestor; `rulegen audit-metadata` lists every
disagreement.

## Requirements

- Linux, Python 3.12, [uv](https://docs.astral.sh/uv/) and git; docker to serve the
  local models with vLLM.
- A cvehound checkout next to this repository, with a full kernel clone at
  `cvehound/tests/linux`: remotes `origin` (torvalds), `next` (linux-next) and
  `stable`, all tags, and a commit-graph. The checkout provides the test suite that
  audits rules and the `write-cve-rule` skill the agents use; the kernel clone answers
  every oracle check.
- The vulns.git and CIP kernel-sec clones under `~/.cache/cvehound`, which
  `cvehound_update_metadata` creates.
- The oracle is CPU-bound: a 32-thread, 96 GB workstation runs every experiment, and
  more cores shorten the sweeps. About 60 GB of disk.
- A GPU for the local models: 24 GB holds the GGUF anchor and the 7B; the larger
  BF16/FP8 models need larger GPUs (`experiments/models.yaml` lists their sizes).
- For the frontier models, the `claude` and `codex` CLIs, logged in.

## Setup

```bash
git clone https://github.com/linux-analysis/cvehound.git
git clone https://github.com/linux-analysis/cvehound-rulegen.git
cd cvehound-rulegen
uv sync --extra gen
export CVEHOUND_CONTENT=none   # score against the installed rule set, not a content overlay

scripts/bootstrap.sh check     # what is missing
scripts/bootstrap.sh setup     # kernel remotes, commit-graph, metadata clones, data tables
scripts/bootstrap.sh verify    # unit tests, a 20-rule gold replay, smoke runs
```

`CVEHOUND_REPO`, `CVEHOUND_KERNEL` and `CVEHOUND_CACHE` override the default layout.

## Data

```bash
uv run rulegen build-cvemeta      # vulns.git + CIP + gold rule headers -> data/cvemeta.parquet
uv run rulegen build-corpus       # every CVE with its split -> data/cves.parquet
uv run rulegen shape-corpus --split train --split val --split test --split pool \
    --split newrule --jobs 16     # fix shape, subsystem, touched functions -> data/shapes.parquet
uv run rulegen tier-corpus --jobs 16              # each gold rule's context class -> data/tiers.parquet
uv run rulegen build-dataset --split train --jobs 16   # and val, test -> data/examples/<split>.parquet
uv run rulegen audit-metadata     # every source disagreement -> reports/metadata-audit.md
```

| split | what | use |
| --- | --- | --- |
| `train` / `val` / `test` | gold rules by fix date: < 2023 / 2023 / >= 2024 | prompted baselines, merged as `gold` |
| `pool` | unruled CVEs fixed before 2023 | expert iteration, via `data/pool-clean.txt` |
| `reserve` | unruled CVEs fixed in 2023-2024 | held out |
| `newrule` | unruled CVEs fixed since 2025 | oracle-only evaluation and new rules |

The evaluation sets are written by seeded commands:

```bash
uv run rulegen sample-newrule --n 200 --out data/newrule200.txt
uv run rulegen build-dataset --split newrule --subset data/newrule200.txt --name newrule200
uv run rulegen sample-panel --exclude-doc-cited --out data/panel-frontier.txt    # gold, by context class and era
uv run rulegen sample-panel --from-panel data/panel-frontier.txt --half --out data/panel-half.txt
uv run rulegen sample-panel --from-panel data/panel-frontier.txt --n 25 --seed 1 --out data/panel-agent.txt
uv run rulegen sample-panel --by shape --candidates data/newrule200.txt --n 50 --out data/panel-newrule.txt
uv run rulegen clean-pool --split pool --shards 4        # -> data/pool-clean.txt and four shards
uv run rulegen build-dataset --split pool --subset data/pool-clean.txt --jobs 16
```

Everything under `data/` derives from the current state of vulns.git, CIP, the kernel
and cvehound's rule set, so lists built later differ from the ones the published
experiments used. To evaluate on a fixed set, pass its id list: `data.subset` in a
config, `--subset` on the command line.

## Scoring

```bash
uv run rulegen score --cve CVE-2024-26619 --rule candidate.cocci   # one candidate -> its Score as JSON
uv run rulegen replay-gold --jobs 12                                # every gold rule through the oracle
uv run rulegen replay-gold --jobs 12 --selectivity --range --tree --cost --tree-jobs 2 \
    --report reports/gold-replay-full.json                          # with T4-T6 and the rule cost
```

`replay-gold` exits non-zero when a gold rule fails a gating leg or is missing from the
installed rule set; fires on today's branch heads are reported, never failures. The
`--cost` replay is the reference the reports compare generated rules' cost against.

## Generating rules

```bash
scripts/serve.sh qwen3.8-27b --wait                                 # vLLM, weights pinned by revision
scripts/serve.sh qwen3.8-27b-gguf                                   # prints the llama-server command for the GGUF anchor
uv run rulegen run --config experiments/sample.yaml \
    --set run_id=sample-qwen3.8-27b-pm-val --set prompt.policy=P-M  # sample n=20 per CVE and score
uv run rulegen run --config experiments/pipeline.yaml               # the validate-repair loop
uv run rulegen run --config experiments/mechanical.yaml             # the mechanical baseline, no model
uv run rulegen run --config experiments/frontier.yaml               # a frontier model through its CLI
uv run rulegen agent-run --run-id agent-claude-new --cli claude --model fable \
    --split newrule --subset data/panel-newrule.txt                 # an agent, one session per CVE
uv run rulegen rescore --run runs/sample-qwen3.8-27b-pm-val --canonicalize canon   # patch-to-detect, offline
uv run rulegen report --run runs/sample-qwen3.8-27b-pm-val --out reports/sample-qwen3.8-27b-pm-val
uv run rulegen show-prompt --cve CVE-2024-26619 --policy P-H        # exactly what a model is sent
uv run rulegen probe --adapter codex-cli --model gpt-6-astra --sample 50 --out runs/probe-astra
```

`experiments/` holds one template per kind of cell -- `sample`, `pipeline`, `mechanical`,
`frontier`, `teach` and `smoke` -- and `--set section.key=value` turns a template into any
cell of its kind. The drivers in `scripts/` compose the published cells this way and name
every run after what it varies; `experiments/README.md` documents the templates, the run
ids and the schema. `experiments/models.yaml` pins every model: the local ones by Hugging
Face revision (the GGUF anchor also by sha256), and the frontier ones by the id the vendor
CLI resolves, with dated list prices for the cost tables. Every run writes a manifest with
the effective config, its identity hash, the git SHAs, package versions, kernel branch
heads, the spatch build and the oracle epochs, and every row carries its prompt hash.

## Reproducing the experiments

| experiments | driver | reports |
| --- | --- | --- |
| gold reference and the mechanical floor | `scripts/reference.sh` | `gold-replay-full.json`, `mechanical-*` |
| local models, sampled, every split and policy | `scripts/sweep.sh cells`, then `merge` | `sample-*`, `sample-cross-model{,-canon}` |
| per-context-class heatmaps of those cells | `scripts/class_heatmap.py --policy P-M` (or `--model ...`) | `--out` |
| oracle feedback against self-critique | `scripts/repair_loop.sh` | `repair-loop{,-strong}` |
| frontier models, agents, leakage probes | `scripts/frontier.sh 1`, `2`, `3`, then `post` | `frontier-*`, `agent-*`, `frontier-panel` |
| expert iteration, one round | `scripts/teach.sh 0 3` | `teach-r1-*`, `data/synthetic/round1.{parquet,md}` |

Every driver resumes where it stopped, sizes the oracle from the host (`JOBS` and
`HEAVY` override), and copies each run's manifest next to its report. The local models
are served with `scripts/serve.sh`; the frontier cells need the vendor CLIs. Absolute
CPU-second costs depend on the host, so the cost tables compare against a gold replay
made on the same host.

## Generating new rules for cvehound

The same oracle that scores the experiments accepts rules for CVEs that have none.

1. Refresh the sources: `uv run cvehound_update_metadata <kernel> <archive>`, then
   `rulegen build-cvemeta`, `rulegen build-corpus` and `rulegen shape-corpus --split
   newrule`. CVEs fixed since 2025 without a rule land in the `newrule` split.
2. Pick the targets as an id list -- `rulegen sample-newrule --n 200 --out
   data/batch.txt`, or any list of `newrule` CVEs -- and build their inputs:
   `rulegen build-dataset --split newrule --subset data/batch.txt --name batch`.
3. Generate with the oracle loop at suite parity, as the teacher does:
   `rulegen run --config experiments/teach.yaml --set run_id=batch --set data.split=batch
   --set data.subset=data/batch.txt`. A frontier model (`experiments/frontier.yaml` with
   the same `data` settings) or agent sessions (`rulegen agent-run --split newrule
   --subset data/batch.txt`) work the same way.
4. Add the tiers the loop leaves out: `rulegen rescore --run runs/batch --out
   runs/batch-full --selectivity --range --range-mode commits --range-max-points 0
   --tree --heads --cost --tree-jobs 2`.
5. Keep the proven rules: `rulegen select-synthetic --run runs/batch-full --out
   data/new/batch.parquet` keeps rules that are strong-valid, name an introducing
   commit, carry no degenerate flag and cost less than `--cost-cap` CPU-seconds per
   whole-tree scan (calibrate it on this host against `reports/gold-replay-full.json`).
   Write them out with `rulegen export-synthetic --dataset data/new/batch.parquet --out
   rules/`.
6. Audit them with the unmodified suite: `scripts/audit_rules.sh rules/`.
7. Contribute the rules that pass to cvehound as `cvehound/cve/<CVE>.cocci`.

## Layout

```
rulegen/
  cli/            the command line, one module per command family (data, oracle, panels, gen, agent, synthetic)
  schema.py       the shared records: corpus rows, model inputs, legs, scores, score requests
  git.py, tables.py  how every module asks git, and writes tables and id lists
  sources.py      vulns.git + CIP + rule headers side by side -> data/cvemeta.parquet; the agreement rule
  corpus.py       CVEs from cvemeta and the gold rules, temporal splits
  extract.py      deterministic git extraction: diff tiers, -L history, rename chains, survival map
  shapes.py       diff anatomy: fix shape, enclosing functions, subsystem
  tiers.py        literal tokens of a rule, its context class, and the text terms of the reward
  promptbuild.py  input policies (P-B, P-C, P-M, P-H) -> byte-identical prompts; the output contract
  oracle/         reward.py (the tiers, the grade), prefilter.py (whole-tree scans over a mini-tree),
                  antigaming.py (decoys), verdicts.py (one SQLite verdict store), service.py (warm workers)
  gen/            harness.py (sample -> parse -> score), pipeline.py + feedback.py (the repair loop),
                  adapters/ (OpenAI-compatible servers, the claude and codex CLIs, mechanical, fake),
                  canon.py, rescore.py, probe.py, agentic.py, config.py, manifest.py, log.py
  eval/           metrics.py (pass@k, valid@b, bootstrap CIs, A12), driver.py (run logs -> tables)
  panel.py        seeded evaluation panels and the new-rule sample
  synthetic.py    expert iteration: the teacher's pool and the rules it keeps
experiments/      one template per kind of cell, models.yaml
scripts/          bootstrap, serving, the experiment drivers, the suite audit
tests/            unit tests, one file per module, shared builders in helpers.py (no spatch run or
                  network; the slow ones need the kernel clone)
```

## Citing

If you use cvehound-rulegen, please cite it with the metadata in
[CITATION.cff](CITATION.cff).

## License

GPL-3.0; see [LICENSE](LICENSE).
