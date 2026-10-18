"""The generation commands: prompts, runs, rescoring, reports, exports, leakage probes."""

import argparse
import logging
import os
from typing import Any

from rulegen import extract, tables
from rulegen.cli import common
from rulegen.schema import SPLIT_NONE

log = logging.getLogger('rulegen')


def cmd_show_prompt(args: argparse.Namespace) -> int:
    """Exactly what the model would be sent for one CVE, with per-section token counts."""
    from rulegen.gen import prompts
    from rulegen.gen.config import context_error, counter_safety
    from rulegen.tokens import make_counter

    records = common.records_by_cve(args)
    split = args.split or (records[args.cve].split if args.cve in records else None)
    if not split or split == SPLIT_NONE:
        log.error('%s is in no split (%s); pass --split', args.cve, records.get(args.cve))
        return 1
    examples = extract.load_split_examples(args.data, split)
    example = next((ex for ex in examples if ex.cve == args.cve), None)
    if example is None:
        log.error('%s is not in data/examples/%s.parquet', args.cve, split)
        return 1
    counter_id, count = make_counter(args.tokenizer)
    safety = counter_safety(args.tokenizer)
    built = prompts.build_messages(
        example,
        args.policy,
        args.budget_tokens,
        system_prompt=args.system,
        hide_cve_id=not args.show_cve_id,
        count=count,
        counter_id=counter_id,
    )
    messages = built.messages
    if args.round_feedback:
        from rulegen.gen import pipeline
        from rulegen.gen.log import SampleRow, read_samples

        run_dir, _, attempt = args.round_feedback.partition(':')
        rows = [r for r in read_samples(run_dir) if r.get('attempt_id') == attempt]
        if not rows:
            log.error('no row %s in %s', attempt, run_dir)
            return 1
        row = SampleRow.from_record_with_score(rows[0])
        messages = pipeline.next_turn(row, example, args.feedback, messages, count)
    for message in messages:
        print(f'=== {message["role"]} ({count(message["content"])} tokens) ===')
        print(message['content'])
    print('=== sections (tokens) ===')
    for name, tokens in built.sections.items():
        print(f'{name:18s} {tokens:6d}')
    total = count('\n'.join(m['content'] for m in messages))
    print(
        f'{"total":18s} {total:6d}  (counter {counter_id}, truncated: {" ".join(built.truncated) or "-"})'
    )
    why = context_error(total, safety, args.max_tokens, args.context_tokens)
    fits = f'fits: {total} x {safety} + {args.max_tokens} reply <= {args.context_tokens}'
    print(f'context check: {why or fits}')
    return 0 if why is None else 2


def cmd_prompt_stats(args: argparse.Namespace) -> int:
    """Prompt-size statistics of a finished run, from its sample log."""
    from rulegen.eval.promptstats import prompt_tables
    from rulegen.gen.log import read_samples
    from rulegen.gen.manifest import read_manifest

    rows = read_samples(args.run)
    manifest = read_manifest(args.run)
    try:
        context = args.context_tokens or int(manifest['prompt']['context_tokens'])
        max_tokens = args.max_tokens or int(manifest['config']['sampling']['max_tokens'])
    except KeyError as err:
        raise SystemExit(
            f'{args.run}: the manifest has no {err}; pass --context-tokens and --max-tokens'
        ) from err
    print(f'# {args.run}: {len(rows)} rows, context {context}, max_tokens {max_tokens}\n')
    print(tables.render_markdown(prompt_tables(rows, context, max_tokens)))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from rulegen.gen import harness
    from rulegen.gen.config import load_config

    cfg = load_config(args.config, args.set)
    totals = harness.run(
        cfg, common.kernel(args), data_dir=args.data, resume=args.resume, dry_run=args.dry_run
    )
    common.print_json(totals)
    return 0


def cmd_rescore(args: argparse.Namespace) -> int:
    from rulegen.gen import canon, rescore
    from rulegen.gen.manifest import read_manifest
    from rulegen.oracle.service import OracleService

    transform = args.canonicalize
    if transform == rescore.AUTO:
        transform = rescore.inherited_transform(read_manifest(args.run[0]))
    transform = transform if canon.transform_fn(transform) else None
    out = args.out or f'{args.run[0].rstrip("/")}-{transform or "rescored"}'
    subset = tables.read_ids(args.subset) if args.subset else None
    with OracleService(common.oracle_config(args), jobs=args.jobs) as svc:
        totals = rescore.rescore(args.run, out, args.data, svc, transform=transform, subset=subset)
    common.print_json(totals)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from rulegen.eval import driver

    report = driver.report(
        args.run, key=args.key, merge=args.merge, gold_cost=args.gold_cost, prices=args.prices
    )
    text = tables.render_markdown(report)
    if args.out:
        tables.write_text(os.path.join(args.out, 'report.md'), text)
        tables.write_csv(report, args.out)
        log.info('wrote %s/report.md (+csv)', args.out)
    print(text)
    return 0


def cmd_export_rules(args: argparse.Namespace) -> int:
    from rulegen.gen.log import export_rules

    written = export_rules(args.run, args.out, column=args.column, key=args.key)
    if args.id_list:
        tables.write_ids(
            args.id_list, [os.path.basename(p).removesuffix('.cocci') for p in written]
        )
    log.info('wrote %d rules to %s', len(written), args.out)
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    from rulegen.gen import probe
    from rulegen.gen.manifest import cvehound_path

    adapter: Any
    if args.adapter == 'openai-compat':
        from rulegen.gen.adapters.openai_compat import OpenAICompatAdapter

        adapter = OpenAICompatAdapter(args.endpoint, model=args.model, timeout_s=600)
    else:
        from rulegen.gen.adapters.claude_cli import ClaudeCliAdapter
        from rulegen.gen.adapters.codex_cli import CodexCliAdapter

        cls = ClaudeCliAdapter if args.adapter == 'claude-cli' else CodexCliAdapter
        adapter = probe.ChatCompleter(
            cls(args.model, args.effort, config_dir=args.config_dir or None, timeout_s=1800),
            ref=args.ref,
        )
    rows = probe.run_membership(
        adapter,
        cvehound_path(common.kernel(args)),
        common.load_corpus(args),
        ref=args.ref,
        n_predict=args.n_predict,
        threshold=args.threshold,
        limit=args.limit,
        sample=args.sample,
        seed=args.seed,
    )
    print(probe.write_results(rows, args.out, args.threshold))
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    from rulegen.gen import canon

    p = sub.add_parser('show-prompt', help='print exactly what the model is sent for one CVE')
    p.add_argument('--cve', required=True)
    p.add_argument('--policy', default='P-H')
    p.add_argument('--split', default=None, help="default: the CVE's split in the corpus")
    p.add_argument('--system', default='sys-v1')
    p.add_argument('--budget-tokens', type=int, default=8192)
    p.add_argument('--tokenizer', default=None, help='tokenizer.json for exact counts')
    p.add_argument('--show-cve-id', action='store_true')
    p.add_argument('--context-tokens', type=int, default=16384)
    p.add_argument('--max-tokens', type=int, default=2048)
    p.add_argument(
        '--round-feedback',
        default=None,
        help='RUN_DIR:ATTEMPT_ID -- also print the repair turn that would follow that attempt',
    )
    p.add_argument('--feedback', default='oracle', choices=['oracle', 'critique'])
    p.set_defaults(func=cmd_show_prompt)

    p = sub.add_parser('prompt-stats', help='prompt tokens per round, slot overflows, trimming')
    p.add_argument('--run', required=True)
    p.add_argument('--context-tokens', type=int, default=0, help='default: the manifest')
    p.add_argument('--max-tokens', type=int, default=0, help='default: the manifest')
    p.set_defaults(func=cmd_prompt_stats)

    p = sub.add_parser('run', help='generate candidate rules from a model and score them')
    p.add_argument('--config', required=True, help='experiments/<name>.yaml')
    p.add_argument('--set', action='append', default=[], help='override, e.g. sampling.n=5')
    p.add_argument('--resume', action='store_true', help='skip attempts already in samples.jsonl')
    p.add_argument('--dry-run', action='store_true', help='build prompts and the manifest only')
    p.set_defaults(func=cmd_run)

    p = sub.add_parser(
        'rescore', help='re-score a run offline, e.g. after patch-to-detect canonicalization'
    )
    p.add_argument('--run', action='append', required=True, help='parent run; repeatable')
    p.add_argument('--out', default='', help='default <run>-<transform>')
    p.add_argument('--subset', default='', help='file of CVE ids: re-score only these rows')
    p.add_argument(
        '--canonicalize',
        default='auto',
        choices=['auto', *sorted(canon.TRANSFORMS), 'none', ''],
        help='auto (whatever the run itself scored with) | canon | patch-to-detect '
        '| polish | none (score the rules as written)',
    )
    common.add_oracle_args(p, jobs=12, selectivity=True)
    p.set_defaults(func=cmd_rescore)

    p = sub.add_parser('report', help='pass@k / valid@b / funnel tables from run logs')
    p.add_argument('--run', action='append', required=True, help='run directory; repeatable')
    p.add_argument('--key', default='s_valid', help='s_valid or s_strong_valid')
    p.add_argument('--merge', default='', help='treat all --run dirs as one run with this name')
    p.add_argument(
        '--gold-cost', default='reports/gold-replay-full.json', help='gold cost distribution'
    )
    p.add_argument(
        '--prices',
        default='experiments/models.yaml',
        help='list prices (the `frontier:` map) for the $ table of vendor-CLI runs',
    )
    p.add_argument('--out', default='', help='write report.md and CSVs here')
    p.set_defaults(func=cmd_report)

    p = sub.add_parser(
        'export-rules', help="a run's rules as <CVE>.cocci files (suite audit input)"
    )
    p.add_argument('--run', required=True)
    p.add_argument('--out', required=True)
    p.add_argument(
        '--column',
        default='rule_text',
        help='the column holding the rule (default: what was scored)',
    )
    p.add_argument('--key', default='s_valid', help='prefer a row where this column is true')
    p.add_argument('--id-list', default='', help='also write the CVE ids, one per line')
    p.set_defaults(func=cmd_export_rules)

    p = sub.add_parser('probe', help='membership-completion leakage check on the public rule text')
    p.add_argument(
        '--adapter',
        default='openai-compat',
        choices=['openai-compat', 'claude-cli', 'codex-cli'],
        help='openai-compat = llama-server raw completion; the CLIs ask in a chat turn',
    )
    p.add_argument('--endpoint', default='http://127.0.0.1:8080/v1')
    p.add_argument('--model', default='')
    p.add_argument('--effort', default='medium', help='CLI adapters: reasoning effort')
    p.add_argument('--config-dir', default='', help='CLI adapters: CLAUDE_CONFIG_DIR / CODEX_HOME')
    p.add_argument('--sample', type=int, default=0, help='draw this many rules at random')
    p.add_argument('--seed', type=int, default=0)
    p.add_argument('--ref', default='1.3.0', help='cvehound tag holding the public rule text')
    p.add_argument('--n-predict', type=int, default=256)
    p.add_argument('--threshold', type=float, default=0.9)
    p.add_argument('--limit', type=int, default=0)
    p.add_argument('--out', required=True, help='runs/probe-<model>')
    p.set_defaults(func=cmd_probe)
