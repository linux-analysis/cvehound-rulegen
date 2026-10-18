"""The agent command: one session per CVE with the write-cve-rule skill and the suite."""

import argparse
import os

from rulegen import extract
from rulegen.cli import common


def cmd_agent_run(args: argparse.Namespace) -> int:
    """One agent session per CVE with the write-cve-rule skill, validator and suite."""
    from rulegen.gen import agentic

    examples_split = args.examples_split or args.split
    # The new-rule cells read the sampled set when the whole split was never built.
    newrule = extract.examples_path(args.data, 'newrule')
    if not args.examples_split and args.split == 'newrule' and not os.path.exists(newrule):
        examples_split = 'newrule200'
    cfg = agentic.AgentConfig(
        run_id=args.run_id,
        cli=args.cli,
        model=args.model,
        effort=args.effort,
        split=args.split,
        examples_split=examples_split,
        subset=args.subset,
        limit=args.limit,
        repetitions=args.repetitions,
        max_wall_s=args.max_wall_s,
        max_tool_calls=args.max_tool_calls,
        jobs=args.agents,
        suite_workers=args.suite_workers,
        suite_tmpdir=args.suite_tmpdir or '',
        config_dir=args.config_dir,
        cli_bin=args.cli_bin,
        keep_venv=args.keep_venv,
        out=args.out,
        workspaces=args.workspaces,
        notes=args.notes,
    )
    totals = agentic.run_agent(
        cfg,
        common.kernel(args),
        common.oracle_config(args),
        data_dir=args.data,
        cvehound_repo=args.cvehound or None,
        oracle_jobs=args.jobs,
        resume=args.resume,
        dry_run=args.dry_run,
    )
    common.print_json(totals)
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        'agent-run',
        help='agentic rule writing: the write-cve-rule skill and the suite, one session per CVE',
    )
    p.add_argument('--run-id', required=True)
    p.add_argument('--cli', required=True, choices=['claude', 'codex'])
    p.add_argument('--model', required=True, help='vendor model id or alias')
    p.add_argument('--effort', default='medium')
    p.add_argument('--split', default='newrule', help='newrule | gold (train+val+test) | ...')
    p.add_argument(
        '--examples-split',
        default='',
        help='examples parquet for Files: completion (default: guessed)',
    )
    p.add_argument('--subset', default='', help='id-list file, e.g. data/panel-newrule.txt')
    p.add_argument('--limit', type=int, default=0)
    p.add_argument('--repetitions', type=int, default=1, help='sessions per CVE')
    p.add_argument('--max-wall-s', type=float, default=2700.0, help='wall clock per session')
    p.add_argument('--max-tool-calls', type=int, default=200, help='tool calls per session')
    p.add_argument('--agents', type=int, default=2, help='sessions in parallel')
    p.add_argument('--suite-workers', type=int, default=4, help='pytest -n inside a session')
    p.add_argument(
        '--suite-tmpdir',
        default=None,
        help='TMPDIR for the suite worktrees (default: the system temp directory)',
    )
    p.add_argument('--config-dir', default='', help='CLAUDE_CONFIG_DIR / CODEX_HOME for the agent')
    p.add_argument('--cli-bin', default='')
    p.add_argument('--cvehound', default='', help='cvehound checkout (default: beside the kernel)')
    p.add_argument(
        '--keep-venv', action='store_true', help='keep each workspace venv after scoring'
    )
    p.add_argument('--out', default='runs')
    p.add_argument('--workspaces', default='runs/agent-workspaces')
    p.add_argument('--notes', default='')
    p.add_argument('--resume', action='store_true', help='skip CVEs already in samples.jsonl')
    p.add_argument(
        '--dry-run', action='store_true', help='list the sessions and write the manifest'
    )
    common.add_oracle_args(p, jobs=4, selectivity=False)
    p.set_defaults(func=cmd_agent_run)
