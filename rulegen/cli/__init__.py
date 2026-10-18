"""rulegen command line: build the corpus and datasets, score rules, generate and evaluate.

`rulegen <command> --help` describes each command; README.md shows them in order.
Each module of this package registers its own commands next to their handlers.
"""

import argparse
import logging
import sys

from rulegen.cli import agent, common, data, gen, oracle, panels
from rulegen.oracle.service import install_diag_handler

log = logging.getLogger('rulegen')

# In the order `rulegen --help` lists them.
COMMANDS = (data, oracle, panels, gen, agent)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='rulegen')
    parser.add_argument('--kernel', default=common.DEFAULT_KERNEL)
    parser.add_argument('--metadata', default=None, help='kernel_cves.json.gz override')
    parser.add_argument('--data', default=common.DEFAULT_DATA)
    parser.add_argument('-v', '--verbose', action='store_true')
    sub = parser.add_subparsers(dest='command', required=True)
    for module in COMMANDS:
        module.register(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))
    # cvehound logs 'Checking:'/'Found:' to the root logger per check; a batch
    # replay wants only its own summary. Give rulegen a private handler and,
    # unless -v, keep the root logger quiet so those per-check lines drop.
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.ERROR,
        format='%(message)s',
    )
    log.handlers = [handler]
    log.propagate = False  # the private handler prints rulegen lines exactly once
    log.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    # jobs=1 scores in this process: the engine's diagnostics must survive the
    # quiet root here as they do in a pool worker (rulegen.oracle.service).
    install_diag_handler()
    try:
        return args.func(args)
    except FileNotFoundError as err:
        # A missing input is the user's to fix: one line, the traceback under -v.
        if args.verbose:
            raise
        log.error('rulegen %s: %s', args.command, err)
        return 1


if __name__ == '__main__':
    sys.exit(main())
