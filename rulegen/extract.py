"""Deterministic git extraction: everything a prompt can be built from.

Every field is a pure function of immutable git objects, so an example can
always be rebuilt from (kernel tip, extractor version). Caps are part of the
extractor's identity — bump EXTRACTOR_VERSION when any of them changes.
"""

import logging
import os
import re
from collections import Counter

from rulegen import tables, tokens
from rulegen.git import GitError, git, git_run, resolves
from rulegen.schema import GOLD_SPLITS, CveRecord, ExampleRecord

log = logging.getLogger(__name__)

EXTRACTOR_VERSION = 1

# Reference tags for the symbol survival map: wide spread over the stable era.
REF_TAGS = ('v2.6.32', 'v3.10', 'v4.4', 'v4.14', 'v4.19', 'v5.4', 'v5.10', 'v5.15', 'v6.1', 'v6.6')

SOURCE_SUFFIXES = ('.c', '.h', '.S')
EXCLUDED_PREFIXES = ('Documentation/', 'tools/', 'scripts/', 'samples/')

MAX_INTERMEDIATE = 50
MAX_SURVIVAL_SYMBOLS = 15
# Slots inside MAX_SURVIVAL_SYMBOLS reserved for historical (class-E) symbols:
# they are the survival map's whole point, and without a reservation the
# changed-line symbols alone fill the cap on almost every diff.
SURVIVAL_HISTORICAL_SLOTS = 5
MAX_HISTORICAL_SYMBOLS = 40
MAX_L_HUNKS = 4
MAX_L_BYTES = 300_000

# Trailer keys dropped from commit messages. Fixes: is deliberately kept — it
# carries the introducing commit's subject inline.
_TRAILER_KEYS = frozenset(
    key.lower()
    for key in (
        'signed-off-by',
        'reviewed-by',
        'acked-by',
        'tested-by',
        'reported-by',
        'suggested-by',
        'co-developed-by',
        'cc',
        'link',
        'closes',
        'message-id',
        'reported-and-tested-by',
        'reviewed-and-tested-by',
        'debugged-by',
        'bisected-by',
        'analyzed-by',
        'noticed-by',
        'requested-by',
        'diagnosed-by',
        'addresses-coverity',
        'addresses-coverity-id',
        'change-id',
        'bug',
    )
)
_TRAILER_RE = re.compile(r'^([A-Za-z][A-Za-z0-9-]*):\s')


def strip_message(message: str) -> tuple[str, bool]:
    """Commit message minus trailers (Fixes: kept); plus a syzbot flag."""
    kept: list[str] = []
    syzbot = 'syzbot' in message or 'syzkaller' in message
    for line in message.splitlines():
        match = _TRAILER_RE.match(line.strip())
        if match and match.group(1).lower() in _TRAILER_KEYS:
            continue
        kept.append(line.rstrip())
    text = '\n'.join(kept).strip()
    return re.sub(r'\n{3,}', '\n\n', text) + ('\n' if text else ''), syzbot


def show_diff(kernel: str, fix: str, files: list[str], *flags: str) -> str:
    """The fix commit's diff, limited to `files` when there are any."""
    args = ['show', '--format=', *flags, fix]
    if files:
        args += ['--', *files]
    return git(kernel, *args)


def changed_lines_only(diff_u0: str) -> str:
    """The +/- payload of a -U0 diff, with file boundaries kept as headers."""
    out: list[str] = []
    for line in diff_u0.splitlines():
        if line.startswith(('--- ', '+++ ')):
            if line.startswith('+++ '):
                out.append(line)
        elif line.startswith(('+', '-')):
            out.append(line)
    return '\n'.join(out) + ('\n' if out else '')


def files_candidates(kernel: str, fix: str) -> list[str]:
    names = git(kernel, 'show', '--format=', '--name-only', fix).split()
    return [
        name
        for name in names
        if name.endswith(SOURCE_SUFFIXES) and not name.startswith(EXCLUDED_PREFIXES)
    ]


def fix_hunks(diff_b: str) -> list[tuple[str, int, int]]:
    """(file, new-side start, new-side count) per hunk of a -U3 diff."""
    hunks: list[tuple[str, int, int]] = []
    current = None
    for line in diff_b.splitlines():
        if line.startswith('+++ b/'):
            current = line[6:]
        elif line.startswith('@@') and current:
            match = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', line)
            if match:
                hunks.append((current, int(match.group(1)), int(match.group(2) or 1)))
    return hunks


def historical_names(kernel: str, fixes: str, fix: str, path: str) -> list[str]:
    """Older names of the file within fixes..fix (rename chain), newest first."""
    try:
        out = git(
            kernel, 'log', '--format=', '--name-only', '--follow', f'{fixes}..{fix}', '--', path
        )
    except GitError:
        return []
    names: list[str] = []
    for name in out.split():
        if name != path and name not in names:
            names.append(name)
    return names


def intermediate_commits(kernel: str, fixes: str, fix: str, files: list[str]) -> list[str]:
    try:
        out = git(
            kernel,
            'log',
            '--format=%h %s',
            f'--max-count={MAX_INTERMEDIATE}',
            f'{fixes}..{fix}',
            '--',
            *files,
        )
    except GitError:
        return []
    return out.splitlines()


def hunk_lines(patch: str) -> str:
    """The code lines of a patch (`+`, `-`, context), without commit headers,
    messages, `diff --git` preambles or file markers."""
    out: list[str] = []
    in_hunk = False
    for line in patch.splitlines():
        if line.startswith('@@'):
            in_hunk = True
            continue
        if line.startswith(('diff --git', 'commit ', 'Author:', 'Date:', 'index ')):
            in_hunk = False
            continue
        if in_hunk and line[:1] in ('+', '-', ' ') and not line.startswith(('+++', '---')):
            out.append(line[1:])
    return '\n'.join(out)


def historical_symbols(
    kernel: str, fixes: str, fix: str, hunks: list[tuple[str, int, int]], current_text: str
) -> list[str]:
    """Identifiers that appear in the traced in-range history of the fix's
    hunks but nowhere in the current files — the pre-rename names and
    short-lived identifiers a back-portable rule needs (context class E)."""
    current = set(tokens.identifiers(current_text))
    seen: Counter[str] = Counter()
    for path, start, count in hunks[:MAX_L_HUNKS]:
        end = start + max(count, 1) - 1
        # -L refuses files created mid-range and other edge shapes; those
        # hunks simply contribute nothing. Only the code lines count: the
        # commit headers and messages the log carries are prose (author
        # names, mail hosts, "returns"), not identifiers the tree ever held.
        patch = git(
            kernel, 'log', '-p', '--format=', f'-L{start},{end}:{path}', f'{fixes}..{fix}', ok=None
        )
        seen.update(tokens.identifiers(hunk_lines(patch[:MAX_L_BYTES])))
    extra = [sym for sym, _ in seen.most_common() if sym not in current]
    return extra[:MAX_HISTORICAL_SYMBOLS]


def _scope_dirs(files: list[str]) -> list[str]:
    dirs = {path.rsplit('/', 1)[0] for path in files if '/' in path}
    return sorted(dirs) + ['include']


def survival_map(
    kernel: str, symbols: list[str], files: list[str], branches: tuple[str, ...] = ()
) -> list[str]:
    """'sym: present <tags>; absent <tags>' lines over the reference tags.

    Scoped to the candidate files' directories plus include/ so the probe stays
    cheap; a symbol that moved subsystem entirely reads as absent, which is
    still the honest hint for a rule anchored in these files.
    """
    tags = [tag for tag in (*REF_TAGS, *branches) if resolves(kernel, tag)]
    scope = _scope_dirs(files)
    lines: list[str] = []
    for sym in symbols[:MAX_SURVIVAL_SYMBOLS]:
        present: list[str] = []
        absent: list[str] = []
        for tag in tags:
            found = git_run(kernel, 'grep', '-lqw', sym, tag, '--', *scope).returncode == 0
            (present if found else absent).append(tag)
        if absent:
            lines.append(f'{sym}: present {" ".join(present) or "-"}; absent {" ".join(absent)}')
        else:
            lines.append(f'{sym}: present everywhere')
    return lines


def _survival_symbols(diff_a: str) -> list[str]:
    """Changed-line identifiers worth probing, rarest-looking first."""
    counts = tokens.identifiers(diff_a)
    # Longer identifiers are rarer in the tree and cheaper to grep; prefer them.
    ranked = sorted(counts, key=lambda sym: (-len(sym), sym))
    return ranked[:MAX_SURVIVAL_SYMBOLS]


def build_example(kernel: str, rec: CveRecord) -> ExampleRecord:
    if not rec.fix:
        raise ValueError(f'{rec.cve}: no fix commit')
    if not resolves(kernel, rec.fix):
        raise ValueError(f'{rec.cve}: unresolvable fix {rec.fix}')
    # Every range-derived section below (historical names, intermediate commits,
    # historical symbols, the survival map) is empty without an introducing
    # commit, and the oracle cannot run the fixes legs or T5 either: such an
    # example is not a smaller prompt, it is not a usable example.
    if not rec.fixes:
        raise ValueError(f'{rec.cve}: no introducing commit')
    if not resolves(kernel, rec.fixes):
        raise ValueError(f'{rec.cve}: unresolvable introducing commit {rec.fixes}')
    fixes = rec.fixes

    message = git(kernel, 'log', '-1', '--format=%B', rec.fix)
    msg_stripped, syzbot = strip_message(message)
    subject = message.splitlines()[0] if message else rec.cmt_subject

    cands = files_candidates(kernel, rec.fix)
    scope = cands or []
    diff_b = show_diff(kernel, rec.fix, scope)
    fallback = False
    if not diff_b.strip():
        # The fix touches nothing that survives the source filter (or is a
        # merge); fall back to the unrestricted diff rather than an empty one.
        scope = []
        diff_b = show_diff(kernel, rec.fix, scope)
        fallback = True
    diff_u0 = show_diff(kernel, rec.fix, scope, '-U0')
    diff_c = show_diff(kernel, rec.fix, scope, '-W')
    diff_a = changed_lines_only(diff_u0)

    hunks = fix_hunks(diff_b)
    hist_names = {
        path: names for path in cands if (names := historical_names(kernel, fixes, rec.fix, path))
    }
    inter = intermediate_commits(kernel, fixes, rec.fix, cands)

    current_blobs = []
    for path in cands:
        for rev in (f'{rec.fix}~', rec.fix):
            proc = git_run(kernel, 'show', f'{rev}:{path}')
            if proc.returncode == 0:
                current_blobs.append(proc.stdout)
    current_text = '\n'.join(current_blobs)

    hist_syms = historical_symbols(kernel, fixes, rec.fix, hunks, current_text)
    hist_slots = min(len(hist_syms), SURVIVAL_HISTORICAL_SLOTS)
    probe_syms = _survival_symbols(diff_a)[: MAX_SURVIVAL_SYMBOLS - hist_slots]
    probe_syms += hist_syms[:hist_slots]
    surv = survival_map(kernel, probe_syms, cands)

    counter = tokens.approx_token_count
    size_stats = {
        'diff_a': counter(diff_a),
        'diff_b': counter(diff_b),
        'diff_c': counter(diff_c),
        'msg': counter(msg_stripped),
        'full_files': counter(current_text),
    }

    return ExampleRecord(
        cve=rec.cve,
        fix=rec.fix,
        fixes=fixes,
        initial_epoch=rec.initial_epoch,
        msg_subject=subject,
        msg_stripped=msg_stripped,
        syzbot=syzbot,
        diff_a=diff_a,
        diff_b=diff_b,
        diff_c=diff_c,
        diff_fallback_unrestricted=fallback,
        files_candidates=cands,
        files_gold=rec.files_gold,
        historical_names=hist_names,
        intermediate=inter,
        historical_symbols=hist_syms,
        survival_map=surv,
        size_stats=size_stats,
    )


# A split name that stands for several example files, loaded together. `gold`
# is every rule-bearing CVE, so a panel drawn across train/val/test can run as
# one cell.
MERGED_SPLITS: dict[str, tuple[str, ...]] = {'gold': GOLD_SPLITS}


def examples_path(data_dir: str, name: str) -> str:
    """The examples parquet of one split (or of a `build-dataset --name`)."""
    return os.path.join(data_dir, 'examples', f'{name}.parquet')


def load_split_examples(data_dir: str, split: str) -> list[ExampleRecord]:
    """The examples of a split, or of every split a merged name stands for."""
    out: list[ExampleRecord] = []
    seen: set[str] = set()
    for part in MERGED_SPLITS.get(split, (split,)):
        for ex in load_examples(examples_path(data_dir, part)):
            if ex.cve not in seen:
                seen.add(ex.cve)
                out.append(ex)
    return out


def load_examples(path: str) -> list[ExampleRecord]:
    return [ExampleRecord.from_row(row) for row in tables.read_rows(path)]


def save_examples(examples: list[ExampleRecord], path: str) -> None:
    tables.write_rows([ex.to_row() for ex in examples], path)
