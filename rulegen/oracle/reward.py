"""The tiered oracle: T0 structure → T1 parse → T2 core pairs → T3 backports
→ decoys → T4 selectivity → T5 range sweep → T6 whole-tree scans → rule cost.

T3 judges each stable branch at the commit that carried the fix there: the
rule must fire just before the backport and stay silent at it. Branches the
sources name no backport for get no leg. Today's branch heads are scanned too,
but only as information (`head:` legs): a fire there is a regression or a
missing backport to look at, never a verdict on the rule.

T4, T5, T6 and the cost probe run only for rules that already pass acceptance:
they never change `valid`, they decide `strong_valid`, shape the reward when
they ran (grade()) and feed the audit and the cost-as-a-metric tables.

Verdict semantics match the cvehound test suite exactly because the checks go
through cvehound.oracle.cached_check / CVEhound.check_cve. Timeouts and spatch
errors are their own verdicts and are never scored as silence.
"""

import hashlib
import logging
import os
import re
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from cvehound import SPATCH_TIMEOUT, CVEhound, _spatch_env
from cvehound.exception import SpatchError, SpatchTimeout, SpatchTruncated, UnsupportedVersion
from cvehound.oracle.kerneltree import (
    BlobMaterializer,
    Sig,
    cached_all_files_check,
    cached_check,
    hound_at,
    sig_has_rule_files,
)
from cvehound.util import (
    killpg,
    parse_spatch_summary,
    parse_spatch_timeout,
    parse_spatch_truncation,
)

from rulegen import tiers
from rulegen.git import commit_oid
from rulegen.oracle import antigaming, prefilter
from rulegen.oracle.verdicts import HeavySlots, ProbeStore, SqliteVerdictCache
from rulegen.oracle.worktrees import WorktreeStore
from rulegen.schema import (
    CVE_ID_RE,
    ERROR,
    FIRE,
    HARD_VERDICTS,
    INITIAL_COMMIT,
    LEG_BP,
    LEG_BP_PRE,
    LEG_CORE,
    LEG_DECOY,
    LEG_HEAD,
    LEG_RANGE,
    LEG_TREE,
    NO_FILES,
    SILENT,
    TIMEOUT,
    TRUNCATED,
    UNSUPPORTED,
    Leg,
    Score,
    ScoreRequest,
    branch_of_ref,
    rule_sha,
)

log = logging.getLogger(__name__)
# One line per leg the engine did not finish (a timeout, a crash, a truncated
# scan). Workers silence the root logger; this one is kept, because it is the
# only record of why a verdict is missing (rulegen.oracle.service).
diag = logging.getLogger('rulegen.oracle.diag')

# Mixed into the verdict-cache identity: bump on any semantic change to how
# one check is *run* (flags, materialization), so old verdicts can never answer
# new questions. A verdict is a function of rule bytes, blob signature and the
# spatch build; which signatures are asked, and how legs aggregate, is
# SCORE_EPOCH's business and costs no cached verdict.
ORACLE_EPOCH = 'rulegen-oracle-v1'
# How legs are chosen and aggregate into a Score and its grade. Recorded in
# manifests; it keys no cached verdict.
SCORE_EPOCH = 'rulegen-score-v1'
# The cost memo has its own epoch so its semantics can move without throwing
# away the (much larger) verdict cache.
COST_EPOCH = 'rulegen-cost-v1'
# T1 and T4 are as pure as the leg checks the verdict cache already memoizes: a
# rule's parse result (with the grep query spatch infers) and its lib/ prefilter
# count depend only on the rule bytes, the tree and the spatch build. Own epochs
# so each can move alone.
PARSE_EPOCH = 'rulegen-parse-v1'
SELECTIVITY_EPOCH = 'rulegen-selectivity-v1'
# The prefilter signature memo (which files a grep query selects at a commit).
PREFILTER_EPOCH = 'rulegen-prefilter-v1'

# Every epoch, for manifests and rescore provenance: one place to add to.
EPOCHS = {
    'ORACLE_EPOCH': ORACLE_EPOCH,
    'SCORE_EPOCH': SCORE_EPOCH,
    'COST_EPOCH': COST_EPOCH,
    'PARSE_EPOCH': PARSE_EPOCH,
    'SELECTIVITY_EPOCH': SELECTIVITY_EPOCH,
    'PREFILTER_EPOCH': PREFILTER_EPOCH,
}

# Reward shaping. Terms unavailable for a CVE or a run (no
# introducing commit, initial-epoch Fixes~, a tier that did not run) drop out
# and each band renormalizes over what ran (two bands: see Grade.reward).
# Discriminating the fix (`fix`) is worth more than merely matching the
# vulnerable code (`fix~`): the second without the first is the over-broad rule.
WEIGHTS = {
    # format
    'structure': 0.05,
    'parse': 0.10,
    'grep_query': 0.05,
    # the text: names something, and nothing on a report line is a wildcard
    'anchored': 0.05,
    'specific_star': 0.05,
    # acceptance legs
    'fix~': 0.20,
    'fix': 0.25,
    'fixes': 0.10,
    'fixes~': 0.05,
    'init': 0.05,
    'backports': 0.10,
    'decoys': 0.10,
    # beyond acceptance, when the tier ran: shaping, never validity
    'selective': 0.05,
    'era': 0.10,
    'tree': 0.05,
}

# The leg kinds acceptance is decided on; anything else (range, tree, head) is
# post-acceptance or informational and never a hard zero.
ACCEPTANCE_KINDS = (LEG_CORE, LEG_BP_PRE, LEG_BP, LEG_DECOY)
# Engine failures (HARD_VERDICTS, rulegen.schema): never scored as silence, a
# hard zero on an acceptance leg.

# The legs that decide acceptance one commit at a time (T2 + the initial-commit
# silence): every one of them must hold for `valid`.
CORE_LEGS = ('fix~', 'fix', 'fixes', 'fixes~', 'init')

SELECTIVITY_DIR = 'lib'
SELECTIVITY_WALL = 120  # seconds; a probe that runs longer has no usable query

# Address-space ceiling for one spatch. A rule whose grep query lets tens of
# thousands of files through parses them all in one process, and spatch can
# grow to tens of GB doing it. Bounding it turns a machine-wide out-of-memory
# into one rule's ERROR verdict. Wall limits alone do not help: the memory is
# gone long before the seconds are.
#
# 8 GB rather than more: the ceiling multiplies by the worker count, and nothing
# legitimate is lost. The dataset gate rejects any rule costing more than 60
# CPU-s of whole-tree scan, and a rule that has parsed its way to 8 GB passed
# that long ago.
#
# It is HEADROOM, not the whole ceiling: see address_space_limit() below. RLIMIT_AS
# counts mapped files, and every git query the oracle makes maps the clone's
# object store first, so a bare 8 GB is a cap on the repository rather than on
# spatch once that store passes 8 GB.
SPATCH_ADDRESS_SPACE_LIMIT = 8 * 1024 * 1024 * 1024


def object_store_bytes(kernel: str) -> int:
    """Address space a git query maps before it does anything: packs and graphs.

    `git cat-file --batch-check` -- the long-lived process every leg's blob
    lookup goes through -- mmaps every packfile, the commit-graph and the pack
    indexes. That is address space the oracle cannot choose not to use.
    """
    root = os.path.join(kernel, '.git')
    if not os.path.isdir(root):
        root = kernel  # a bare clone
    total = 0
    for sub in ('objects/pack', 'objects/info'):
        path = os.path.join(root, sub)
        if not os.path.isdir(path):
            continue
        with os.scandir(path) as entries:
            total += sum(e.stat().st_size for e in entries if e.is_file())
    return total


def address_space_limit(headroom: int, kernel: str) -> int:
    """What RLIMIT_AS must be for `headroom` to mean what it says.

    The ceiling exists to stop one runaway spatch parse, so it has to sit above
    the mappings that are there before spatch starts. On a clone whose packs
    are larger than the headroom, a flat ceiling would kill `git cat-file` at
    startup, and every rule would fail with a broken pipe rather than a verdict.
    0 means the cap is off, and stays off.
    """
    if not headroom:
        return 0
    return headroom + object_store_bytes(kernel)


def limit_address_space(limit: int = SPATCH_ADDRESS_SPACE_LIMIT) -> None:
    """Cap this process and everything it goes on to spawn.

    Set once per oracle worker rather than per subprocess: most spatch runs are
    not ours to launch. The leg checks go through cvehound's `cached_check`,
    which talks to a `spatch --zygote` the library forks itself, and that zygote
    is what a whole-tree scan grows inside. A child inherits RLIMIT_AS, so
    limiting the worker limits every spatch beneath it, however it got there.
    """
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    if hard != resource.RLIM_INFINITY:
        limit = min(limit, hard)
    resource.setrlimit(
        resource.RLIMIT_AS, (limit, limit if hard == resource.RLIM_INFINITY else hard)
    )


# The parsed-C AST cache pays for itself here in a way it cannot in the suite:
# the blob store gives a file the same path across rules and runs, and a repair
# loop checks dozens of rules against the same handful of trees, so every rule
# after the first reads the parse instead of redoing it (about twice as fast).
# It is always on. coccinelle keys entries by the absolute
# path of the parsed file, so the cache lives next to the blob store it indexes
# (`<work_root>/astcache/<spatch build>`) and travels with it; coccinelle never
# prunes, so the size is ours to bound.
ASTCACHE_LIMIT = 8 * 1024 * 1024 * 1024


def store_dir(work_root: str) -> str:
    """The content-addressed blob store and the per-commit trees linked from it."""
    return os.path.join(work_root, 'store')


def cache_dir(work_root: str) -> str:
    """The SQLite verdict and probe store (rulegen.oracle.verdicts)."""
    return os.path.join(work_root, 'oracle_cache')


def astcache_path(work_root: str, spatch: str) -> str:
    """This work root's parse cache for one spatch build (entries are untyped
    marshalled OCaml values, unreadable across builds)."""
    from cvehound.util import spatch_identity as build_identity

    ident = hashlib.sha256(build_identity(spatch).encode()).hexdigest()[:16]
    path = os.path.join(os.path.abspath(work_root), 'astcache', ident)
    os.makedirs(path, exist_ok=True)
    return path


RANGE_MAX_POINTS = 16  # T5: distinct blob signatures checked in Fixes..Fix~ (evenly spaced)
RANGE_MODES = ('tags', 'commits')  # T5 enumeration: tagged kernels, or every commit (test_05)
COST_REF = antigaming.DECOY_TAG  # one pinned whole tree so rule costs are comparable
COST_WALL = 300  # seconds; the suite's own whole-tree wall


@dataclass(frozen=True, kw_only=True)
class OracleOptions:
    """Which checks run beyond T0-T3, and how wide: the one set of knobs the
    service (OracleConfig), a run's config (OracleRunConfig) and the command
    line all describe. Everything past the decoys runs only on a valid rule."""

    run_decoys: bool = True
    run_selectivity: bool = False  # T4
    run_range: bool = False  # T5
    run_tree: bool = False  # T6 at each backport
    run_heads: bool = False  # informational whole-tree scans at today's heads
    run_cost: bool = False
    tree_jobs: int = 1  # spatch -j for whole-tree scans
    range_max_points: int = RANGE_MAX_POINTS  # 0 = every distinct signature
    range_mode: str = 'tags'  # T5 enumeration: tags | commits (the suite's --between-mode)


@dataclass
class OracleCtx:
    kernel: str
    hound: CVEhound
    materializer: BlobMaterializer
    # The kernel clone itself. The materializer is handed an object reader
    # (`repo.git`); the tag/log/worktree calls below want the repo.
    repo: Any
    cache: SqliteVerdictCache | None
    probes: ProbeStore
    branches: tuple[str, ...]
    decoy_blobs: list[tuple[str, str]]
    rules_dir: str
    work_root: str = ''
    worktrees: WorktreeStore | None = None  # created lazily: only the cost probe needs one
    spatch_id: str = ''  # verdict_identity(hound), hashed: part of every probe memo key
    heavy: HeavySlots = field(default_factory=lambda: HeavySlots('', 0))  # n=0: unbounded
    resolved: dict[str, str | None] = field(default_factory=dict)

    def worktree(self, ref: str) -> str:
        if self.worktrees is None:
            self.worktrees = WorktreeStore(self.repo, os.path.join(self.work_root, 'worktrees'))
        return self.worktrees.path(ref)

    def resolve(self, ref: str) -> str | None:
        """The commit a ref names, memoized: refs do not move during a run."""
        if ref not in self.resolved:
            self.resolved[ref] = commit_oid(self.materializer.git, ref)
        return self.resolved[ref]

    def ref_resolvable(self, ref: str) -> bool:
        return self.resolve(ref) is not None

    @property
    def store_root(self) -> str:
        return store_dir(self.work_root)


def verdict_identity(hound: CVEhound) -> str:
    """conftest._spatch_identity's fields plus this oracle's epoch.

    The parse cache is not part of it: a verdict is a function of the rule
    bytes, the blob signature and the spatch build, and cvehound verified the
    CTL is identical with and without the cache.
    """
    out = subprocess.run([hound.spatch, '--version'], capture_output=True, check=True, text=True)
    return '\x00'.join(
        (
            hound.spatch,
            out.stdout.strip(),
            f'zygote={hound.zygote}',
            ORACLE_EPOCH,
        )
    )


def make_ctx(
    kernel: str,
    work_root: str,
    branches: tuple[str, ...],
    use_cache: bool = True,
    zygote: str | None = None,
    worktrees_root: str | None = None,
    heavy_slots: int = 0,
) -> OracleCtx:
    from cvehound.util import find_spatch
    from git import Repo

    kernel = os.path.abspath(kernel)
    work_root = os.path.abspath(work_root)
    rules_dir = os.path.join(work_root, 'rules')
    os.makedirs(rules_dir, exist_ok=True)
    hound = CVEhound(kernel, zygote=zygote, ast_cache=astcache_path(work_root, find_spatch(None)))
    repo = Repo(kernel)
    materializer = BlobMaterializer(repo.git, store_dir(work_root))
    identity = verdict_identity(hound)
    cache = SqliteVerdictCache(cache_dir(work_root), identity) if use_cache else None
    return OracleCtx(
        kernel=kernel,
        hound=hound,
        materializer=materializer,
        repo=repo,
        cache=cache,
        probes=ProbeStore(cache_dir(work_root), conn=cache.conn if cache else None),
        branches=tuple(branches),
        decoy_blobs=antigaming.decoy_blobs(materializer),
        rules_dir=rules_dir,
        spatch_id=hashlib.sha256(identity.encode()).hexdigest()[:16],
        work_root=work_root,
        worktrees=WorktreeStore(repo, worktrees_root) if worktrees_root else None,
        heavy=HeavySlots(work_root, heavy_slots),
    )


def probe_memo(
    ctx: OracleCtx,
    key: str,
    compute: Callable[[], dict],
    accept: Callable[[dict], bool] = lambda _rec: True,
) -> dict:
    """Memoize one probe result per key in the shared oracle store (verdicts.ProbeStore).

    The probes that are not legs -- T1 parse, T4 selectivity, the cost scan --
    keyed by rule bytes, tree and epoch, so a rescore or a later run never
    repeats them.
    """
    cached = ctx.probes.get(key)
    if cached is not None and accept(cached):
        return cached
    rec = {**compute(), 'key': key}
    ctx.probes.put(key, rec)
    return rec


def head_oid(ctx: OracleCtx) -> str:
    """The kernel checkout's HEAD: what a working-tree probe actually reads."""
    return commit_oid(ctx.materializer.git, 'HEAD') or 'unknown'


def write_candidate(ctx: OracleCtx, cve: str, rule_text: str) -> tuple[str, str]:
    """Content-addressed candidate file: same bytes = same path, never rewritten.

    Everything downstream memoizes by path (ResultCache rule hashes included),
    so a path's bytes must be immutable.
    """
    sha = rule_sha(rule_text)
    path = os.path.join(ctx.rules_dir, f'{sha[:16]}-{cve}.cocci')
    if not os.path.exists(path):
        tmp = f'{path}.tmp{os.getpid()}'
        with open(tmp, 'w') as fh:
            fh.write(rule_text)
        os.replace(tmp, path)
    return path, sha


_STAR_RE = re.compile(r'^\*\s*(.*)$', re.MULTILINE)
_VIRTUAL_RE = re.compile(r'^virtual\s', re.MULTILINE)
# `exists` as a rule-header keyword (`@r exists@`), not `when exists` on an ellipsis.
_HEADER_EXISTS_RE = re.compile(r'^@[^@\n]*\bexists\s*@', re.MULTILINE)


def structure_failures(rule_text: str, cve: str | None = None) -> list[str]:
    """T0: what test_00_metadata and validate-rule.sh assert before spatch runs.

    The cvehound rule contract: Files:, Fix:, exactly one of Fixes:/Detect-To:,
    at least one column-0 `*`, no script rules, no `virtual` declaration (the
    tool defines none, so anything gated on one never runs), no `exists` in a
    rule header (a starred rule is already in exists mode), and no other CVE's
    id anywhere in the text.
    """
    failures = []
    header = []
    for line in rule_text.splitlines():
        if not line.startswith('///'):
            break
        header.append(line)
    header_text = '\n'.join(header)
    if not re.search(r'Files:\s*\S', header_text):
        failures.append('no Files: path in the /// header')
    if not re.search(r'/// Fix:\s*\S', header_text):
        failures.append('no Fix: commit in the /// header')
    has_fixes = re.search(r'/// Fixes:\s*\S', header_text)
    has_detect_to = re.search(r'/// Detect-To:\s*\S', header_text)
    if has_fixes and has_detect_to:
        failures.append('both Fixes: and Detect-To: set')
    elif not has_fixes and not has_detect_to:
        failures.append('no Fixes: or Detect-To: commit in the /// header')
    if 'script:python' in rule_text:
        failures.append('script:python is not allowed')
    if _VIRTUAL_RE.search(rule_text):
        failures.append('declares a virtual rule: cvehound defines none, so it can never run')
    if _HEADER_EXISTS_RE.search(rule_text):
        failures.append(
            '`exists` in a rule header is a no-op (a starred rule already matches on some path); '
            'drop it, or write `... when forall` on the ellipsis that must hold on every path'
        )
    if cve:
        foreign = sorted({m for m in CVE_ID_RE.findall(rule_text) if m != cve})
        if foreign:
            failures.append(f'names another CVE: {" ".join(foreign)}')
    stars = _STAR_RE.findall(rule_text)
    if not stars:
        failures.append('nothing is starred: the rule can never report')
    # A starred lone brace is only a problem when it is orphaned. When another
    # starred line is a statement head ending in '{', the '}' is that block's
    # paired close and legitimately starred -- validate-rule.sh warns rather
    # than fails on it, and the corpus relies on it.
    lone_braces = [p for p in stars if p.strip() in ('{', '}')]
    paired_head = any(p.rstrip().endswith('{') and p.strip() != '{' for p in stars)
    if lone_braces and not paired_head:
        failures.append(
            'a starred lone brace with no paired statement head: spatch drops it silently'
        )
    return failures


def parse_and_query(ctx: OracleCtx, rule_path: str, sha: str) -> tuple[bool, str | None, str]:
    """T1: does the rule parse, and which grep query did spatch infer for it?

    (parsed, query text or None, stderr). Memoized per (rule bytes, spatch
    build): the same rule text re-scored by a later run or a rescore never pays
    for another `spatch --parse-cocci`.
    """
    fields = ('parse', 'query', 'stderr')
    rec = probe_memo(
        ctx,
        f'parse|{sha}|{ctx.spatch_id}|{PARSE_EPOCH}',
        lambda: dict(zip(fields, _parse_and_query(ctx, rule_path), strict=True)),
    )
    query = rec['query']
    return bool(rec['parse']), (str(query) if query else None), str(rec['stderr'])


def _parse_and_query(ctx: OracleCtx, rule_path: str) -> tuple[bool, str | None, str]:
    try:
        proc = subprocess.run(
            [ctx.hound.spatch, '--parse-cocci', rule_path],
            capture_output=True,
            text=True,
            errors='replace',
            env=_spatch_env(),
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # A rule whose --parse-cocci hangs must earn a verdict, not crash the
        # scoring batch (Pool.map rethrows in the parent, losing every sibling
        # Score). It scores exactly like any other unparsable rule.
        return False, None, 'parse-cocci timed out'
    if proc.returncode != 0:
        return False, None, proc.stderr.strip()[:2000]
    return True, _grep_query(proc.stdout), ''


def _grep_query(parse_output: str) -> str | None:
    lines = parse_output.splitlines()
    for pos, line in enumerate(lines):
        if 'grep query' in line.lower():
            value = lines[pos + 1].strip() if pos + 1 < len(lines) else ''
            return None if value.lower() in ('', 'none') else value
    return None


DETAIL_MAX = 240


def _detail(err: Exception) -> str:
    """The one line a Leg keeps about why its check gave no answer."""
    if isinstance(err, SpatchTimeout):
        text = f'wall {err.timeout}s' if err.wall else f'{err.timeout} CPU-s'
        text += f' on {", ".join(err.files)}' if err.files else ''
    elif isinstance(err, SpatchTruncated):
        text = f'dropped {", ".join(err.files) or "unnamed files"}: '
        text += ', '.join(err.kinds) or 'no exception named'
        text += ' (after one retry)' if err.retried else ''
    elif isinstance(err, SpatchError):
        lines = [line.strip() for line in err.stderr.splitlines() if line.strip()]
        text = f'rc {err.returncode}' + (f': {lines[-1]}' if lines else '')
    elif isinstance(err, UnsupportedVersion):
        text = f'needs spatch >= {err.rule_version}'
    else:
        text = repr(err)
    return text[:DETAIL_MAX]


def judge(name: str, expect: str, check: Callable[[], str], cve: str = '') -> Leg:
    """Run one check and turn it into a timed Leg.

    The single place engine failures become verdicts: a timeout, a truncated
    scan or a spatch error is its own verdict and is never scored as silence.
    SpatchTimeout and SpatchTruncated subclass SpatchError, so they come first.
    """
    leg = Leg(name=name, expect=expect)
    started = time.monotonic()
    try:
        leg.verdict = check()
    except SpatchTimeout as err:
        leg.verdict, leg.detail = TIMEOUT, _detail(err)
    except SpatchTruncated as err:
        leg.verdict, leg.detail = TRUNCATED, _detail(err)
    except SpatchError as err:
        leg.verdict, leg.detail = ERROR, _detail(err)
    except UnsupportedVersion as err:
        leg.verdict, leg.detail = UNSUPPORTED, _detail(err)
    leg.seconds = round(time.monotonic() - started, 3)
    if leg.verdict in HARD_VERDICTS:
        diag.warning('%s %s: %s (%s)', cve or '-', name, leg.verdict, leg.detail)
    return leg


def check_leg(ctx: OracleCtx, cve: str, name: str, sig: Sig, expect: str) -> Leg:
    def check() -> str:
        if not sig_has_rule_files(sig):
            return NO_FILES
        return FIRE if cached_check(ctx.hound, ctx.materializer, ctx.cache, sig, cve) else SILENT

    return judge(name, expect, check, cve)


_FILES_MATCH_RE = re.compile(r'(\d+) files? match')


def _files_match(stderr: str) -> int | None:
    if 'no inferred keywords' in stderr:
        return None
    match = _FILES_MATCH_RE.search(stderr)
    return int(match.group(1)) if match else None


def _spatch_cmd(
    ctx: OracleCtx,
    rule_path: str,
    target: str,
    jobs: int = 1,
    timeout: int | None = None,
    tmp_dir: str | None = None,
) -> list[str]:
    """The one directory-scan invocation both probes share (cvehound's flags).

    Not --very-quiet: it hides the 'no inferred keywords' marker (pr2, unlike
    the eprintf'd 'N files match') that both probes read off stderr.
    """
    # No -D: the rules declare no virtual rule, and spatch rejects `-D detect`
    # outright ("virtual rule detect not supported") when nothing declares it.
    cmd = [
        ctx.hound.spatch,
        '--no-includes',
        '--include-headers',
        '--chunksize',
        '1',
        '-j',
        str(jobs),
    ]
    if timeout is not None:
        cmd += ['--timeout', str(timeout)]
    if tmp_dir is not None:
        cmd += ['--tmp-dir', tmp_dir]
    return cmd + ['--cocci-file', rule_path, target]


def _spawn_spatch(cmd: list[str], tree: str) -> subprocess.Popen:
    """A directory scan in its own process group, so killpg takes its workers too,
    under the worker's address-space cap; stdout dropped, stderr streamed back."""
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        errors='replace',
        start_new_session=True,
        preexec_fn=limit_address_space,  # noqa: PLW1509 — a setrlimit is fork-safe
        env=_spatch_env(tree),
    )


def selectivity_probe(
    ctx: OracleCtx, rule_path: str, rule_files: list[str], sha: str
) -> int | None:
    """T4, memoized per (rule bytes, kernel HEAD). See _selectivity_probe."""
    rec = probe_memo(
        ctx,
        f't4|{sha}|{head_oid(ctx)}|{SELECTIVITY_EPOCH}',
        lambda: {'unrelated_files': _selectivity_probe(ctx, rule_path, rule_files)},
    )
    return rec['unrelated_files']


def _selectivity_probe(ctx: OracleCtx, rule_path: str, rule_files: list[str]) -> int | None:
    """T4: how many unrelated lib/ files survive the rule's grep query.

    Streams spatch's stderr and kills the scan at the first 'N files match' or
    'no inferred keywords' line — the probe wants the prefilter's answer, not
    the scan. Returns unrelated survivor count; None means no usable answer:
    no query at all (the whole tree would be parsed), spatch died before
    printing either marker, or the wall expired.
    """
    lib = os.path.join(ctx.kernel, SELECTIVITY_DIR)
    proc = _spawn_spatch(_spatch_cmd(ctx, rule_path, lib), ctx.kernel)
    # The stderr iteration blocks between lines, so the wall must live outside
    # the reading thread: a timer kills the process group, which ends the
    # stream and falls through to the unanswered-probe verdict below.
    verdict: int | None = None
    watchdog = threading.Timer(SELECTIVITY_WALL, killpg, args=(proc.pid,))
    watchdog.start()
    try:
        assert proc.stderr is not None
        for line in proc.stderr:
            if 'no inferred keywords' in line:
                break
            matched = _files_match(line)
            if matched is not None:
                own = sum(f.startswith(SELECTIVITY_DIR + '/') for f in rule_files)
                verdict = max(0, matched - own)
                break
    finally:
        watchdog.cancel()
        killpg(proc.pid)
        proc.wait()
    return verdict


def core_specs(
    fix: str, fixes: str | None, initial_epoch: bool, resolvable: Callable[[str], bool]
) -> list[tuple[str, str, str]]:
    """(ref, leg name, expectation) for the legs acceptance is decided on.

    The suite's test_03/test_04 pairs, plus test_02's negative half: a bug
    introduced after the start of git history must not be reported there. An
    initial-epoch CVE has no `fixes~` and no such silence — the initial commit
    *is* its vulnerable state, already covered by the `fixes` leg.
    """
    specs = [(f'{fix}~', 'fix~', FIRE), (fix, 'fix', SILENT)]
    if fixes and resolvable(fixes):
        specs.append((fixes, 'fixes', FIRE))
        if not initial_epoch:
            specs.append((f'{fixes}~', 'fixes~', SILENT))
    if not initial_epoch and resolvable(INITIAL_COMMIT):
        specs.append((INITIAL_COMMIT, 'init', SILENT))
    return specs


def range_refs(
    ctx: OracleCtx, fix: str, fixes: str, files: list[str] | None = None, mode: str = 'tags'
) -> list[str]:
    """Refs spanning the vulnerable range, oldest first — the suite's two --between-mode.

    'tags': tagged kernels (rc included) between the introducing and the fixing
    commit. 'commits': every non-merge commit touching the rule's files along the
    ancestry path, which is what `pytest --between-mode=commits` walks.
    """
    if mode not in RANGE_MODES:
        raise ValueError(f'range mode must be one of {RANGE_MODES}, got {mode!r}')
    git = ctx.repo.git
    if mode == 'commits':
        out = git.log(
            '--format=%H',
            '--no-merges',
            '--ancestry-path',
            f'{fixes}..{fix}~',
            '--',
            *(files or []),
        )
        # git log is newest first; the sweep reads oldest first like the tag list.
        return out.split()[::-1]
    return git.tag(
        '--contains', fixes, '--merged', f'{fix}~', '-l', 'v*', '--sort=creatordate'
    ).split()


def range_points(
    ctx: OracleCtx,
    refs: list[str],
    files: list[str],
    exclude: set[Sig],
    max_points: int = RANGE_MAX_POINTS,
) -> list[tuple[str, Sig]]:
    """Distinct blob signatures along the range, deduped, evenly subsampled.

    Deterministic: the same refs give the same points, so cached verdicts are
    reused across runs. Signatures already checked as fix~/fixes drop out.
    `max_points <= 0` keeps every distinct signature (the suite's own coverage).
    """
    points: list[tuple[str, Sig]] = []
    seen: set[Sig] = set(exclude)
    for ref in refs:
        sig = ctx.materializer.sig(ref, files)
        if sig in seen or not sig_has_rule_files(sig):
            continue
        seen.add(sig)
        points.append((ref, sig))
    if max_points <= 0 or len(points) <= max_points:
        return points
    step = len(points) / max_points
    return [points[int(i * step)] for i in range(max_points)]


def range_sweep(
    ctx: OracleCtx,
    cve: str,
    fix: str,
    fixes: str,
    files: list[str],
    exclude: set[Sig],
    max_points: int = RANGE_MAX_POINTS,
    mode: str = 'tags',
) -> list[Leg]:
    """T5: the rule must fire at every distinct state of its files in Fixes..Fix~."""
    refs = range_refs(ctx, fix, fixes, files, mode)
    return [
        check_leg(ctx, cve, f'{LEG_RANGE}:{ref}', sig, FIRE)
        for ref, sig in range_points(ctx, refs, files, exclude, max_points)
    ]


def backport_specs(
    backports: tuple[tuple[str, str], ...], resolvable: Callable[[str], bool]
) -> list[tuple[str, str, str]]:
    """(ref, leg name, expectation) for T3: each stable branch at its backport.

    `B~` is the branch just before the fix landed there (the rule must fire:
    that is the vulnerable stable kernel cvehound exists to flag) and `B` is
    the branch with the fix (silent). The name carries the commit so the row
    records exactly which backport answered.
    """
    specs = []
    for branch, commit in backports:
        if not commit or not resolvable(commit) or not resolvable(f'{commit}~'):
            continue
        specs.append((f'{commit}~', f'{LEG_BP_PRE}:{branch}@{commit}', FIRE))
        specs.append((commit, f'{LEG_BP}:{branch}@{commit}', SILENT))
    return specs


VALID_FLOOR = 0.75  # every valid rule scores at least this; no invalid rule reaches it
TEXT_TERMS = ('anchored', 'specific_star')
POST_ACCEPTANCE = ('selective', 'era', 'tree')
ACCEPT_TERMS = tuple(term for term in WEIGHTS if term not in POST_ACCEPTANCE)
QUALITY_TERMS = TEXT_TERMS + POST_ACCEPTANCE
# A silence counts once the fire that gives it meaning has landed.
NEEDS_FIRE = {'fix': 'fix~', 'init': 'fix~', 'fixes~': 'fixes'}


@dataclass
class Grade:
    earned: dict[str, float]
    available: dict[str, float]
    valid: bool
    hard_zero: str | None = None  # TIMEOUT/ERROR/UNSUPPORTED on an acceptance leg

    def share(self, terms: tuple[str, ...]) -> float:
        """Earned over available across the named terms that were available; 1 when none was."""
        available = sum(self.available[t] for t in terms if t in self.available)
        if not available:
            return 1.0
        return sum(self.earned.get(t, 0.0) for t in terms) / available

    @property
    def reward(self) -> float:
        """Two bands, so `valid` is a floor no invalid rule can reach: an invalid
        rule scores its share of the acceptance terms (format, text, legs) below
        VALID_FLOOR, a valid one its share of the quality terms (text, T4/T5/T6
        when they ran) above it. One ratio over everything would let an invalid
        rule outscore a valid one, because the post-acceptance tiers run only on
        valid rules and so only a valid rule is ever charged for them."""
        if self.hard_zero:
            return 0.0
        if not self.valid:
            return round(VALID_FLOOR * self.share(ACCEPT_TERMS), 4)
        return round(VALID_FLOOR + (1 - VALID_FLOOR) * self.share(QUALITY_TERMS), 4)


def grade(score: Score) -> Grade:
    """Reward and acceptance from what ran. Pure: no spatch, no git.

    Reads the tiers the Score already records (T0 failures and text terms, T1
    parse and grep query, the legs, T4/T5/T6 when they ran). Terms a CVE or a
    run cannot have (no fixes~ for an initial-epoch bug, no backport on a
    branch, a tier that did not run) are simply absent and the total
    renormalizes over what ran. A vacuous silence -- no rule files at a ref
    that had to be silent -- earns nothing and costs nothing; no files at a
    ref that had to fire is a miss like any other.

    A silence is evidence only next to the fire that gives it meaning: `fix`,
    `init` and the decoys earn once `fix~` fired, `fixes~` once `fixes` did,
    and a backport branch earns as a pair. Otherwise a rule matching nothing
    would collect every silence and outscore an over-broad one. Range and
    tree legs shape the reward when present but never decide `valid`; head
    legs are ignored entirely. The reward is two bands (Grade.reward).
    """
    available = {'structure': WEIGHTS['structure'], 'parse': WEIGHTS['parse']}
    earned: dict[str, float] = {}
    if score.t0_failures:
        return Grade(earned, available, False)
    earned['structure'] = WEIGHTS['structure']
    available['grep_query'] = WEIGHTS['grep_query']
    if not score.t1_parse:
        return Grade(earned, available, False)
    earned['parse'] = WEIGHTS['parse']
    if score.t1_grep_query:
        earned['grep_query'] = WEIGHTS['grep_query']
    # What the text says about the bug, graded only when it was read (a Score
    # without the text terms gets no such term).
    if score.t0_anchored is not None:
        available['anchored'] = WEIGHTS['anchored']
        available['specific_star'] = WEIGHTS['specific_star']
        if score.t0_anchored:
            earned['anchored'] = WEIGHTS['anchored']
        if not score.t0_wildcards:
            earned['specific_star'] = WEIGHTS['specific_star']

    judged = [leg for leg in score.legs if leg.kind in ACCEPTANCE_KINDS]
    hard = next((leg.verdict for leg in judged if leg.verdict in HARD_VERDICTS), None)
    if hard:
        # A rule that breaks the engine earns nothing, whatever else held.
        return Grade({}, available, False, hard)
    graded = [leg for leg in judged if not (leg.verdict == NO_FILES and leg.expect == SILENT)]
    core = [leg for leg in graded if leg.kind == LEG_CORE]
    fired = {leg.name for leg in core if leg.expect == FIRE and leg.ok}
    for leg in core:
        available[leg.name] = WEIGHTS[leg.name]
        prerequisite = NEEDS_FIRE.get(leg.name)
        if leg.ok and (prerequisite is None or prerequisite in fired):
            earned[leg.name] = WEIGHTS[leg.name]

    def earn(family: str, fraction: float) -> None:
        # `earned` lists what was earned, so nothing at zero.
        if fraction > 0:
            earned[family] = WEIGHTS[family] * fraction

    # Each branch is one question -- vulnerable just before the backport, fixed
    # at it -- so it earns as a pair; a vacuous silence at the backport (files
    # gone there) is ok, no files before it is a miss (Leg.ok).
    pairs: dict[str, list[bool]] = {}
    for leg in judged:
        if leg.kind in (LEG_BP_PRE, LEG_BP):
            pairs.setdefault(branch_of_ref(leg.ref), []).append(leg.ok)
    if pairs:
        available['backports'] = WEIGHTS['backports']
        earn('backports', sum(all(oks) for oks in pairs.values()) / len(pairs))
    # Decoys are part of acceptance, not just shaping: a rule that fires on
    # foreign code served at its own paths is degenerate however well the
    # fix~/fix pair behaves.
    decoys = [leg for leg in graded if leg.kind == LEG_DECOY]
    if decoys:
        available['decoys'] = WEIGHTS['decoys']
        if 'fix~' in fired:
            earn('decoys', sum(leg.ok for leg in decoys) / len(decoys))
    valid = bool(core) and all(leg.ok for leg in graded)

    # Beyond acceptance, when the tier ran (on valid rules): shaping only.
    if score.t4_unrelated_files is not None:
        available['selective'] = WEIGHTS['selective']
        if score.t4_unrelated_files == 0:
            earned['selective'] = WEIGHTS['selective']
    for family, kind in (('era', LEG_RANGE), ('tree', LEG_TREE)):
        legs = score.legs_of(kind)
        if legs:
            available[family] = WEIGHTS[family]
            earn(family, sum(leg.ok for leg in legs) / len(legs))
    return Grade(earned, available, valid)


def prefilter_sig(ctx: OracleCtx, commit: str, words: list[str]) -> Sig:
    """Which files spatch would parse at `commit` for a rule with these query
    words -- the T6/head verdict key -- memoized: a `git grep` over a kernel
    tree costs seconds and the answer is a function of (commit, words)."""
    words_id = hashlib.sha256(' '.join(words).encode()).hexdigest()[:16]
    rec = probe_memo(
        ctx,
        f'prefilter|{commit}|{words_id}|{PREFILTER_EPOCH}',
        lambda: {
            'sig': prefilter.tree_sig(
                ctx.materializer.git,
                commit,
                prefilter.matching_files(ctx.repo.git, commit, words),
            )
        },
    )
    return tuple((path, oid) for path, oid in rec['sig'])


def prefilter_scan(
    ctx: OracleCtx, cve: str, name: str, commit: str, expect: str, words: list[str], jobs: int = 1
) -> Leg:
    """A whole-tree scan at any commit, over the files spatch would parse there.

    T6 at a backport and the informational head scans both come through here:
    `git grep` applies the rule's own grep query to the commit, the matching
    blobs are linked into the commit's directory in the store, and cvehound's
    all_files check runs over that. Verdict-identical to scanning a checkout
    (rulegen.oracle.prefilter), memoized under the prefilter signature. A
    heavy-scan slot is taken only when spatch actually has to run.
    """

    def check() -> str:
        sig = prefilter_sig(ctx, commit, words)
        if not sig_has_rule_files(sig):
            return NO_FILES  # nothing at this commit can match: silence
        if ctx.cache is not None:
            hit = ctx.cache.get(ctx.cache.key(ctx.hound.get_rule(cve), sig))
            if hit is not None:
                return FIRE if hit else SILENT
        with ctx.heavy.acquire():
            fired = cached_all_files_check(
                ctx.hound,
                lambda: hound_at(
                    ctx.hound,
                    prefilter.link_into_commit_dir(ctx.materializer, ctx.store_root, commit, sig),
                ),
                ctx.cache,
                sig,
                cve,
                jobs,
            )
        return FIRE if fired else SILENT

    return judge(name, expect, check, cve)


def scan_refs(
    ctx: OracleCtx,
    cve: str,
    kind: str,
    refs: list[tuple[str, str | None]],
    words: list[str],
    jobs: int,
) -> list[Leg]:
    """One silent-expected prefilter scan per (label, commit), named '<kind>:<label>@<commit>'."""
    return [
        prefilter_scan(ctx, cve, f'{kind}:{label}@{commit}', commit, SILENT, words, jobs)
        for label, commit in refs
        if commit and ctx.ref_resolvable(commit)
    ]


def cost_probe(
    ctx: OracleCtx, rule_path: str, sha: str, jobs: int = 1, wall: int = COST_WALL
) -> dict:
    """One whole-tree scan at COST_REF: CPU seconds, wall, prefilter survivors.

    The deployment cost of a rule as a first-class metric: how many files the
    grep query lets through, and how much engine time a scan of one tree costs.
    Memoized per (rule sha, tree) in the probe store; a complete scan answers
    for any job count, a truncated one only for its own.

    `timed_out` covers both the wall and spatch's own per-file --timeout (which
    drops the file and exits 0); a truncated scan records cpu_seconds=None so
    downstream `is not None` filters exclude it instead of under-counting.
    """
    tree_oid = ctx.materializer.whole_tree_sig(COST_REF)[0][1]

    # A truncated scan's cost depends on how many threads got cut off, so it
    # only answers for the job count it was measured with.
    # A scan that dropped files measured less than the rule costs and is never reused.
    def accept(rec: dict) -> bool:
        return not rec.get('truncated') and (not rec.get('timed_out') or rec.get('jobs') == jobs)

    return probe_memo(
        ctx,
        f'{sha}|{tree_oid}|{COST_EPOCH}',
        lambda: _cost_scan(ctx, rule_path, jobs, wall),
        accept,
    )


def _cost_scan(ctx: OracleCtx, rule_path: str, jobs: int, wall: int) -> dict:
    """One whole-tree scan at COST_REF, uncached."""
    import resource

    tree = ctx.worktree(COST_REF)
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    # spatch -j>1 stages its per-thread files at '<--tmp-dir>_<rule>_<date>_<pid>'
    # (a prefix, not a parent; relative to cwd by default), and a killed scan
    # never removes them: point the prefix inside a directory we own and clean.
    with tempfile.TemporaryDirectory(
        prefix='cost-', dir=ctx.work_root, ignore_cleanup_errors=True
    ) as tmp_dir:
        cmd = _spatch_cmd(
            ctx,
            rule_path,
            tree,
            jobs=jobs,
            timeout=SPATCH_TIMEOUT,
            tmp_dir=os.path.join(tmp_dir, 'par'),
        )
        proc = _spawn_spatch(cmd, tree)
        timed_out = False
        try:
            _out, err = proc.communicate(timeout=wall)
        except subprocess.TimeoutExpired:
            timed_out = True
            killpg(proc.pid)
            _out, err = proc.communicate()
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    err = err or ''
    # A per-file --timeout drops the file, prints an EXN line and exits 0: the
    # scan is still truncated.
    if parse_spatch_timeout(err, proc.returncode) is not None:
        timed_out = True
    # Any other dropped file takes the same shape and under-counts the same way.
    # A build that ends every scan with SPATCH-SUMMARY says so itself, counts
    # the unreadable files no EXN line names, and a missing summary means the
    # scan did not finish.
    if 'summary' in getattr(ctx.hound, 'features', ()) and proc.returncode == 0:
        counts = parse_spatch_summary(err)
        truncated = counts is None or bool(
            counts.get('dropped', 0) - counts.get('timeouts', 0) > 0 or counts.get('unreadable')
        )
    else:
        truncated = proc.returncode == 0 and parse_spatch_truncation(err) is not None
    cpu = round((after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime), 3)
    return {
        'jobs': jobs,
        'prefilter_files': _files_match(err),
        'cpu_seconds': None if (timed_out or truncated) else cpu,
        'wall_seconds': round(time.monotonic() - started, 3),
        'timed_out': timed_out,
        'truncated': truncated,
        'returncode': proc.returncode,
    }


def score_rule(ctx: OracleCtx, req: ScoreRequest, opts: OracleOptions | None = None) -> Score:
    opts = opts or OracleOptions()
    started = time.monotonic()
    cve = req.cve
    rule_path, sha = write_candidate(ctx, cve, req.rule_text)
    score = Score(cve=cve, rule_sha=sha, rule_path=rule_path)

    def finish(fail_class: str) -> Score:
        g = grade(score)
        score.fail_class = g.hard_zero or fail_class
        score.valid = g.valid
        score.reward = g.reward
        score.truncated_legs = sum(1 for leg in score.legs if leg.verdict == TRUNCATED)
        score.wall_seconds = round(time.monotonic() - started, 3)
        return score

    # T0: the contract, and what the text says about the bug (graded once it parses).
    score.t0_failures = structure_failures(req.rule_text, cve)
    score.t0_anchored, score.t0_wildcards = tiers.text_terms(req.rule_text)
    if score.t0_failures:
        return finish('structure')

    # T1
    parse_ok, query, parse_err = parse_and_query(ctx, rule_path, sha)
    score.t1_parse, score.t1_grep_query = parse_ok, query is not None
    if not parse_ok:
        log.debug('%s: parse failed: %s', cve, parse_err)
        score.t1_stderr = parse_err
        return finish('parse')

    ctx.hound.add_rule(cve, rule_path)
    files = ctx.hound.get_rule_files(cve)

    if not ctx.ref_resolvable(req.fix):
        # A fix hash the local clone lacks (stale checkout, bad metadata) is a
        # harness-side failure: sig() would raise and crash the whole scoring
        # batch. Surface it as an engine-error Score instead.
        log.warning('%s: unresolvable fix commit %s', cve, req.fix)
        score.fail_class, score.note = ERROR, f'unresolvable fix commit {req.fix}'
        score.wall_seconds = round(time.monotonic() - started, 3)
        return score
    if not req.fixes or not ctx.ref_resolvable(req.fixes):
        # Without an introducing commit there is no fixes/fixes~ pair and no
        # range to sweep: the rule would be judged only at the fix and at
        # backports, and the suite rejects it regardless. Refuse rather than
        # score a weaker question under the same name.
        log.warning('%s: no resolvable introducing commit (%s)', cve, req.fixes)
        return Score.unscored(cve, req.rule_text, 'harness', 'no introducing commit')

    # T2 (the core pairs), T3 (each stable branch at its backport) and the
    # decoys. A timeout or an error on any of them is a hard zero.
    core = core_specs(req.fix, req.fixes, req.initial_epoch, ctx.ref_resolvable)
    for name, sig, expect in _acceptance_legs(ctx, core, req.backports, files, opts.run_decoys):
        leg = check_leg(ctx, cve, name, sig, expect)
        score.legs.append(leg)
        if leg.verdict in HARD_VERDICTS:
            return finish(leg.verdict)

    score.valid = grade(score).valid
    if score.valid:
        checked = {ctx.materializer.sig(ref, files) for ref, _name, _expect in core}
        score.strong_valid = _strong_tiers(ctx, score, req, opts, files, checked, query)
    # Graded afresh: the tiers that just ran shape the reward (never `valid`).
    return finish('none')


def _acceptance_legs(
    ctx: OracleCtx,
    core: list[tuple[str, str, str]],
    backports: tuple[tuple[str, str], ...],
    files: list[str],
    decoys: bool,
) -> Iterator[tuple[str, Sig, str]]:
    """(leg name, signature, expectation) for every leg acceptance is decided on,
    in order; each signature is computed only once its leg is next to run."""
    for ref, name, expect in core:
        yield name, ctx.materializer.sig(ref, files), expect
    for ref, name, expect in backport_specs(backports, ctx.ref_resolvable):
        yield name, ctx.materializer.sig(ref, files), expect
    if decoys:
        # Unrelated code at the rule's own paths must stay silent.
        for source, sig in antigaming.decoy_sigs(ctx.decoy_blobs, files):
            yield f'{LEG_DECOY}:{source}', sig, SILENT


def _fired(legs: list[Leg]) -> int:
    return sum(1 for leg in legs if leg.verdict == FIRE)


def _strong_tiers(
    ctx: OracleCtx,
    score: Score,
    req: ScoreRequest,
    opts: OracleOptions,
    files: list[str],
    checked: set[Sig],
    query: str | None,
) -> bool:
    """Beyond acceptance, for a rule that passed it: whether it is strong-valid.

    T4 prefilter selectivity, the T5 range sweep, T6 whole-tree scans at the
    backports, the informational head scans and the cost probe. Each records
    its columns and legs on `score`; they shape the final grade, never `valid`.
    `checked` holds the signatures the core legs already judged.
    """
    rule_path, sha = score.rule_path, score.rule_sha
    strong = True
    # T4 (slow: a spatch over lib/ per rule). An unanswered probe (None) is not a pass.
    if opts.run_selectivity:
        score.t4_unrelated_files = selectivity_probe(ctx, rule_path, files, sha)
        strong = score.t4_unrelated_files == 0
    words = prefilter.query_words(query) if query else []
    try:
        if opts.run_range:
            legs = range_sweep(
                ctx,
                req.cve,
                req.fix,
                req.fixes,
                files,
                checked,
                opts.range_max_points,
                opts.range_mode,
            )
            score.legs.extend(legs)
            score.t5_mode, score.t5_points, score.t5_fired = (
                opts.range_mode,
                len(legs),
                _fired(legs),
            )
            strong = strong and all(leg.ok for leg in legs)
        if opts.run_tree:
            # T6 at every backport the rule was judged on. A rule spatch has no
            # grep query for would parse the whole tree everywhere: it is not
            # strong, whatever the scan would say, and the scan is not run.
            legs = (
                scan_refs(ctx, req.cve, LEG_TREE, list(req.backports), words, opts.tree_jobs)
                if words
                else []
            )
            strong = strong and bool(words) and all(leg.ok for leg in legs)
            score.legs.extend(legs)
            score.t6_trees, score.t6_fired = len(legs), _fired(legs)
        if opts.run_heads and words:
            # Informational: what the rule reports on today's trees. Recorded,
            # never graded (Leg.gating is False for head legs).
            heads = [(ref, ctx.resolve(ref)) for ref in ctx.branches]
            legs = scan_refs(ctx, req.cve, LEG_HEAD, heads, words, opts.tree_jobs)
            score.legs.extend(legs)
            score.head_checked, score.head_fires = len(legs), _fired(legs)
        if opts.run_cost:
            with ctx.heavy.acquire():
                cost = cost_probe(ctx, rule_path, sha, jobs=opts.tree_jobs)
            score.cost_prefilter_files = cost['prefilter_files']
            score.cost_cpu_seconds = cost['cpu_seconds']
            score.cost_wall_seconds = cost['wall_seconds']
    except Exception as err:  # noqa: BLE001 — acceptance is already decided
        # A git/worktree/memo failure here is the harness's, not the rule's:
        # keep the reward and legs already earned, just withhold strong_valid
        # and say why in its own column (t1_stderr is T1's, and repair feedback).
        log.warning('%s: post-acceptance tier crashed: %r', req.cve, err)
        score.strong_error = f'{err!r}'[:2000]
        return False
    return strong
