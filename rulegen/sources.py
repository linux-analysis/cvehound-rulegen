"""Every CVE metadata source side by side, and the agreement rule between them.

cvehound's packaged `kernel_cves.json.gz` carries one fix commit, one
introducing commit and a rejected flag per CVE -- what the tool needs. The
bench needs more: which source said what, whether they agree, and on which
stable branches the fix landed. Those live only in the raw clones
(kernel.org vulns.git and CIP kernel-sec, both under ~/.cache/cvehound), so
this module reads them directly and writes `data/cvemeta.parquet`.

Nothing here resolves a disagreement. A CVE whose sources name different
commits, or several fixes, or an introducing commit that is not an ancestor of
the fix, is reported under an issue code and excluded from generation; the
rule header stays authoritative for gold CVEs, as the suite asserts. Every git
question is injected so the merge is testable without a clone.
"""

import glob
import json
import logging
import os
import re
import subprocess
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from cvehound.gitevidence import FIXES_TRAILER

from rulegen import tables
from rulegen.git import git, git_run
from rulegen.schema import DEFAULT_BRANCHES, INITIAL_COMMIT, INITIAL_COMMIT_HASH, CveMeta

log = logging.getLogger(__name__)

MAINLINE = 'mainline'
MAINLINE_REF = 'origin/master'

# The stable branches the oracle judges backports on: the suite's heads minus
# master and next. CIP names them 'stable/<version>'.
BACKPORT_BRANCHES = tuple(b for b in DEFAULT_BRANCHES if b.startswith('stable/'))


def cip_key(branch: str) -> str:
    """'stable/linux-6.1.y' -> 'stable/6.1' (CIP's fixed-by key)."""
    match = re.fullmatch(r'stable/linux-(\d+\.\d+)\.y', branch)
    if not match:
        raise ValueError(f'not a stable branch name: {branch!r}')
    return f'stable/{match.group(1)}'


# Issue codes. The first group gates (the CVE is excluded from generation);
# the per-branch ones only drop that branch's legs; the last are informational.
GATING = frozenset(
    {
        'rejected',
        'no-fix',
        'no-introducing',
        'multi-fix',
        'multi-introducing',
        'fix-disagree',
        'introducing-disagree',
        'trailer-disagree',
        'fix-unresolvable',
        'introducing-unresolvable',
        'not-ancestor',
    }
)
GATING_GOLD = frozenset(
    {'rejected', 'fix-unresolvable', 'introducing-unresolvable', 'not-ancestor'}
)
BRANCH_ISSUES = ('backport-disagree', 'backport-multi', 'backport-other-fix')  # '<code>:<branch>'
_SHA_RE = re.compile(r'^[0-9a-f]{40}$')
# How a stable commit names the mainline commit it carries.
_UPSTREAM_RE = re.compile(
    r'(?:commit ([0-9a-f]{12,40}) upstream|\[ Upstream commit ([0-9a-f]{12,40}) \]|'
    r'cherry picked from commit ([0-9a-f]{12,40}))',
    re.IGNORECASE,
)


def upstreams_of(message: str) -> list[str]:
    """Every mainline commit a stable commit's message cites as its upstream, in order.

    A backport message can mention other commits first ("this fixes a
    regression from commit X upstream"), so the caller matches the agreed fix
    against all of them, not the first.
    """
    return list(
        dict.fromkeys(
            next(g for g in match.groups() if g) for match in _UPSTREAM_RE.finditer(message)
        )
    )


class BranchIndex:
    """Which branch a commit belongs to, from rev-list sets built once.

    `branch_of(sha)` is 'mainline', a stable branch name, or None. `in_base(sha,
    branch)` says whether a mainline commit predates the branch point, i.e. the
    branch carries it without a backport. The mainline sets are nested (5.10's
    base is inside 5.15's, and so on), so one dict of generation levels covers
    every branch.
    """

    def __init__(
        self,
        mainline_level: dict[str, int],
        branch_sets: dict[str, frozenset[str]],
        branches: tuple[str, ...],
    ) -> None:
        self.mainline_level = mainline_level  # sha -> smallest branch index whose base holds it
        self.branch_sets = branch_sets  # branch -> its own (non-mainline) commits
        self.branches = branches  # oldest base first

    @classmethod
    def build(
        cls,
        kernel: str,
        branches: tuple[str, ...] = BACKPORT_BRANCHES,
        mainline: str = MAINLINE_REF,
    ) -> 'BranchIndex':
        def rev_list(*args: str) -> list[str]:
            return git(kernel, 'rev-list', *args).split()

        def merge_base(a: str, b: str) -> str:
            return git(kernel, 'merge-base', a, b).strip()

        def commit_date(sha: str) -> int:
            return int(git(kernel, 'log', '-1', '--format=%ct', sha).strip())

        # Oldest branch point first, so a commit's level is the first base holding it.
        bases = {b: merge_base(mainline, b) for b in branches}
        ordered = sorted(branches, key=lambda b: commit_date(bases[b]))
        level: dict[str, int] = {}
        seen: list[str] = []
        for i, branch in enumerate(ordered):
            for sha in rev_list(bases[branch], *[f'^{s}' for s in seen]):
                level.setdefault(sha, i)
            seen.append(bases[branch])
        for sha in rev_list(mainline, *[f'^{s}' for s in seen]):
            level.setdefault(sha, len(ordered))
        sets = {b: frozenset(rev_list(b, f'^{mainline}')) for b in branches}
        return cls(level, sets, tuple(ordered))

    def known(self, sha: str) -> bool:
        return sha in self.mainline_level or any(sha in s for s in self.branch_sets.values())

    def branch_of(self, sha: str) -> str | None:
        if sha in self.mainline_level:
            return MAINLINE
        for branch, shas in self.branch_sets.items():
            if sha in shas:
                return branch
        return None

    def in_base(self, sha: str, branch: str) -> bool:
        level = self.mainline_level.get(sha)
        return level is not None and level <= self.branches.index(branch)


@dataclass
class SourceView:
    """What one source says about a CVE. Shas are full and already in the clone."""

    fix: list[str] = field(default_factory=list)  # mainline fixing commits
    introduced: list[str] = field(default_factory=list)  # mainline introducing commits
    backports: dict[str, list[str]] = field(default_factory=dict)  # branch -> fixing commits there
    rejected: bool = False
    description: str = ''
    note: str = ''  # CIP's ignore.all text


def parse_vulns_record(data: dict, index: BranchIndex, rejected: bool = False) -> SourceView:
    """One vulns.git CVE JSON 5 record.

    Every branch carrying the fix is one git range: `version` is where the bug
    came from (a mainline commit, or a stable commit when the bug itself was
    backported), `lessThan` the fixing commit on that branch. Which branch a
    range describes is decided by the clone, not by source order.
    """
    cna = data.get('containers', {}).get('cna', {})
    view = SourceView(rejected=rejected)
    for item in cna.get('descriptions') or []:
        if item.get('lang', 'en').startswith('en') and item.get('value'):
            view.description = item['value']
            break
    fixes: list[str] = []
    introduced: list[str] = []
    for item in cna.get('affected', []):
        for ver in item.get('versions', []):
            if ver.get('versionType') != 'git' or not ver.get('lessThan'):
                continue
            fix, start = ver['lessThan'], ver.get('version', '')
            where = index.branch_of(fix)
            if where == MAINLINE:
                fixes.append(fix)
                if index.branch_of(start) == MAINLINE:
                    introduced.append(start)
            elif where is not None:
                view.backports.setdefault(where, []).append(fix)
    view.fix = list(dict.fromkeys(fixes))
    view.introduced = list(dict.fromkeys(introduced))
    view.backports = {b: list(dict.fromkeys(s)) for b, s in view.backports.items()}
    return view


def parse_cip_issue(
    data: dict, index: BranchIndex, branches: tuple[str, ...] = BACKPORT_BRANCHES
) -> SourceView:
    """One CIP kernel-sec issue (YAML already loaded).

    Only `mainline` and the `stable/<version>` keys of the branches the oracle
    judges are read; distro and CIP-product keys carry package versions. A
    mainline sha under a stable key means "fixed since the branch point", not a
    backport, and is left to `in_base`.
    """
    from cvehound.scripts.update_metadata import is_cip_rejected

    def shas(value: object) -> list[str]:
        items = [value] if isinstance(value, str) else list(value or [])
        return [s for s in items if isinstance(s, str) and _SHA_RE.match(s) and index.known(s)]

    fixed_by = data.get('fixed-by') or {}
    introduced_by = data.get('introduced-by') or {}
    view = SourceView(
        fix=[s for s in shas(fixed_by.get(MAINLINE)) if index.branch_of(s) == MAINLINE],
        introduced=[s for s in shas(introduced_by.get(MAINLINE)) if index.branch_of(s) == MAINLINE],
        rejected=is_cip_rejected(data),
        description=str(data.get('description') or ''),
        note=str((data.get('ignore') or {}).get('all') or ''),
    )
    for branch in branches:
        on_branch = [s for s in shas(fixed_by.get(cip_key(branch))) if index.branch_of(s) == branch]
        if on_branch:
            view.backports[branch] = on_branch
    return view


@dataclass(frozen=True)
class HeaderView:
    """A gold rule's own header: authoritative for fix and introducing commit."""

    fix: str | None
    fixes: str | None
    fixes_kind: str | None  # 'fixes' | 'detect-to'
    rule_path: str
    files: tuple[str, ...] = ()
    version: int = 0


def trailers_in(message: str) -> list[str]:
    """The `Fixes:` trailer shas of a commit message, abbreviated as written
    (cvehound's own trailer pattern, so the suite and the bench read the same lines)."""
    return list(dict.fromkeys(FIXES_TRAILER.findall(message)))


def _single(values: list[str], code: str, issues: list[str]) -> str | None:
    if len(values) > 1:
        issues.append(code)
        return None
    return values[0] if values else None


def _said(views: list[SourceView], attr: str, multi: str, issues: list[str]) -> list[str]:
    """The one commit each speaking source names; a source naming several is noted and dropped."""
    said = [_single(getattr(v, attr), multi, issues) for v in views if getattr(v, attr)]
    return [sha for sha in said if sha]


def merge(
    cve: str,
    vulns: SourceView | None,
    cip: SourceView | None,
    header: HeaderView | None,
    trailers_of: Callable[[str], list[str]],
    resolve: Callable[[str], str | None],
    is_ancestor: Callable[[str, str], bool],
    index: BranchIndex,
    branches: tuple[str, ...] = BACKPORT_BRANCHES,
    cited_upstream: Callable[[str], Sequence[str]] = lambda _sha: (),
) -> CveMeta:
    """The agreed view of one CVE, with every disagreement named.

    Fix and introducing commit: each source that speaks must name exactly one
    mainline commit, and all speaking sources must name the same one. The fix
    commit's own `Fixes:` trailers are a source for the introducing commit too
    (the suite asserts a rule's `Fixes:` is among them). A gold header wins over
    all of it, and a Detect-To: boundary is exempt from the introducing-commit
    agreement (it is a detector boundary, not the bug's origin) but not from
    ancestry: the range legs only make sense below the fix.
    """
    issues: list[str] = []
    views = [v for v in (vulns, cip) if v is not None]
    if any(v.rejected for v in views):
        issues.append('rejected')
    fix = _agree_fix(views, header, resolve, issues)
    trailers = [t for t in (resolve(x) for x in trailers_of(fix)) if t] if fix else []
    introduced, kind = _agree_introducing(views, header, trailers, resolve, is_ancestor, issues)
    initial = introduced in (INITIAL_COMMIT, INITIAL_COMMIT_HASH) or (
        introduced is not None and resolve(introduced) == INITIAL_COMMIT_HASH
    )
    if (
        fix
        and introduced
        and 'fix-unresolvable' not in issues
        and 'introducing-unresolvable' not in issues
        and not initial
        and not is_ancestor(resolve(introduced) or introduced, resolve(fix) or fix)
    ):
        issues.append('not-ancestor')
    backports = {}
    for branch in branches:
        backport = _agree_backport(
            branch, views, fix, introduced, initial, resolve, index, cited_upstream, issues
        )
        if backport:
            backports[branch] = backport

    gating = GATING_GOLD if header is not None else GATING
    return CveMeta(
        cve=cve,
        description=(vulns.description if vulns else '') or (cip.description if cip else ''),
        vulns_fix=vulns.fix if vulns else [],
        vulns_introduced=vulns.introduced if vulns else [],
        vulns_backports=vulns.backports if vulns else {},
        vulns_rejected=bool(vulns and vulns.rejected),
        cip_fix=cip.fix if cip else [],
        cip_introduced=cip.introduced if cip else [],
        cip_backports=cip.backports if cip else {},
        cip_rejected=bool(cip and cip.rejected),
        cip_note=cip.note if cip else '',
        trailer_fixes=trailers,
        header_fix=header.fix if header else None,
        header_fixes=header.fixes if header else None,
        header_fixes_kind=header.fixes_kind if header else None,
        header_files=list(header.files) if header else [],
        header_version=header.version if header else 0,
        rule_path=header.rule_path if header else None,
        fix=fix,
        introduced=introduced,
        introduced_kind=kind,
        backports=backports,
        issues=issues,
        eligible=not any(i in gating for i in issues),
    )


def _agree_fix(
    views: list[SourceView],
    header: HeaderView | None,
    resolve: Callable[[str], str | None],
    issues: list[str],
) -> str | None:
    """The fix commit: the one the sources agree on, or the gold header's."""
    said = _said(views, 'fix', 'multi-fix', issues)
    source_fix = None
    if len(set(said)) > 1:
        issues.append('fix-disagree')
    elif said:
        source_fix = said[0]
    fix = source_fix
    if header is not None:
        # The header's spelling is kept as written (the suite reads it back;
        # `Fixes: v2.6.12-rc2` stays a tag), but it must resolve in the clone.
        fix = header.fix or None
        if fix is None:
            issues.append('no-fix')
        elif resolve(fix) is None:
            issues.append('fix-unresolvable')
        elif source_fix and resolve(fix) != source_fix:
            issues.append('header-fix-disagree')
    elif fix is None:
        issues.append('no-fix')
    elif resolve(fix) is None:
        issues.append('fix-unresolvable')
    return fix


def _agree_introducing(
    views: list[SourceView],
    header: HeaderView | None,
    trailers: list[str],
    resolve: Callable[[str], str | None],
    is_ancestor: Callable[[str, str], bool],
    issues: list[str],
) -> tuple[str | None, str | None]:
    """(introducing commit, its kind): the gold header's, else the sources' agreed one,
    else the widest of the fix's `Fixes:` trailers."""
    introduced = None
    kind = None
    if header is not None:
        if header.fixes:
            introduced, kind = header.fixes, header.fixes_kind
            if resolve(introduced) is None:
                issues.append('introducing-unresolvable')
        else:
            issues.append('no-introducing')
        if introduced and kind == 'fixes':
            said = _said(views, 'introduced', 'multi-introducing', issues)
            if any(s != resolve(introduced) for s in said):
                issues.append('header-introducing-disagree')
        return introduced, kind
    said = _said(views, 'introduced', 'multi-introducing', issues)
    if len(set(said)) > 1:
        issues.append('introducing-disagree')
    elif said:
        introduced, kind = said[0], 'meta'
    elif trailers:
        introduced, kind = _widest(trailers, is_ancestor), 'trailer'
    else:
        issues.append('no-introducing')
    # What the suite's test_fixes will assert of any rule written for this CVE.
    if introduced and trailers and introduced not in trailers:
        issues.append('trailer-disagree')
    if introduced and resolve(introduced) is None:
        issues.append('introducing-unresolvable')
    return introduced, kind


def _agree_backport(
    branch: str,
    views: list[SourceView],
    fix: str | None,
    introduced: str | None,
    initial: bool,
    resolve: Callable[[str], str | None],
    index: BranchIndex,
    cited_upstream: Callable[[str], Sequence[str]],
    issues: list[str],
) -> str | None:
    """The one commit that carried the fix to `branch`, or None.

    Per branch, one of: the fix is in the branch base (nothing to judge), a
    source names the backport (a leg), the bug never reached the branch
    (nothing to judge), or the branch carries the bug unfixed (a missing
    backport: nothing to judge, worth listing).
    """
    named = [set(v.backports.get(branch, ())) for v in views if v.backports.get(branch)]
    fix_sha = (resolve(fix) or fix) if fix else None
    if fix_sha and index.in_base(fix_sha, branch):
        issues.append(f'fixed-in-base:{branch}')
        return None
    if not named:
        if (
            fix
            and introduced
            and not initial
            and not index.in_base(resolve(introduced) or introduced, branch)
        ):
            issues.append(f'not-affected:{branch}')
        elif fix:
            issues.append(f'unfixed:{branch}')
        return None
    if len(named) > 1 and any(s != named[0] for s in named[1:]):
        issues.append(f'backport-disagree:{branch}')
        return None
    shas = sorted(named[0])
    if len(shas) > 1:
        issues.append(f'backport-multi:{branch}')
        return None
    # A stable commit that says which mainline commit it carries must name
    # the agreed fix among the commits it cites: the sources sometimes list
    # a related fix on a branch (CVE-2022-0998 on 5.10 names the bounds
    # check that preceded the real fix), and judging a rule at that commit
    # asks the wrong question.
    cited = cited_upstream(shas[0])
    if cited and fix_sha and not any(fix_sha.startswith(c) for c in cited):
        issues.append(f'backport-other-fix:{branch}')
        return None
    return shas[0]


def _widest(shas: list[str], is_ancestor: Callable[[str, str], bool]) -> str:
    """Of several introducing commits, the one below all others (the widest range), else the first."""
    for sha in shas:
        if all(sha == other or is_ancestor(sha, other) for other in shas):
            return sha
    return shas[0]


# ---------------------------------------------------------------------------
# Reading the clones


def default_source_dirs() -> tuple[str, str]:
    from cvehound.scripts.update_metadata import get_cache_dir

    cache = get_cache_dir()
    return os.path.join(cache, 'kernel-vulns'), os.path.join(cache, 'cip-kernel-sec')


def load_vulns(vulns_dir: str, index: BranchIndex) -> dict[str, SourceView]:
    out: dict[str, SourceView] = {}
    for state in ('published', 'rejected'):
        for path in sorted(glob.glob(os.path.join(vulns_dir, 'cve', state, '*', 'CVE-*.json'))):
            try:
                with open(path) as fh:
                    data = json.load(fh)
            except (OSError, ValueError) as err:
                log.warning('%s: unreadable: %s', path, err)
                continue
            meta = data.get('cveMetadata', {})
            cve = meta.get('cveId') or meta.get('cveID') or os.path.basename(path)[:-5]
            if not cve.startswith('CVE-'):
                continue
            view = parse_vulns_record(data, index, rejected=(state == 'rejected'))
            # A record present in both states: the rejection is the later word.
            if cve in out and not view.rejected:
                continue
            out[cve] = view
    return out


def load_cip(cip_dir: str, index: BranchIndex) -> dict[str, SourceView]:
    import yaml

    out: dict[str, SourceView] = {}
    for path in sorted(glob.glob(os.path.join(cip_dir, 'issues', 'CVE-*.yml'))):
        try:
            with open(path) as fh:
                data = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as err:
            log.warning('%s: unreadable: %s', path, err)
            continue
        if not data:
            continue
        out[os.path.basename(path)[:-4]] = parse_cip_issue(data, index)
    return out


class GitQueries:
    """The git questions merge() asks, over the real clone, batched where the
    question set is known up front and memoized otherwise."""

    def __init__(self, kernel: str, index: BranchIndex | None = None) -> None:
        self.kernel = kernel
        self.index = index
        self._resolved: dict[str, str | None] = {}
        self._ancestry: dict[tuple[str, str], bool] = {}
        self._messages: dict[str, str] = {}

    def _git(self, *args: str, input: str | None = None) -> subprocess.CompletedProcess:
        return git_run(self.kernel, *args, input=input)

    def resolve(self, ref: str) -> str | None:
        # A full sha the branch index already holds needs no process.
        if self.index is not None and _SHA_RE.match(ref) and self.index.known(ref):
            return ref
        if ref not in self._resolved:
            out = self._git('rev-parse', '--verify', '--quiet', f'{ref}^{{commit}}')
            self._resolved[ref] = out.stdout.strip() if out.returncode == 0 else None
        return self._resolved[ref]

    def resolve_many(self, refs: Iterable[str]) -> None:
        """Warm the memo for many refs with one `cat-file --batch-check` stream."""
        wanted = sorted({r for r in refs if r and r not in self._resolved})
        if not wanted:
            return
        out = self._git(
            'cat-file', '--batch-check=%(objectname) %(objecttype)', input='\n'.join(wanted) + '\n'
        )
        for ref, line in zip(wanted, out.stdout.splitlines(), strict=False):
            parts = line.split()
            self._resolved[ref] = parts[0] if len(parts) == 2 and parts[1] == 'commit' else None

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        if ancestor == descendant:
            return True
        key = (ancestor, descendant)
        if key not in self._ancestry:
            self._ancestry[key] = (
                self._git('merge-base', '--is-ancestor', ancestor, descendant).returncode == 0
            )
        return self._ancestry[key]

    def messages(self, shas: Iterable[str]) -> None:
        """Warm the message memo for many commits with one `git log --stdin`."""
        wanted = sorted({s for s in shas if s and s not in self._messages})
        if not wanted:
            return
        out = self._git(
            'log', '--no-walk', '--stdin', '--format=%x1e%H%x1f%B', input='\n'.join(wanted) + '\n'
        )
        for record in out.stdout.split('\x1e'):
            sha, sep, body = record.partition('\x1f')
            if sep:
                self._messages[sha.strip()] = body

    def message(self, sha: str) -> str:
        if sha not in self._messages:
            out = self._git('show', '-s', '--format=%B', sha)
            self._messages[sha] = out.stdout if out.returncode == 0 else ''
        return self._messages[sha]

    def trailers_of(self, fix: str) -> list[str]:
        return trailers_in(self.message(self.resolve(fix) or fix))

    def cited_upstream(self, sha: str) -> list[str]:
        return upstreams_of(self.message(sha))

    def commit_info(self, shas: Iterable[str]) -> dict[str, tuple[int, str]]:
        """sha -> (committer date, subject), one batched git call."""
        wanted = sorted({s for s in shas if s})
        if not wanted:
            return {}
        out = self._git(
            'log',
            '--no-walk',
            '--stdin',
            '--format=%H%x00%ct%x00%s',
            input='\n'.join(wanted) + '\n',
        )
        info: dict[str, tuple[int, str]] = {}
        for line in out.stdout.splitlines():
            sha, _, rest = line.partition('\x00')
            date, _, subject = rest.partition('\x00')
            if sha and date.isdigit():
                info[sha] = (int(date), subject.strip())
        return info


def build_cvemeta(
    kernel: str,
    vulns_dir: str,
    cip_dir: str,
    rules: dict[str, HeaderView],
    branches: tuple[str, ...] = BACKPORT_BRANCHES,
) -> list[CveMeta]:
    """Every CVE either clone or the rule set knows, merged."""
    index = BranchIndex.build(kernel, branches)
    log.info('branch index: %d mainline commits, %s', len(index.mainline_level), index.branches)
    vulns = load_vulns(vulns_dir, index)
    cip = load_cip(cip_dir, index)
    log.info(
        'sources: %d vulns.git records, %d CIP issues, %d rules', len(vulns), len(cip), len(rules)
    )
    git = GitQueries(kernel, index)
    # Every fix any source names: their messages (for the Fixes: trailers) and
    # the trailers' abbreviated shas resolve in two streams, not 30k processes.
    fixes = {sha for v in (*vulns.values(), *cip.values()) for sha in v.fix}
    fixes |= {h.fix for h in rules.values() if h.fix}
    backport_shas = {
        sha
        for v in (*vulns.values(), *cip.values())
        for shas in v.backports.values()
        for sha in shas
    }
    git.resolve_many(fixes)
    git.messages([*(git.resolve(f) or f for f in fixes), *backport_shas])
    git.resolve_many(t for sha in fixes for t in git.trailers_of(sha))
    metas = [
        merge(
            cve,
            vulns.get(cve),
            cip.get(cve),
            rules.get(cve),
            git.trailers_of,
            git.resolve,
            git.is_ancestor,
            index,
            branches,
            git.cited_upstream,
        )
        for cve in sorted(set(vulns) | set(cip) | set(rules))
    ]
    info = git.commit_info(m.fix for m in metas if m.fix)
    for meta in metas:
        if meta.fix and meta.fix in info:
            meta.fix_date, meta.cmt_subject = info[meta.fix]
    return metas


# ---------------------------------------------------------------------------
# Persistence and the audit


# The merged metadata table under the data directory.
CVEMETA = 'cvemeta.parquet'


def save_cvemeta(metas: list[CveMeta], path: str) -> None:
    tables.write_rows([m.to_row() for m in metas], path)


def load_cvemeta(path: str) -> list[CveMeta]:
    return [CveMeta.from_row(row) for row in tables.read_rows(path)]


def issue_code(issue: str) -> str:
    return issue.partition(':')[0]


def audit_rows(metas: list[CveMeta], splits: dict[str, str]) -> list[dict[str, object]]:
    """One row per (cve, issue) with what each source said -- the audit parquet."""
    rows = []
    for m in metas:
        for issue in m.issues:
            rows.append(
                {
                    'cve': m.cve,
                    'split': splits.get(m.cve, ''),
                    'issue': issue,
                    'code': issue_code(issue),
                    'gating': issue in (GATING_GOLD if m.rule_path else GATING),
                    'vulns_fix': ' '.join(m.vulns_fix),
                    'cip_fix': ' '.join(m.cip_fix),
                    'header_fix': m.header_fix or '',
                    'vulns_introduced': ' '.join(m.vulns_introduced),
                    'cip_introduced': ' '.join(m.cip_introduced),
                    'trailer_fixes': ' '.join(m.trailer_fixes),
                    'header_fixes': m.header_fixes or '',
                    'vulns_backports': json.dumps(m.vulns_backports, sort_keys=True),
                    'cip_backports': json.dumps(m.cip_backports, sort_keys=True),
                    'rule_path': m.rule_path or '',
                }
            )
    return rows


# The issue codes the audit lists CVE by CVE, with what each source said.
LISTED_ISSUES = frozenset(
    {
        'fix-disagree',
        'introducing-disagree',
        'trailer-disagree',
        'multi-fix',
        'multi-introducing',
        'header-fix-disagree',
        'header-introducing-disagree',
        'not-ancestor',
        'backport-disagree',
        'backport-multi',
    }
)


def audit_markdown(
    metas: list[CveMeta], splits: dict[str, str], branches: tuple[str, ...] = BACKPORT_BRANCHES
) -> str:
    """The human-readable audit: totals, every issue with its values, backport coverage."""
    by_split: dict[str, list[CveMeta]] = {}
    for m in metas:
        by_split.setdefault(splits.get(m.cve, 'unlisted'), []).append(m)
    return tables.render_markdown(
        [
            _totals_table(by_split),
            _issues_table(by_split),
            _detail_table(metas, splits),
            _rejected_table(metas, splits),
            _coverage_table(by_split, branches),
        ]
    )


def _totals_table(by_split: dict[str, list[CveMeta]]) -> tables.Table:
    table = tables.Table(
        'CVEs by split', ['split', 'CVEs', 'eligible', 'with backport on >=1 branch']
    )
    for split, items in sorted(by_split.items()):
        table.rows.append(
            [
                split,
                len(items),
                sum(m.eligible for m in items),
                sum(bool(m.backports) for m in items),
            ]
        )
    return table


def _issues_table(by_split: dict[str, list[CveMeta]]) -> tables.Table:
    counts = {
        split: Counter(issue_code(issue) for m in items for issue in m.issues)
        for split, items in by_split.items()
    }
    split_names = sorted(by_split)
    table = tables.Table('Issues by code and split', ['code', 'gates', *split_names])
    for code in sorted(set().union(*counts.values())):
        gates = 'yes' if code in GATING else ('branch' if code in BRANCH_ISSUES else 'no')
        table.rows.append([code, gates, *[counts[s][code] for s in split_names]])
    return table


def _few(shas: list[str], keep: int = 3) -> str:
    shown = ' '.join(s[:12] for s in shas[:keep])
    return f'{shown} (+{len(shas) - keep})' if len(shas) > keep else shown


def _detail_table(metas: list[CveMeta], splits: dict[str, str]) -> tables.Table:
    table = tables.Table(
        'Disagreements and multi-commit CVEs',
        ['cve', 'split', 'issue', 'vulns.git', 'CIP', 'trailers', 'rule header'],
        note='fix values first, introducing values after "/", at most three shas each; '
        'per-branch issues list that branch only',
    )
    for m in metas:
        for issue in m.issues:
            code, _, branch = issue.partition(':')
            if code not in LISTED_ISSUES:
                continue
            split = splits.get(m.cve, '')
            if code.startswith('backport-'):
                vulns = _few(m.vulns_backports.get(branch, []))
                cip = _few(m.cip_backports.get(branch, []))
                table.rows.append([m.cve, split, issue, vulns, cip, '', ''])
                continue
            table.rows.append(
                [
                    m.cve,
                    split,
                    issue,
                    f'{_few(m.vulns_fix)} / {_few(m.vulns_introduced)}',
                    f'{_few(m.cip_fix)} / {_few(m.cip_introduced)}',
                    _few(m.trailer_fixes),
                    f'{(m.header_fix or "")[:12]} / {(m.header_fixes or "")[:12]}',
                ]
            )
    return table


def _rejected_table(metas: list[CveMeta], splits: dict[str, str]) -> tables.Table:
    table = tables.Table('Rejected CVEs', ['cve', 'split', 'vulns.git', 'CIP note', 'rule'])
    for m in metas:
        if 'rejected' in m.issues:
            table.rows.append(
                [
                    m.cve,
                    splits.get(m.cve, ''),
                    'rejected' if m.vulns_rejected else '',
                    m.cip_note[:80].replace('\n', ' ') if m.cip_rejected else '',
                    os.path.basename(m.rule_path) if m.rule_path else '',
                ]
            )
    return table


def _coverage_table(by_split: dict[str, list[CveMeta]], branches: tuple[str, ...]) -> tables.Table:
    table = tables.Table(
        'Backport coverage by branch',
        [
            'split',
            'branch',
            'backport known',
            'fixed in base',
            'not affected',
            'unfixed',
            'branch issue',
        ],
        note='"unfixed" = the branch carries the bug and no source names a backport of the fix',
    )
    for split, items in sorted(by_split.items()):
        for branch in branches:
            branch_issues = {f'{code}:{branch}' for code in BRANCH_ISSUES}
            table.rows.append(
                [
                    split,
                    branch,
                    sum(branch in m.backports for m in items),
                    sum(f'fixed-in-base:{branch}' in m.issues for m in items),
                    sum(f'not-affected:{branch}' in m.issues for m in items),
                    sum(f'unfixed:{branch}' in m.issues for m in items),
                    sum(bool(branch_issues.intersection(m.issues)) for m in items),
                ]
            )
    return table


def header_views(rules: dict[str, str]) -> dict[str, HeaderView]:
    """HeaderView per gold rule path (cve -> path), via the corpus header parser."""
    from rulegen.corpus import parse_rule_header

    out = {}
    for cve, path in rules.items():
        h = parse_rule_header(path)
        out[cve] = HeaderView(
            fix=h['fix'],
            fixes=h['fixes'],
            fixes_kind=h['fixes_kind'],
            rule_path=path,
            files=tuple(h['files']),
            version=int(h['version'] or 0),
        )
    return out
