"""Unified-diff anatomy: hunks, fix shapes, and which function a change sits in.

Pure text; no git. Used by the mechanical baseline (star the removed lines of
the enclosing function), by the new-rule stratification (fix shape × subsystem)
and by the test-overlap exclusion ((file, function) pairs a fix touches).

The `@@ ... @@ name` trailer of a `-W` hunk names the function *preceding* the
hunk, not the one containing the change, so attribution walks the hunk body
with a brace-depth counter instead.
"""

import difflib
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

from rulegen import tables
from rulegen.extract import SOURCE_SUFFIXES, files_candidates, show_diff
from rulegen.git import git

_FILE_RE = re.compile(r'^diff --git a/(\S+) b/(\S+)')
_HUNK_RE = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')
_HEAD_RE = re.compile(r'^(?:[A-Za-z_][\w\s\*,]*?[\s\*])?([A-Za-z_]\w*)\s*\(')
NOT_FUNCTIONS = frozenset(
    """
    if for while switch return else do case sizeof typeof defined goto
    EXPORT_SYMBOL EXPORT_SYMBOL_GPL MODULE_LICENSE MODULE_AUTHOR MODULE_DESCRIPTION
    module_init module_exit module_param DEFINE_MUTEX DEFINE_SPINLOCK
    static_assert BUILD_BUG_ON
    """.split()  # noqa: SIM905
)
_DECL_RE = re.compile(r'^[\w\s\*]+\s\**[A-Za-z_]\w*(\s*\[[^\]]*\])*\s*(=[^;]*)?;$')
_JUMPS = frozenset({'return', 'goto', 'break', 'continue', 'else', 'case', 'default', 'do'})
_TRIVIAL = frozenset({'break;', 'continue;', 'return;'})


@dataclass
class Hunk:
    file: str
    old_start: int
    new_start: int
    lines: list[str] = field(default_factory=list)  # with the leading ' ', '-' or '+'

    def side(self, which: str) -> list[int]:
        """Indices of the lines present on the 'old' or 'new' side."""
        keep = (' ', '-') if which == 'old' else (' ', '+')
        return [i for i, line in enumerate(self.lines) if line[:1] in keep]


def parse_hunks(diff: str) -> list[Hunk]:
    hunks: list[Hunk] = []
    file = ''
    cur: Hunk | None = None
    for line in diff.splitlines():
        match = _FILE_RE.match(line)
        if match:
            file = match.group(2)
            cur = None
            continue
        match = _HUNK_RE.match(line)
        if match:
            cur = Hunk(file, int(match.group(1)), int(match.group(3)))
            hunks.append(cur)
            continue
        if cur is None or line.startswith('\\'):
            continue  # file headers, '\ No newline at end of file'
        if line == '':
            line = ' '  # a blank context line whose marker was stripped
        if line[0] in ' -+':
            cur.lines.append(line)
    return hunks


def is_source(path: str) -> bool:
    return path.endswith(SOURCE_SUFFIXES)


def _changed_runs(hunk: Hunk) -> list[tuple[list[str], list[str]]]:
    """Consecutive changed lines as (removed, added) pairs, in hunk order."""
    runs: list[tuple[list[str], list[str]]] = []
    minus: list[str] = []
    plus: list[str] = []
    for line in hunk.lines + [' ']:
        if line.startswith('-'):
            if plus:  # a '+' run followed by '-' starts a new pair
                runs.append((minus, plus))
                minus, plus = [], []
            minus.append(line[1:])
        elif line.startswith('+'):
            plus.append(line[1:])
        else:
            if minus or plus:
                runs.append((minus, plus))
            minus, plus = [], []
    return runs


def fix_shape(diff: str) -> str:
    """The skill's decision table: adds / removes / changes / refactor."""
    hunks = parse_hunks(diff)
    runs = [run for hunk in hunks if is_source(hunk.file) for run in _changed_runs(hunk)]
    if not runs:
        return 'refactor'
    if all(not minus for minus, _plus in runs):
        return 'adds'
    if all(not plus for _minus, plus in runs):
        return 'removes'
    n_add = sum(len(plus) for _minus, plus in runs)
    n_del = sum(len(minus) for minus, _plus in runs)
    paired = 0
    for minus, plus in runs:
        if minus and plus:
            before = ' '.join(line.strip() for line in minus)
            after = ' '.join(line.strip() for line in plus)
            if difflib.SequenceMatcher(None, before, after).ratio() >= 0.6:
                paired += len(minus) + len(plus)
    if paired >= 0.6 * (n_add + n_del):
        return 'changes'  # mostly edits of existing lines
    # Mixed diffs take the dominant side: a fix that adds a check and touches a
    # line elsewhere is still 'adds' for the decision table.
    if n_add >= 3 * n_del:
        return 'adds'
    if n_del >= 3 * n_add:
        return 'removes'
    return 'refactor'


class _Stripper:
    """Removes comments and string literals so braces can be counted."""

    def __init__(self) -> None:
        self.in_comment = False

    def __call__(self, line: str) -> str:
        out = []
        i = 0
        while i < len(line):
            if self.in_comment:
                end = line.find('*/', i)
                if end < 0:
                    return ''.join(out)
                self.in_comment = False
                i = end + 2
                continue
            ch = line[i]
            if line.startswith('/*', i):
                self.in_comment = True
                i += 2
                continue
            if line.startswith('//', i):
                break
            if ch in '"\'':
                quote = ch
                i += 1
                while i < len(line) and line[i] != quote:
                    i += 2 if line[i] == '\\' else 1
                i += 1
                out.append('""')
                continue
            out.append(ch)
            i += 1
        return ''.join(out)


def function_head(code: str) -> str | None:
    """The function a definition line at brace depth 0 introduces, if any."""
    if not code or code[0].isspace() or code.startswith('#'):
        return None
    if code.strip().endswith(';'):
        return None  # prototype or declaration; a multi-line signature ends in ','
    match = _HEAD_RE.match(code)
    if not match:
        return None
    name = match.group(1)
    if name in NOT_FUNCTIONS:
        return None
    return name


def enclosing_functions(hunk: Hunk, side: str = 'old') -> list[str | None]:
    """Per hunk line: the function whose body (or head) it belongs to, on one side."""
    names: list[str | None] = [None] * len(hunk.lines)
    strip = _Stripper()
    depth = 0
    current: str | None = None
    pending: str | None = None  # head seen, body '{' not yet
    for i in hunk.side(side):
        raw = hunk.lines[i][1:]
        code = strip(raw)
        if depth == 0 and current is None:
            head = function_head(code)
            if head:
                pending = head
        opens, closes = code.count('{'), code.count('}')
        if pending is not None and opens:
            current, pending = pending, None
        if current is not None or pending is not None:
            names[i] = current or pending
        depth += opens - closes
        if depth <= 0:
            depth = 0
            if current is not None and closes:
                current = None
        if pending is not None and code.strip().endswith(';'):
            pending = None
    return names


def hunk_functions(diff: str) -> set[tuple[str, str]]:
    """(file, function) pairs whose body a fix changes — the overlap key."""
    out: set[tuple[str, str]] = set()
    for hunk in parse_hunks(diff):
        if not is_source(hunk.file):
            continue
        for side in ('old', 'new'):
            names = enclosing_functions(hunk, side)
            marker = '-' if side == 'old' else '+'
            for i, line in enumerate(hunk.lines):
                if line.startswith(marker) and names[i]:
                    out.add((hunk.file, names[i]))
    return out


def complete_statement(head: list[str], tail: list[str], limit: int = 3) -> list[str]:
    """A changed `if (...)` whose brace-less body is unchanged context: borrow up to
    `limit` following lines so the statement can complete."""
    for k in range(1, limit + 1):
        stmts = statements(head + tail[:k])
        if stmts:
            return stmts[:1]
    return []


def statements(lines: list[str]) -> list[str]:
    """Complete C statements from raw code lines: multi-line calls and
    brace-less `if (...) stmt;` collapse onto one line, compounds are dropped."""
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    strip = _Stripper()
    for raw in lines:
        code = strip(raw).strip()
        if not code or code.startswith('#'):
            continue
        text = raw.strip()
        if not buf and (text.startswith(('}', 'else', 'case ', 'default:')) or text.endswith(':')):
            if text.endswith('{') or text.endswith(':') or text == '}':
                continue
            text = re.sub(r'^\}\s*', '', text)  # `} else if (...)` keeps its statement part
        buf.append(text)
        depth += code.count('(') - code.count(')')
        if depth <= 0 and text.endswith(';'):
            stmt = ' '.join(buf)
            buf, depth = [], 0
            if '{' not in stmt and '}' not in stmt and not is_declaration(stmt):
                out.append(strip_annotations(stmt))
        elif depth <= 0 and text.endswith(('{', '}', ':')):
            buf, depth = [], 0
    return out


def is_declaration(stmt: str) -> bool:
    """`type name;` / `type name = init;` — but never `return x;` or a call."""
    first = re.match(r'[A-Za-z_]\w*', stmt)
    if first and first.group(0) in _JUMPS:
        return False
    return bool(_DECL_RE.match(stmt))


KERNEL_TYPEDEFS = frozenset(
    """
    u8 u16 u32 u64 s8 s16 s32 s64 __u8 __u16 __u32 __u64 __s8 __s16 __s32 __s64
    __le16 __le32 __le64 __be16 __be32 __be64 __sum16 __wsum
    size_t ssize_t loff_t off_t dma_addr_t phys_addr_t resource_size_t gfp_t umode_t
    pid_t uid_t gid_t kuid_t kgid_t dev_t sector_t blkcnt_t atomic_t atomic64_t
    bool uint8_t uint16_t uint32_t uint64_t int8_t int16_t int32_t int64_t uintptr_t
    """.split()  # noqa: SIM905
)
_TYPEDEF_RE = re.compile(r'\b([A-Za-z_]\w*)\b')
# Sparse/compiler annotations that spatch's C parser swallows as attributes but
# an SmPL pattern may not spell out; dropping them keeps the pattern matching.
_ANNOTATION_RE = re.compile(
    r'\b__(?:force|user|iomem|rcu|percpu|kernel|bitwise|must_check|maybe_unused|always_inline|'
    r'cold|hot|pure|read_mostly|init|exit|initdata|initconst|ref|cacheline_aligned|packed|'
    r'nocast|safe|private|unused|noinline|weak|used|printf\(\d+,\s*\d+\)|aligned\(\d+\))\b\s*'
)


def strip_annotations(stmt: str) -> str:
    return re.sub(r'\s+', ' ', _ANNOTATION_RE.sub('', stmt)).replace('( ', '(').strip()


def typedefs_used(text: str) -> list[str]:
    """Kernel typedef names a pattern spells out; SmPL needs them declared."""
    seen = {m.group(1) for m in _TYPEDEF_RE.finditer(text)}
    return sorted(seen & KERNEL_TYPEDEFS)


def starrable(stmts: list[str]) -> list[str]:
    """Drop bare jumps when anything more specific is available."""
    specific = [s for s in stmts if s not in _TRIVIAL and not s.startswith('goto ')]
    return specific or stmts


def subsystem(path: str) -> str:
    """Two path components for the big trees, one otherwise (drivers/net, fs/ext4, kernel)."""
    parts = path.split('/')
    if parts[0] in ('drivers', 'net', 'fs', 'arch', 'sound', 'include', 'tools', 'security'):
        return '/'.join(parts[:2]) if len(parts) > 2 else parts[0]
    return parts[0]


# ---------------------------------------------------------------------------
# Corpus-scale shape records: the stratification and overlap keys for the
# new-rule sample and the pool build. Needs git (cheap: two `git show` per CVE).


@dataclass
class ShapeRecord:
    cve: str
    split: str
    fix: str
    year: int
    subsystem: str  # of the first touched source file, '' when none
    # adds | removes | changes | refactor, or two shapes no rule can be judged on:
    # none (the fix touches no C/asm source) and deletes (every touched source
    # file is removed -- a subsystem retirement; with no fixed code to be silent
    # on, any pattern in the deleted files would pass, so cvehound expresses
    # those as .grep rules, not semantic patches).
    shape: str
    n_files: int
    n_add: int
    n_del: int
    funcs: list[str] = field(default_factory=list)  # 'file:function' the fix changes


# The shapes no rule can be judged on (ShapeRecord.shape): never sampled or taught.
UNJUDGED_SHAPES = ('none', 'deletes')


def deletion_only(statuses: list[tuple[str, str]], files: list[str]) -> bool:
    """Whether every one of `files` is deleted in a `--name-status` listing."""
    status = {path: code for code, path in statuses}
    return bool(files) and all(status.get(path, '').startswith('D') for path in files)


def file_statuses(kernel: str, fix: str) -> list[tuple[str, str]]:
    """(status, path) per file the fix commit touches, first parent for merges."""
    out = git(
        kernel, 'diff-tree', '--no-commit-id', '-r', '--name-status', '-m', '--first-parent', fix
    )
    rows = [line.split('\t') for line in out.splitlines() if line.strip()]
    return [(row[0], row[-1]) for row in rows if len(row) >= 2]


def shape_record(kernel: str, rec: Any) -> ShapeRecord:
    """Classify one CVE's fix commit; `rec` is a CveRecord with fix and fix_date."""
    files = files_candidates(kernel, rec.fix)
    year = time.gmtime(rec.fix_date).tm_year if rec.fix_date else 0
    if not files:
        return ShapeRecord(rec.cve, rec.split, rec.fix, year, '', 'none', 0, 0, 0)
    if deletion_only(file_statuses(kernel, rec.fix), files):
        return ShapeRecord(
            rec.cve, rec.split, rec.fix, year, subsystem(files[0]), 'deletes', len(files), 0, 0
        )
    diff_b = show_diff(kernel, rec.fix, files, '-U3')
    diff_c = show_diff(kernel, rec.fix, files, '-W')
    hunks = parse_hunks(diff_b)
    n_add = sum(1 for h in hunks for line in h.lines if line.startswith('+'))
    n_del = sum(1 for h in hunks for line in h.lines if line.startswith('-'))
    funcs = sorted(f'{file}:{func}' for file, func in hunk_functions(diff_c))
    return ShapeRecord(
        rec.cve,
        rec.split,
        rec.fix,
        year,
        subsystem(files[0]),
        fix_shape(diff_b),
        len(files),
        n_add,
        n_del,
        funcs,
    )


def _shape_one(payload: tuple[str, Any]) -> ShapeRecord | tuple[str, str]:
    kernel, rec = payload
    try:
        return shape_record(kernel, rec)
    except (ValueError, RuntimeError, OSError) as err:
        return rec.cve, str(err)


def classify_shapes(kernel: str, records: list[Any], jobs: int = 8) -> list[ShapeRecord]:
    """Shape every record with a fix commit; a CVE git cannot answer for is left out."""
    import multiprocessing

    payloads = [(kernel, rec) for rec in records if rec.fix]
    if jobs <= 1:
        results = list(map(_shape_one, payloads))
    else:
        with multiprocessing.get_context('spawn').Pool(jobs) as pool:
            results = list(pool.imap_unordered(_shape_one, payloads, chunksize=8))
    return sorted((r for r in results if isinstance(r, ShapeRecord)), key=lambda r: r.cve)


# The shape table under the data directory.
SHAPES = 'shapes.parquet'


def save_shapes(records: list[ShapeRecord], path: str) -> None:
    import dataclasses

    tables.write_rows([dataclasses.asdict(r) for r in records], path)


def load_shapes(path: str) -> list[ShapeRecord]:
    return [ShapeRecord(**row) for row in tables.read_rows(path)]


def load_table(data_dir: str) -> list[ShapeRecord]:
    """The shape table of a data directory."""
    return load_shapes(os.path.join(data_dir, SHAPES))


def test_overlap(shapes: list[ShapeRecord], test_cves: set[str]) -> set[str]:
    """CVEs (outside the test set) whose fix touches a (file, function) a test CVE touches."""
    keys = {f for r in shapes if r.cve in test_cves for f in r.funcs}
    return {r.cve for r in shapes if r.cve not in test_cves and keys.intersection(r.funcs)}
