"""Whole-tree scans without whole trees: spatch's own prefilter, applied by git.

spatch reads every file it is handed, but its inferred "Grep query" -- the
words a file must contain for the rule to possibly match -- decides which of
them it parses. Asking `git grep -w` for the files at a commit that contain any
of those words yields a superset of what spatch would parse (the query is a
boolean formula over the same words; the disjunction is its weakest form), so
a scan over just those files gives the same verdict as a scan over the tree.

That turns a T6 check at an arbitrary commit -- a backport on a stable branch,
which no worktree can be kept for -- into a mini-tree the blob store already
knows how to build, sized by the rule's own selectivity rather than by the
kernel. The files are linked into one directory per commit that accumulates
across rules, so a path is stable for the lifetime of the store and
coccinelle's path-keyed AST cache keeps hitting from one rule to the next.
"""

import contextlib
import os
import re
from collections.abc import Iterable

from cvehound import KCONFIG_H
from cvehound.oracle.kerneltree import BlobMaterializer, ls_tree_entries
from cvehound.oracle.resultcache import Sig

from rulegen.git import commit_oid

_WORD_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
# What spatch parses (extract.SOURCE_SUFFIXES also lists .S, which it does not).
SPATCH_SUFFIXES = ('.c', '.h')
LS_TREE_CHUNK = 2000  # pathspecs per ls-tree call, well under the argv limit


def query_words(query: str) -> list[str]:
    """The identifiers of spatch's grep query, in order, without duplicates.

    The printed form is a boolean formula (`a || b`, `a && (b || c)`); only its
    atoms matter here because the disjunction over them is what git greps for.
    """
    return list(dict.fromkeys(_WORD_RE.findall(query)))


def parse_grep_output(output: str, ref: str) -> list[str]:
    """`git grep -l <ref>` prints '<ref>:<path>' per line; keep the paths."""
    prefix = f'{ref}:'
    return [line[len(prefix) :] for line in output.splitlines() if line.startswith(prefix)]


def matching_files(git, ref: str, words: Iterable[str]) -> list[str]:
    """Source files at `ref` containing any of the words (whole-word, text only)."""
    words = list(words)
    if not words:
        return []
    # One alternation, not one -e per word: git's word matching over several
    # patterns retries per occurrence of each, and a query carrying a common
    # short identifier (`n`, `i`, `ret`) then takes minutes of CPU per tree
    # where the single regex takes seconds.
    # The words are identifiers (_WORD_RE), so they need no escaping.
    args = ['-l', '-w', '-I', '-E', '--no-color', '-e', '|'.join(words)]
    args += [ref, '--', *(f'*{suffix}' for suffix in SPATCH_SUFFIXES)]
    # GitPython's grep raises on exit 1 (no match) unless told otherwise.
    out = git.grep(*args, with_exceptions=False)
    return parse_grep_output(out, ref)


def tree_sig(git, commit: str, paths: Iterable[str]) -> Sig:
    """A signature in kerneltree.sig()'s shape for the given paths at a commit:
    the paths plus the kconfig probe, sorted, missing paths omitted.

    One `git ls-tree` with the paths as pathspecs (chunked: a common word can
    match tens of thousands of files) rather than a walk of the whole tree.
    An unresolvable commit raises for the reason kerneltree.sig() does: a
    vacuous empty signature would cache a false silence.
    """
    if commit_oid(git, commit) is None:
        raise ValueError(f'unresolvable ref: {commit}')
    wanted = sorted(set(paths) | {KCONFIG_H})
    entries: dict[str, str] = {}
    for start in range(0, len(wanted), LS_TREE_CHUNK):
        for _mode, otype, oid, path in ls_tree_entries(
            git, commit, '--', *wanted[start : start + LS_TREE_CHUNK]
        ):
            if otype == 'blob':
                entries[path] = oid
    return tuple(sorted(entries.items()))


def commit_dir(root: str, commit: str) -> str:
    return os.path.join(root, 'refs', commit)


def link_into_commit_dir(materializer: BlobMaterializer, root: str, commit: str, sig: Sig) -> str:
    """The per-commit directory holding at least the signature's blobs.

    materialize() fetches the blobs and builds the per-signature tree; the
    files are then hardlinked (same inodes) under a directory named by the
    commit, which grows as more rules ask for more files and never changes an
    existing path. spatch scans the whole directory: the extra files other
    rules brought in are ones its own prefilter skips, so the verdict is the
    one the signature alone would give.
    """
    src = materializer.materialize(sig)
    dest = commit_dir(root, commit)
    for relpath, _oid in sig:
        target = os.path.join(dest, relpath)
        if os.path.exists(target):
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with contextlib.suppress(FileExistsError):  # another worker linked it first
            os.link(os.path.join(src, relpath), target)
    os.makedirs(dest, exist_ok=True)
    return dest
