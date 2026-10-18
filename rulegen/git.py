"""One way to ask a git clone a question.

Every module that reads history goes through here, so a failure always looks
the same: `GitError`, a RuntimeError, which the per-CVE workers already treat
as "skip this CVE", carrying the command and the end of its stderr. Output is
decoded with replacement: a commit message with stray bytes is still text.
"""

import subprocess
from typing import Any


class GitError(RuntimeError):
    """A git command exited with a code its caller did not expect."""


def git_run(repo: str, *args: str, input: str | None = None) -> subprocess.CompletedProcess:
    """`git -C repo <args>`, whatever its exit code: the caller reads the result."""
    return subprocess.run(
        ['git', '-C', repo, *args],
        input=input,
        capture_output=True,
        text=True,
        errors='replace',
        check=False,
    )


def git(repo: str, *args: str, ok: tuple[int, ...] | None = (0,), input: str | None = None) -> str:
    """The stdout of `git -C repo <args>`; GitError on an exit code outside `ok` (None: any)."""
    proc = git_run(repo, *args, input=input)
    if ok is not None and proc.returncode not in ok:
        raise GitError(f'git {args[0]} failed ({proc.returncode}): {proc.stderr.strip()[:500]}')
    return proc.stdout


def resolves(repo: str, rev: str) -> bool:
    """Whether `rev` names a commit in the clone."""
    return git_run(repo, 'cat-file', '-e', f'{rev}^{{commit}}').returncode == 0


def commit_oid(reader: Any, ref: str) -> str | None:
    """The commit `ref` names, asked through a long-lived object reader (GitPython's
    `repo.git`, which keeps one `cat-file --batch-check` process), or None."""
    from cvehound.oracle.kerneltree import object_header

    obj = object_header(reader, f'{ref}^{{commit}}')
    return obj[0] if obj else None
