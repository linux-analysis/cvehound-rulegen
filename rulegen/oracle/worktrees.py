"""Persistent detached worktrees at branch heads and tags, for whole-tree scans.

A port of the suite's `_branch_worktree` (tests/conftest.py): a full kernel
checkout costs 5-15 s, so worktrees live under the oracle work root (on a real
disk, not tmpfs) and are refreshed to the ref's current commit once per
process. A file lock covers creation and refresh across worker processes.
Cache keys never depend on a worktree's staleness: verdicts are keyed by the
tree object id (whole_tree_sig), and the path is refreshed before use.
"""

import os
from typing import Any

from filelock import FileLock

from rulegen.git import commit_oid, git, git_run


class WorktreeStore:
    def __init__(self, repo: Any, root: str) -> None:
        self.repo = repo
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self._fresh: set[str] = set()

    def commit_oid(self, ref: str) -> str:
        # Asked through the object reader (`repo.git`); the repo itself is what
        # `worktree add` below needs.
        oid = commit_oid(self.repo.git, ref)
        if oid is None:
            raise ValueError(f'unresolvable ref: {ref}')
        return oid

    def head(self, path: str) -> str | None:
        proc = git_run(path, 'rev-parse', 'HEAD')
        return proc.stdout.strip() if proc.returncode == 0 else None

    def path(self, ref: str) -> str:
        """A checked-out tree at `ref`'s current commit."""
        from git import GitCommandError

        path = os.path.join(self.root, ref.replace('/', '-'))
        if path in self._fresh:
            return path
        target = self.commit_oid(ref)
        with FileLock(path + '.lock'):
            if not os.path.exists(os.path.join(path, '.git')):  # a worktree's .git is a file
                try:
                    self.repo.git.worktree('add', '--detach', '--force', path, target)
                except GitCommandError:
                    # A stale admin entry (deleted directory) blocks the add;
                    # prune and retry — only on this failure path, so sibling
                    # workers' in-flight adds are never pruned from under them.
                    self.repo.git.worktree('prune')
                    self.repo.git.worktree('add', '--detach', '--force', path, target)
            elif self.head(path) != target:
                git(path, 'checkout', '--force', '--detach', target)
        self._fresh.add(path)
        return path
