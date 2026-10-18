"""Persistent worktrees for whole-tree scans: created once, refreshed when the ref moves."""

from git import Repo

from rulegen.git import git
from rulegen.oracle.worktrees import WorktreeStore


def test_worktree_store_creates_and_refreshes(tmp_path):
    src = tmp_path / 'src'
    repo = Repo.init(str(src))
    commits = []
    for text in ('int a;\n', 'int b;\n'):
        (src / 'a.c').write_text(text)
        repo.index.add(['a.c'])
        commits.append(repo.index.commit(text).hexsha)
    repo.create_tag('v1', ref=commits[0])

    store = WorktreeStore(repo, str(tmp_path / 'wt'))
    path = store.path('v1')
    assert (tmp_path / 'wt' / 'v1' / 'a.c').read_text() == 'int a;\n'
    assert store.head(path) == commits[0]
    # Another process (a fresh store) sees a stale tree when the ref moves.
    repo.delete_tag('v1')
    repo.create_tag('v1', ref=commits[1])
    assert WorktreeStore(repo, str(tmp_path / 'wt')).path('v1') == path
    assert (tmp_path / 'wt' / 'v1' / 'a.c').read_text() == 'int b;\n'
    assert git(path, 'rev-parse', 'HEAD').strip() == commits[1]
    assert store.head(str(tmp_path / 'nowhere')) is None
