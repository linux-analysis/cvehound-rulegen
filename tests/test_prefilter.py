"""git-grep prefilter for whole-tree scans: query parsing, output parsing, signatures, linking."""

import os

import pytest
from cvehound import KCONFIG_H

from rulegen.oracle import prefilter


def test_query_words_takes_the_atoms_of_the_formula():
    assert prefilter.query_words('snd_ctl_elem_id || name || get_ctl_id_hash') == [
        'snd_ctl_elem_id',
        'name',
        'get_ctl_id_hash',
    ]
    assert prefilter.query_words('(a && b) || (a && c)') == ['a', 'b', 'c']
    assert prefilter.query_words('') == []


def test_parse_grep_output_keeps_only_this_refs_paths():
    out = 'v6.6:sound/core/control.c\nv6.6:include/sound/control.h\nother:x.c\n\n'
    assert prefilter.parse_grep_output(out, 'v6.6') == [
        'sound/core/control.c',
        'include/sound/control.h',
    ]


class FakeGit:
    def __init__(self, tree: dict[str, str], matches: list[str]) -> None:
        self.tree, self.matches, self.calls = tree, matches, []

    def get_object_header(self, name):
        if name.startswith('missing'):
            raise ValueError(name)
        return ('sha', 'commit', 1)

    def ls_tree(self, *args):
        # ls_tree_entries passes -z first; then the commit, '--', the pathspecs.
        assert args[0] == '-z' and args[2] == '--'
        wanted = set(args[3:])
        self.calls.append(('ls-tree', len(wanted)))
        return ''.join(
            f'100644 blob {oid}\t{path}\0' for path, oid in self.tree.items() if path in wanted
        )

    def grep(self, *args, **kwargs):
        self.calls.append(args)
        ref = args[-4]
        return '\n'.join(f'{ref}:{path}' for path in self.matches)


def test_matching_files_greps_every_word_as_a_whole_word_in_sources_only():
    git = FakeGit({}, ['a/b.c'])
    assert prefilter.matching_files(git, 'v6.6', ['kfree_skb', 'name']) == ['a/b.c']
    (call,) = git.calls
    assert call[:5] == ('-l', '-w', '-I', '-E', '--no-color')
    assert call[5:7] == ('-e', 'kfree_skb|name')  # one alternation, never one -e per word
    assert call[-4:] == ('v6.6', '--', '*.c', '*.h')
    assert prefilter.matching_files(git, 'v6.6', []) == []


def test_tree_sig_matches_kerneltree_shape_and_refuses_unknown_commits():
    tree = {'a/b.c': 'oid1', 'c.h': 'oid2', KCONFIG_H: 'oidk', 'z.c': 'oid3'}
    git = FakeGit(tree, ['z.c', 'a/b.c'])
    sig = prefilter.tree_sig(git, 'sha', prefilter.matching_files(git, 'sha', ['w']))
    assert sig == (('a/b.c', 'oid1'), (KCONFIG_H, 'oidk'), ('z.c', 'oid3'))
    assert prefilter.tree_sig(git, 'sha', ['missing.c']) == ((KCONFIG_H, 'oidk'),)
    with pytest.raises(ValueError, match='unresolvable'):
        prefilter.tree_sig(git, 'missing-commit', ['a/b.c'])
    # Many paths go out in bounded chunks, never one argv per path.
    git.calls.clear()
    prefilter.tree_sig(git, 'sha', [f'f{i}.c' for i in range(prefilter.LS_TREE_CHUNK * 2 + 1)])
    assert [c for c in git.calls if c[0] == 'ls-tree'] == [
        ('ls-tree', prefilter.LS_TREE_CHUNK),
        ('ls-tree', prefilter.LS_TREE_CHUNK),
        ('ls-tree', 2),
    ]


class FakeMaterializer:
    def __init__(self, root: str) -> None:
        self.root = root

    def materialize(self, sig):
        tree = os.path.join(self.root, 'trees', 't1')
        for relpath, oid in sig:
            path = os.path.join(tree, relpath)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as fh:
                fh.write(oid)
        return tree


def test_link_into_commit_dir_accumulates_and_never_rewrites(tmp_path):
    root = str(tmp_path)
    mat = FakeMaterializer(root)
    sig1 = (('a/b.c', 'oid1'), (KCONFIG_H, 'oidk'))
    dest = prefilter.link_into_commit_dir(mat, root, 'sha', sig1)
    assert dest == prefilter.commit_dir(root, 'sha')
    with open(os.path.join(dest, 'a/b.c')) as fh:
        assert fh.read() == 'oid1'
    # A second rule brings one more file; the first stays as it was (same inode).
    inode = os.stat(os.path.join(dest, 'a/b.c')).st_ino
    sig2 = (('a/b.c', 'oid1'), ('c.h', 'oid2'))
    prefilter.link_into_commit_dir(mat, root, 'sha', sig2)
    assert sorted(os.listdir(dest)) == ['a', 'c.h', 'include']
    assert os.stat(os.path.join(dest, 'a/b.c')).st_ino == inode
    assert os.stat(os.path.join(dest, 'c.h')).st_nlink == 2
