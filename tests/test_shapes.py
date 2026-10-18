"""Diff anatomy on real kernel -W excerpts: shapes, enclosing functions, statements."""

import pytest
from helpers import ADDS, CHANGES, REMOVES, make_record

from rulegen import shapes
from rulegen.shapes import (
    ShapeRecord,
    classify_shapes,
    complete_statement,
    deletion_only,
    enclosing_functions,
    fix_shape,
    hunk_functions,
    is_declaration,
    parse_hunks,
    statements,
    subsystem,
    typedefs_used,
)


@pytest.mark.parametrize(
    ('diff', 'shape'),
    [
        (ADDS, 'adds'),
        (REMOVES, 'removes'),
        (CHANGES, 'changes'),
        (ADDS + REMOVES, 'adds'),  # the dominant side of a mixed diff
        (ADDS + REMOVES + REMOVES, 'refactor'),  # neither side dominates, nothing paired
    ],
)
def test_fix_shapes_follow_the_decision_table(diff, shape):
    assert fix_shape(diff) == shape


def test_enclosing_function_is_read_from_the_body_not_the_trailer():
    (hunk,) = parse_hunks(ADDS)
    names = enclosing_functions(hunk, 'new')
    added = [names[i] for i, line in enumerate(hunk.lines) if line.startswith('+')]
    assert added == ['ovl_copy_up_one'] * 4
    assert hunk_functions(ADDS) == {('fs/overlayfs/copy_up.c', 'ovl_copy_up_one')}
    assert hunk_functions(REMOVES) == {('net/sched/cls_route.c', 'route4_change')}
    # Braces inside comments and strings do not disturb the depth counter.
    assert hunk_functions(CHANGES) == {('fs/ksmbd/auth.c', 'ksmbd_decode_ntlmssp_auth_blob')}


def test_added_statements_collapse_across_lines():
    added = [line[1:] for line in parse_hunks(ADDS)[0].lines if line.startswith('+')]
    assert statements(added) == [
        'if (!kuid_has_mapping(current_user_ns(), ctx.stat.uid) || '
        '!kgid_has_mapping(current_user_ns(), ctx.stat.gid)) return -EOVERFLOW;'
    ]


@pytest.mark.parametrize(
    ('lines', 'expected'),
    [
        # Declarations and compound heads are not statements.
        (['\tint err;', '\tstruct foo *p = bar(x);', '\terr = baz(p);'], ['err = baz(p);']),
        (['\tif (x) {', '\t\tkfree(p);', '\t}'], ['kfree(p);']),
        (['\tfoo(a,', '\t    b);', '#ifdef X', '\tbreak;'], ['foo(a, b);', 'break;']),
        # Sparse annotations are dropped from patterns.
        (['\trc = put_user(amount, (int __user *)argp);'], ['rc = put_user(amount, (int *)argp);']),
        (
            ['\treturn jhash_3words(v, (__force u32)a->s6_addr32[2], initval);'],
            ['return jhash_3words(v, (u32)a->s6_addr32[2], initval);'],
        ),
    ],
)
def test_statements(lines, expected):
    assert statements(lines) == expected


@pytest.mark.parametrize(
    ('head', 'tail', 'expected'),
    [
        # A changed condition borrows its unchanged body.
        (
            ['\t\tif (!set->ops->commit)'],
            ['\t\t\tcontinue;', '\t}'],
            ['if (!set->ops->commit) continue;'],
        ),
        (['\tfoo(a,'], ['\t    b);'], ['foo(a, b);']),
        (['\t}'], ['\treturn 0;'], ['return 0;']),
    ],
)
def test_complete_statement(head, tail, expected):
    assert complete_statement(head, tail) == expected


def test_declarations_versus_statements():
    for decl in (
        'int x;',
        'struct foo *p = bar(x);',
        'size_t read_pos = consumed * subbuf_size + buf->bytes_consumed;',
    ):
        assert is_declaration(decl)
    for stmt in ('return ret;', 'return 0;', 'kfree(p);', 'x = y;'):
        assert not is_declaration(stmt)
    assert typedefs_used('return (u64)dn_off + (__force u32)a->s6_addr32[2];') == ['u32', 'u64']


@pytest.mark.parametrize(
    ('path', 'bucket'),
    [
        ('drivers/net/usb/foo.c', 'drivers/net'),
        ('fs/ext4/inode.c', 'fs/ext4'),
        ('kernel/bpf/verifier.c', 'kernel'),
        ('mm/slub.c', 'mm'),
    ],
)
def test_subsystem_buckets(path, bucket):
    assert subsystem(path) == bucket


def test_deletion_only_fixes_get_their_own_shape():
    statuses = [('D', 'sound/oss/a.c'), ('D', 'sound/oss/b.h'), ('M', 'sound/Kconfig')]
    assert deletion_only(statuses, ['sound/oss/a.c', 'sound/oss/b.h'])
    assert not deletion_only(
        statuses + [('M', 'sound/oss/c.c')], ['sound/oss/a.c', 'sound/oss/c.c']
    )
    assert not deletion_only([('R100', 'new.c')], ['new.c'])  # a rename is not a deletion
    assert not deletion_only(statuses, [])


def shape(cve: str, split: str, funcs: list[str]) -> ShapeRecord:
    return ShapeRecord(cve, split, 'f' * 40, 2025, 'net', 'adds', 1, 1, 0, funcs)


def test_overlap_is_a_shared_file_and_function():
    rows = [
        shape('CVE-2024-0001', 'test', ['net/ipv4/x.c:fn0']),
        shape('CVE-2025-0001', 'newrule', ['net/ipv4/x.c:fn0', 'a.c:g']),
        shape('CVE-2025-0002', 'newrule', ['net/ipv4/x.c:fn1']),
    ]
    assert shapes.test_overlap(rows, {'CVE-2024-0001'}) == {'CVE-2025-0001'}


def test_a_cve_git_cannot_answer_for_is_left_out_not_fatal(monkeypatch, tmp_path):
    """One bad fix commit must not abort the classification of thousands."""
    monkeypatch.setattr(shapes, 'files_candidates', lambda _kernel, _fix: ['net/foo.c'])
    assert classify_shapes(str(tmp_path), [make_record('CVE-2025-0001')], jobs=1) == []
