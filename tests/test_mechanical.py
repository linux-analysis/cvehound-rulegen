"""The mechanical baseline on real diff excerpts: shape-appropriate, structurally valid rules."""

import pytest
from helpers import ADDS, CHANGES, FIX, FIXES, REMOVES, make_example

from rulegen.gen.adapters.base import GenRequest, SamplingParams
from rulegen.gen.mechanical import MechanicalAdapter, mechanical_rule
from rulegen.oracle.reward import structure_failures
from rulegen.promptbuild import finalize_rule, parse_rule_output


def finalized(diff_c: str, files: list[str]) -> str | None:
    example = make_example('CVE-2023-9999', diff_c=diff_c, diff_b=diff_c, files_candidates=files)
    body = mechanical_rule(example)
    return None if body is None else finalize_rule(body, FIX, FIXES, 'fixes')


@pytest.mark.parametrize(
    ('diff', 'files', 'expected'),
    [
        # A removal stars the removed statement in its function, unguarded.
        (
            REMOVES,
            ['net/sched/cls_route.c'],
            [
                '/// Files: net/sched/cls_route.c\n/// Fix: ',
                'route4_change(...)',
                '*\tf->res = fold->res;',
            ],
        ),
        # An addition guards with `when !=` and stars the statement it protects.
        (
            ADDS,
            ['fs/overlayfs/copy_up.c'],
            [
                'ovl_copy_up_one(...)',
                '\t    when != if (!kuid_has_mapping(current_user_ns(), ctx.stat.uid) || '
                '!kgid_has_mapping(current_user_ns(), ctx.stat.gid)) return -EOVERFLOW;',
                '*\tctx.metacopy = ovl_need_meta_copy_up(dentry, ctx.stat.mode, flags);',
            ],
        ),
        # A change stars the old statement.
        (
            CHANGES,
            ['fs/ksmbd/auth.c'],
            [
                '*\tif (blob_len < (u64)dn_off + dn_len || blob_len < (u64)nt_off + nt_len) '
                'return -EINVAL;'
            ],
        ),
    ],
    ids=['removes', 'adds', 'changes'],
)
def test_each_fix_shape_gets_its_rule(diff, files, expected):
    rule = finalized(diff, files)
    assert rule is not None and structure_failures(rule) == []
    for text in expected:
        assert text in rule
    assert ('when !=' in rule) is (diff is ADDS)


def test_nothing_starrable_yields_no_rule_and_a_contract_row():
    nothing = 'diff --git a/a.c b/a.c\n@@ -1,3 +1,3 @@ int f(void)\n int f(void)\n {\n-}\n+}\n'
    assert mechanical_rule(make_example('CVE-2023-9998', diff_c=nothing)) is None
    comp = MechanicalAdapter().complete(
        GenRequest([], SamplingParams(), 0, example=make_example('CVE-2023-9998', diff_c=nothing))
    )
    assert comp.text == '' and parse_rule_output(comp.text) is None


def test_adapter_output_honours_the_contract():
    example = make_example(
        'CVE-2023-9997', diff_c=REMOVES, files_candidates=['net/sched/cls_route.c']
    )
    comp = MechanicalAdapter().complete(GenRequest([], SamplingParams(), 0, example=example))
    body = parse_rule_output(comp.text)
    assert body is not None and body.startswith('/// Files: net/sched/cls_route.c\n\n@')
    assert 'virtual' not in body


def test_casts_to_kernel_typedefs_are_declared():
    diff = (
        'diff --git a/net/x.c b/net/x.c\n@@ -1,6 +1,6 @@ int other(void)\n'
        ' int f(int a)\n {\n-\treturn (u64)a + (__force u32)b;\n+\treturn a;\n }\n'
    )
    rule = finalized(diff, ['net/x.c'])
    assert rule is not None
    assert '@r1@\ntypedef u32, u64;\n@@' in rule
    assert '*\treturn (u64)a + (u32)b;' in rule  # __force dropped, typedefs declared
