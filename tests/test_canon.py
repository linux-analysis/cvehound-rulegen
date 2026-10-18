"""Patch-to-detect canonicalization of transformation-style completions."""

from helpers import FIX, FIXES

from rulegen.gen.canon import blocks, canonicalize, patch_to_detect, polish
from rulegen.oracle.reward import structure_failures
from rulegen.promptbuild import finalize_rule

CHANGE_PATCH = """\
/// Files: fs/ksmbd/auth.c

@r@
expression blob_len, dn_off, dn_len, nt_off, nt_len;
@@

ksmbd_decode_ntlmssp_auth_blob(...)
{
	...
-	if (blob_len < (u64)dn_off + dn_len || blob_len < (u64)nt_off + nt_len)
+	if (blob_len < (u64)dn_off + dn_len || blob_len < (u64)nt_off + nt_len ||
+	    nt_len < CIFS_ENCPWD_SIZE)
		return -EINVAL;
	...
}
"""

ADD_PATCH = """\
/// Files: fs/overlayfs/copy_up.c

@r@
expression ctx, dentry, flags;
@@

ovl_copy_up_one(...)
{
	...
+	if (!kuid_has_mapping(current_user_ns(), ctx.stat.uid) ||
+	    !kgid_has_mapping(current_user_ns(), ctx.stat.gid))
+		return -EOVERFLOW;
	ctx.metacopy = ovl_need_meta_copy_up(dentry, ctx.stat.mode, flags);
	...
}
"""


def test_change_patch_stars_the_removed_line_and_drops_the_added():
    out = patch_to_detect(CHANGE_PATCH)
    assert out is not None
    assert '*\tif (blob_len < (u64)dn_off + dn_len || blob_len < (u64)nt_off + nt_len)' in out
    assert 'CIFS_ENCPWD_SIZE' not in out and '\n+' not in out and '\n-' not in out
    assert structure_failures(finalize_rule(out, FIX, FIXES, 'fixes')) == []


def test_pure_addition_becomes_when_and_stars_the_guarded_statement():
    out = patch_to_detect(ADD_PATCH)
    assert out is not None
    assert (
        '\t... when != if (!kuid_has_mapping(current_user_ns(), ctx.stat.uid) || '
        '!kgid_has_mapping(current_user_ns(), ctx.stat.gid)) return -EOVERFLOW;' in out
    )
    assert '*\tctx.metacopy = ovl_need_meta_copy_up(dentry, ctx.stat.mode, flags);' in out
    assert structure_failures(finalize_rule(out, FIX, FIXES, 'fixes')) == []


def test_already_detection_or_hopeless_returns_none():
    starred = (
        CHANGE_PATCH.replace('-\tif', '*\tif')
        .replace('+\tif', '\tif')
        .replace('+\t    nt', '\t    nt')
    )
    assert patch_to_detect(starred) is None  # nothing to convert
    assert patch_to_detect('/// Files: a.c\n@r@\n@@\nf(...) { ... }\n') is None


def test_polish_normalizes_heads_declares_typedefs_and_drops_tag_clashes():
    rule = (
        '/// Files: fs/overlayfs/copy_up.c\n\n@r@\nidentifier ctx;\nexpression parent, dentry, flags;\n'
        'position p;\ntype T;\n@@\n\novl_copy_up_one(struct dentry *parent, struct dentry *dentry,\n'
        '\t\t\tint flags)\n{\n\t...\n*\tctx.metacopy = ovl_need_meta_copy_up(dentry, (u64)ctx.stat.mode, flags)@p;\n\t...\n}\n'
    )
    out = polish(rule)
    assert 'ovl_copy_up_one(...)\n{' in out
    # `dentry` no longer clashes once the head is normalized, so the declaration survives.
    assert 'expression parent, dentry, flags;' in out
    assert 'typedef u64;' in out and 'position p;' not in out and '@p' not in out
    assert '*\tctx.metacopy = ovl_need_meta_copy_up(dentry, (u64)ctx.stat.mode, flags);' in out
    assert canonicalize(out) is None  # idempotent: nothing left to change
    clash = '/// Files: a.c\n\n@r@\nexpression p, dentry;\n@@\n\nfoo(...)\n{\n*\tp = container_of(x, struct dentry, d_alias);\n}\n'
    assert 'expression p;' in polish(
        clash
    )  # a struct tag spelled out cannot also be a metavariable
    assert polish('/// Files: a.c\n\n@r@\n@@\n\nfoo(...)\n{\n*\tbar();\n}\n') == (
        '/// Files: a.c\n\n@r@\n@@\n\nfoo(...)\n{\n*\tbar();\n}\n'
    )


def test_canonicalize_composes_patch_and_polish():
    rule = (
        '/// Files: f.c\n\n@r@\nexpression a, b;\n@@\n\nksmbd_decode(authblob, blob_len)\n{\n\t...\n'
        '-\tif (blob_len < (u64)a + b)\n+\tif (blob_len < (u64)a + b || x)\n\t\treturn -EINVAL;\n\t...\n}\n'
    )
    out = canonicalize(rule)
    assert out is not None
    assert 'ksmbd_decode(...)' in out and 'typedef u64;' in out
    assert '*\tif (blob_len < (u64)a + b)' in out and '\n+' not in out


def test_polish_handles_return_types_body_noise_fields_and_iterators():
    rule = (
        '/// Files: drivers/hid/hid-core.c\n\n@r@\nexpression hid, stat, ctx;\nidentifier report;\n@@\n\n'
        'struct hid_report *hid_validate_values(struct hid_device *hid,\n\t\t\t\t\tunsigned int type)\n{\n'
        '\tint err;\n\tstruct hid_report *r = NULL;\n\t...\n\terr = vfs_getattr(&ctx.stat, 0);\n'
        '\tlist_for_each_entry(report, &hid->report_list, list) {\n*\t\tuse(report);\n\t}\n\t...\nout:\n\treturn r;\n}\n'
    )
    out = polish(rule)
    assert 'hid_validate_values(...)\n{' in out and 'struct hid_report *hid_validate' not in out
    assert (
        '\tint err;' not in out
        and 'struct hid_report *r = NULL;' not in out
        and '\nout:' not in out
    )
    assert 'expression hid, ctx;' in out and 'identifier stat;' in out  # field use -> identifier
    assert 'iterator name list_for_each_entry;' in out
    assert '*\t\tuse(report);' in out and '\treturn r;' in out


def test_polish_shares_the_baseline_head_test():
    """normalize_heads uses shapes.function_head, so the mechanical baseline and canon agree on heads."""
    typed = (
        '/// Files: a.c\n\n@r@\nexpression e;\n@@\n\n'
        'static int __must_check foo_probe(struct device *dev, int flags)\n{\n*\tbar(e);\n}\n'
    )
    assert 'foo_probe(...)\n{' in polish(typed)
    # A prototype is not a head: it keeps its parameters (and is dropped as a
    # declaration by drop_body_noise only inside a body).
    proto = '/// Files: a.c\n\n@r@\n@@\n\nint foo(int a);\n'
    assert 'int foo(int a);' in polish(proto)
    # One walker: the block indices agree with what the passes slice.
    lines = typed.split('\n')
    (header, meta_end, end) = blocks(lines)[0]
    assert lines[header] == '@r@' and lines[meta_end] == '@@' and end == len(lines)
