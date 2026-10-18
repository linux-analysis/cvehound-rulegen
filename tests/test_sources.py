"""The metadata sources side by side, and the agreement rule — no clone needed."""

import pytest
from helpers import B61, B510, FIX

from rulegen import sources
from rulegen.schema import INITIAL_COMMIT_HASH, CveMeta
from rulegen.sources import BranchIndex, HeaderView, SourceView, merge

FIX2, INTRO, INTRO2 = 'e' * 40, '1' * 40, '2' * 40
OLD = '0' * 40  # a mainline commit inside every branch base
BP61, BP61B, BP510 = 'a' * 40, 'b' * 40, 'c' * 40


def branch_index(mainline, branch_sets, bases):
    """A BranchIndex from sets: `bases[b]` are the mainline commits branch b carries."""
    branches = tuple(branch_sets)
    level = dict.fromkeys(mainline, len(branches))
    for i, branch in enumerate(branches):
        for sha in bases.get(branch, ()):
            level[sha] = min(level.get(sha, i), i)
    return BranchIndex(level, {b: frozenset(s) for b, s in branch_sets.items()}, branches)


@pytest.fixture
def index():
    return branch_index(
        mainline=[FIX, FIX2, INTRO, INTRO2, OLD, INITIAL_COMMIT_HASH],
        branch_sets={B510: {BP510}, B61: {BP61, BP61B}},
        bases={B510: {OLD, INITIAL_COMMIT_HASH}, B61: {OLD, INITIAL_COMMIT_HASH}},
    )


ALL = (FIX, FIX2, INTRO, INTRO2, OLD, BP61, BP61B, BP510, INITIAL_COMMIT_HASH)


def resolve(ref):
    """Abbreviated or full sha -> full sha, like git rev-parse."""
    return next((s for s in ALL if s.startswith(ref)), None)


def ancestor(a, b):
    return (a, b) in {(INTRO, FIX), (INTRO2, FIX), (INTRO2, FIX2), (INTRO, INTRO2), (OLD, FIX)}


def no_trailers(_fix):
    return []


def do_merge(index, vulns=None, cip=None, header=None, trailers=no_trailers, cites=lambda _s: ()):
    return merge(
        'CVE-2022-1', vulns, cip, header, trailers, resolve, ancestor, index, (B61, B510), cites
    )


def git_range(start: str, end: str, status: str = 'affected', kind: str = 'git') -> dict:
    """One `versions` entry of a vulns.git CVE record."""
    return {'version': start, 'lessThan': end, 'status': status, 'versionType': kind}


# -- the sources --------------------------------------------------------------


def test_branch_index_places_commits_and_knows_branch_bases(index):
    assert index.branch_of(FIX) == 'mainline'
    assert index.branch_of(BP61) == B61 and index.branch_of(BP510) == B510
    assert index.branch_of('z' * 40) is None
    assert index.in_base(OLD, B510) and index.in_base(OLD, B61)
    assert not index.in_base(FIX, B61) and not index.in_base(BP61, B61)


def test_vulns_record_splits_mainline_ranges_from_backports(index):
    versions = [
        git_range(INTRO, FIX),
        git_range(INTRO, BP61),
        git_range('0', BP510),
        git_range('6.1', '6.1.5', status='unaffected', kind='semver'),
    ]
    data = {
        'containers': {
            'cna': {
                'descriptions': [{'lang': 'en', 'value': 'In the Linux kernel ...'}],
                'affected': [{'versions': versions}],
            }
        }
    }
    view = sources.parse_vulns_record(data, index, rejected=True)
    assert view.fix == [FIX] and view.introduced == [INTRO]
    assert view.backports == {B61: [BP61], B510: [BP510]}
    assert view.rejected and view.description.startswith('In the Linux kernel')


def test_cip_issue_maps_stable_keys_and_ignores_the_rest(index):
    data = {
        'description': 'net: fix it',
        'fixed-by': {
            'mainline': [FIX],
            'stable/6.1': [BP61],
            'stable/5.10': [OLD],  # the mainline sha: fixed in the base, not a backport
            'cip/4.19': ['x' * 40],
            'ubuntu/focal': ['version:5.4.0-9.12'],
        },
        'introduced-by': {'mainline': INTRO},
        'ignore': {'all': 'This CVE was rejected upstream'},
    }
    view = sources.parse_cip_issue(data, index, (B61, B510))
    assert view.fix == [FIX] and view.introduced == [INTRO]
    assert view.backports == {B61: [BP61]}
    assert view.rejected and view.note.startswith('This CVE')
    assert sources.parse_cip_issue({'fixed-by': {'mainline': 'never'}}, index).fix == []


def test_cip_key_names_the_branch_the_way_cip_does():
    assert sources.cip_key(B61) == 'stable/6.1'
    with pytest.raises(ValueError):
        sources.cip_key('origin/master')


def test_trailers_are_taken_in_order_without_duplicates():
    msg = 'net: fix\n\nFixes: aaaa111 ("one")\nFixes: bbbb222 ("two")\nFixes: aaaa111 ("again")\n'
    assert sources.trailers_in(msg) == ['aaaa111', 'bbbb222']
    assert sources.trailers_in('no trailer') == []


# -- agreement ------------------------------------------------------------------


def test_agreeing_sources_give_an_eligible_cve_with_backports(index):
    vulns = SourceView(fix=[FIX], introduced=[INTRO], backports={B61: [BP61]})
    cip = SourceView(fix=[FIX], introduced=[INTRO], backports={B61: [BP61], B510: [BP510]})
    meta = do_merge(index, vulns, cip, trailers=lambda _f: [INTRO[:12]])
    assert isinstance(meta, CveMeta)
    assert meta.fix == FIX and meta.introduced == INTRO and meta.introduced_kind == 'meta'
    assert meta.backports == {B61: BP61, B510: BP510}
    assert meta.issues == [] and meta.eligible


def test_one_source_is_enough_and_the_trailer_fills_a_missing_anchor(index):
    meta = do_merge(index, SourceView(fix=[FIX]), trailers=lambda _f: [INTRO2[:12], INTRO[:12]])
    # The widest range: INTRO is an ancestor of INTRO2.
    assert meta.introduced == INTRO and meta.introduced_kind == 'trailer'
    assert meta.trailer_fixes == [INTRO2, INTRO]
    assert meta.eligible


def test_disagreement_is_reported_and_gates(index):
    vulns = SourceView(fix=[FIX], introduced=[INTRO])
    cip = SourceView(fix=[FIX2], introduced=[INTRO2])
    meta = do_merge(index, vulns, cip)
    assert 'fix-disagree' in meta.issues and 'introducing-disagree' in meta.issues
    assert meta.fix is None and meta.introduced is None and not meta.eligible


def test_multi_commit_cves_are_dropped(index):
    meta = do_merge(index, SourceView(fix=[FIX, FIX2], introduced=[INTRO]))
    assert 'multi-fix' in meta.issues and not meta.eligible
    meta = do_merge(index, SourceView(fix=[FIX], introduced=[INTRO, INTRO2]))
    assert 'multi-introducing' in meta.issues and not meta.eligible


def test_the_trailer_must_agree_with_the_metadata_anchor(index):
    """test_fixes will assert the rule's Fixes: is among the fix commit's trailers."""
    meta = do_merge(
        index, SourceView(fix=[FIX], introduced=[INTRO]), trailers=lambda _f: [INTRO2[:12]]
    )
    assert 'trailer-disagree' in meta.issues and not meta.eligible


def test_missing_and_unresolvable_commits_and_ancestry(index):
    assert 'no-fix' in do_merge(index, SourceView()).issues
    assert 'no-introducing' in do_merge(index, SourceView(fix=[FIX])).issues
    # Introducing commit not below the fix.
    meta = do_merge(index, SourceView(fix=[FIX2], introduced=[INTRO]))
    assert 'not-ancestor' in meta.issues and not meta.eligible
    # The initial commit needs no ancestry check.
    meta = do_merge(index, SourceView(fix=[FIX], introduced=[INITIAL_COMMIT_HASH]))
    assert 'not-ancestor' not in meta.issues and meta.eligible


def test_rejected_by_either_source_gates(index):
    meta = do_merge(index, SourceView(fix=[FIX], introduced=[INTRO]), SourceView(rejected=True))
    assert 'rejected' in meta.issues and not meta.eligible and meta.cip_rejected


def test_gold_header_is_authoritative_and_disagreement_is_report_only(index):
    header = HeaderView(fix=FIX2, fixes=INTRO2, fixes_kind='fixes', rule_path='/r/CVE-2022-1.cocci')
    vulns = SourceView(fix=[FIX], introduced=[INTRO])
    meta = do_merge(index, vulns, header=header)
    assert meta.fix == FIX2 and meta.introduced == INTRO2 and meta.introduced_kind == 'fixes'
    assert 'header-fix-disagree' in meta.issues and 'header-introducing-disagree' in meta.issues
    assert meta.eligible and meta.rule_path.endswith('.cocci')
    # But a rejected or non-ancestor gold CVE is out, rule and all.
    rejected = do_merge(index, SourceView(rejected=True), header=header)
    assert not rejected.eligible and rejected.rule_path == header.rule_path
    bad = HeaderView(fix=FIX, fixes=FIX2, fixes_kind='fixes', rule_path='/r/x.cocci')
    assert 'not-ancestor' in do_merge(index, vulns, header=bad).issues


def test_detect_to_skips_the_anchor_agreement_but_not_ancestry(index):
    header = HeaderView(fix=FIX, fixes=INTRO2, fixes_kind='detect-to', rule_path='/r/x.cocci')
    meta = do_merge(index, SourceView(fix=[FIX], introduced=[INTRO]), header=header)
    assert meta.introduced == INTRO2 and meta.introduced_kind == 'detect-to'
    assert 'header-introducing-disagree' not in meta.issues and meta.eligible
    boundary_above_fix = HeaderView(
        fix=INTRO2, fixes=FIX, fixes_kind='detect-to', rule_path='/r/x.cocci'
    )
    assert 'not-ancestor' in do_merge(index, header=boundary_above_fix).issues


def test_backport_conflicts_drop_only_that_branch(index):
    vulns = SourceView(fix=[FIX], introduced=[INTRO], backports={B61: [BP61], B510: [BP510]})
    cip = SourceView(fix=[FIX], introduced=[INTRO], backports={B61: [BP61B]})
    meta = do_merge(index, vulns, cip)
    assert meta.backports == {B510: BP510}
    assert f'backport-disagree:{B61}' in meta.issues and meta.eligible
    multi = SourceView(fix=[FIX], introduced=[INTRO], backports={B61: [BP61, BP61B]})
    meta = do_merge(index, multi)
    assert meta.backports == {} and f'backport-multi:{B61}' in meta.issues and meta.eligible
    assert f'not-affected:{B510}' in meta.issues  # informational: the bug never reached 5.10


def test_a_backport_that_cites_another_upstream_commit_is_not_the_backport(index):
    """CVE-2022-0998 on 5.10: the sources name a related fix, not this one."""
    assert sources.upstreams_of('x\n\ncommit ' + FIX + ' upstream.\n') == [FIX]
    assert sources.upstreams_of('[ Upstream commit ' + FIX2[:12] + ' ]') == [FIX2[:12]]
    assert sources.upstreams_of('(cherry picked from commit ' + FIX + ')') == [FIX]
    assert sources.upstreams_of('no citation') == []
    # A message that discusses another commit before naming its own upstream
    # cites both; the agreed fix only has to be among them.
    both = 'fixes a regression from commit ' + FIX2 + ' upstream.\n\ncommit ' + FIX + ' upstream.\n'
    assert sources.upstreams_of(both) == [FIX2, FIX]
    vulns = SourceView(fix=[FIX], introduced=[INTRO], backports={B61: [BP61], B510: [BP510]})
    meta = do_merge(index, vulns, cites=lambda _sha: [FIX2, FIX])
    assert meta.backports == {B61: BP61, B510: BP510}
    assert f'backport-other-fix:{B61}' not in meta.issues
    meta = do_merge(index, vulns, cites=lambda sha: {BP61: [FIX2[:12]], BP510: [FIX]}[sha])
    assert meta.backports == {B510: BP510}
    assert f'backport-other-fix:{B61}' in meta.issues and meta.eligible
    # A backport that cites nothing is taken at the sources' word.
    meta = do_merge(index, vulns)
    assert meta.backports == {B61: BP61, B510: BP510}


def test_a_branch_the_bug_never_reached_is_not_affected(index):
    # INTRO is not in either branch base and no backport is named: the bug is
    # newer than both branches, which is not the same as being unfixed there.
    meta = do_merge(index, SourceView(fix=[FIX], introduced=[INTRO]))
    assert f'not-affected:{B61}' in meta.issues and f'unfixed:{B61}' not in meta.issues
    # A bug present since the initial commit is on every branch.
    meta = do_merge(index, SourceView(fix=[FIX], introduced=[INITIAL_COMMIT_HASH]))
    assert f'unfixed:{B61}' in meta.issues


def test_a_fix_in_the_branch_base_needs_no_backport(index):
    meta = do_merge(index, SourceView(fix=[OLD], introduced=[INITIAL_COMMIT_HASH]))
    assert meta.backports == {}
    assert f'fixed-in-base:{B61}' in meta.issues and f'fixed-in-base:{B510}' in meta.issues
    assert meta.eligible


def test_cvemeta_round_trips_through_rows(index):
    meta = do_merge(index, SourceView(fix=[FIX], introduced=[INTRO], backports={B61: [BP61]}))
    row = meta.to_row()
    assert isinstance(row['backports'], str)
    assert CveMeta.from_row(row) == meta


def test_audit_tables_render_every_issue_with_its_values(index):
    metas = [
        do_merge(index, SourceView(fix=[FIX], introduced=[INTRO]), SourceView(fix=[FIX2])),
        do_merge(index, SourceView(fix=[FIX], introduced=[INTRO], backports={B61: [BP61]})),
    ]
    metas[1].cve = 'CVE-2022-2'
    splits = {'CVE-2022-1': 'none', 'CVE-2022-2': 'pool'}
    md = sources.audit_markdown(metas, splits, (B61, B510))
    assert '| fix-disagree | yes |' in md
    assert (
        f'| CVE-2022-1 | none | fix-disagree | {FIX[:12]} / {INTRO[:12]} | {FIX2[:12]} /  |' in md
    )
    assert f'| pool | {B61} | 1 | 0 | 0 | 0 | 0 |' in md
    rows = sources.audit_rows(metas, splits)
    assert {r['code'] for r in rows} >= {'fix-disagree', 'not-affected'}
    assert all(r['gating'] is (r['code'] in sources.GATING) for r in rows)
