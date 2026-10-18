"""The oracle's pure parts: the T0 contract, verdicts, leg specs, range points, the grade,
the cost scan and the address-space cap. No spatch and no kernel clone."""

import logging
import multiprocessing as mp
import os
import resource
import types

import pytest
from cvehound.exception import SpatchError, SpatchTimeout, SpatchTruncated, UnsupportedVersion
from helpers import B61, B510, FIX, FIXES, KFREE, SHA1, SHA2

from rulegen.oracle import reward
from rulegen.oracle.reward import (
    CORE_LEGS,
    VALID_FLOOR,
    WEIGHTS,
    backport_specs,
    core_specs,
    grade,
    judge,
    range_points,
    range_refs,
    structure_failures,
)
from rulegen.promptbuild import finalize_rule
from rulegen.schema import (
    ERROR,
    FIRE,
    INITIAL_COMMIT,
    NO_FILES,
    SILENT,
    TIMEOUT,
    TRUNCATED,
    UNSUPPORTED,
    Leg,
    Score,
)

# -- T0: the rule contract ----------------------------------------------------------

RULE = finalize_rule(KFREE, FIX, FIXES, 'fixes')


def test_a_finalized_rule_meets_the_contract():
    assert structure_failures(RULE) == []
    assert structure_failures(RULE.replace('/// Fixes:', '/// Detect-To:')) == []
    # `when exists` on an ellipsis is a real construct, unlike `exists` in a header.
    assert structure_failures(RULE.replace('*\tkfree', '\t... when exists\n*\tkfree')) == []


@pytest.mark.parametrize(
    ('old', 'new', 'failure'),
    [
        # cvehound defines no virtual rule, so anything gated on one never runs.
        ('@r@', 'virtual detect\n\n@r@', 'virtual'),
        ('@r@', 'virtual patch\n\n@r@', 'virtual'),
        # A header `exists` is a no-op: a starred rule already matches on some path.
        ('@r@', '@r exists@', 'exists'),
        ('@r@', '@ exists @', 'exists'),
        (f'/// Fixes: {FIXES}\n', '', 'Fixes: or Detect-To:'),
        ('/// Fixes:', '/// Detect-To: dddd\n/// Fixes:', 'Detect-To'),
        ('/// Files:', '/// Filez:', 'Files:'),
        ('*\tkfree(sk);', '\tkfree(sk);', 'starred'),
        ('*\tkfree(sk);', '*\t}', 'brace'),
        ('}\n', '}\n\n@script:python@\n@@\nprint(1)\n', 'script:python'),
    ],
)
def test_each_contract_violation_is_named(old, new, failure):
    assert any(failure in f for f in structure_failures(RULE.replace(old, new)))


def test_a_foreign_cve_id_is_rejected_only_when_the_rule_names_another():
    body = RULE.replace('@r@', '// see CVE-2020-1234\n@r@')
    assert structure_failures(body) == []  # no id to compare against
    assert structure_failures(body, 'CVE-2020-1234') == []
    assert any('CVE-2020-1234' in f for f in structure_failures(body, 'CVE-2021-9'))


# -- verdicts --------------------------------------------------------------------------

TORN = 'Failure("input_value: truncated object")'


def raising(err: Exception):
    def check() -> str:
        raise err

    return check


@pytest.mark.parametrize(
    ('err', 'verdict', 'detail'),
    [
        # Subclasses before SpatchError, or a truncation reads as a crash.
        (
            SpatchTruncated('C', '/k', 0, '', [(TORN, 'net/a.c')]),
            TRUNCATED,
            f'dropped net/a.c: {TORN}',
        ),
        (SpatchTruncated('C', '/k', 0, '', [], retried=True), TRUNCATED, 'unnamed files'),
        (SpatchTimeout('C', '/k', 0, '', 60, ['a.c']), TIMEOUT, '60 CPU-s on a.c'),
        (SpatchTimeout('C', '/k', -9, '', 300, wall=True), TIMEOUT, 'wall 300s'),
        (
            SpatchError('C', '/k', 2, 'noise\nFatal error: exception Sys_error("x")\n'),
            ERROR,
            'rc 2: Fatal error: exception Sys_error("x")',
        ),
        (UnsupportedVersion(132, 'C', 140), UNSUPPORTED, 'needs spatch >= 1.4.0'),
    ],
)
def test_each_engine_failure_has_its_verdict_and_a_reason(err, verdict, detail, caplog):
    with caplog.at_level(logging.WARNING, logger='rulegen.oracle.diag'):
        leg = judge('tree:stable/linux-5.15.y@abc', SILENT, raising(err), cve='CVE-2022-50071')
    assert leg.verdict == verdict and not leg.ok
    assert detail in leg.detail and len(leg.detail) <= 240
    # One diagnostic line per hard verdict, naming the CVE and the leg.
    assert 'CVE-2022-50071 tree:stable/linux-5.15.y@abc' in caplog.text


def test_an_answer_carries_no_detail_and_logs_nothing(caplog):
    with caplog.at_level(logging.WARNING, logger='rulegen.oracle.diag'):
        leg = judge('fix~', FIRE, lambda: FIRE, cve='C')
    assert leg.ok and leg.detail == '' and caplog.text == ''


@pytest.mark.parametrize(
    ('stderr', 'files'),
    [
        ('warning: ...\n12 files match\nrest', 12),
        ('1 file match', 1),
        ('no inferred keywords\n99 files match', None),
        ('nothing useful', None),
    ],
)
def test_files_match_reads_the_prefilter_count(stderr, files):
    assert reward._files_match(stderr) == files


# -- which legs a rule is judged on ---------------------------------------------------


def always(_ref: str) -> bool:
    return True


@pytest.mark.parametrize(
    ('fixes', 'initial_epoch', 'resolvable', 'names'),
    [
        # test_02's negative half joins the acceptance legs for a normal CVE.
        ('fixessha', False, always, ['fix~', 'fix', 'fixes', 'fixes~', 'init']),
        # The initial commit *is* the vulnerable state: `fixes` already covers it.
        (INITIAL_COMMIT, True, always, ['fix~', 'fix', 'fixes']),
        # Refs the clone cannot resolve get no leg.
        ('fixessha', False, lambda _ref: False, ['fix~', 'fix']),
    ],
)
def test_core_specs(fixes, initial_epoch, resolvable, names):
    specs = core_specs('fixsha', fixes, initial_epoch, resolvable)
    assert [name for _ref, name, _expect in specs] == names
    assert all(name in CORE_LEGS and name in WEIGHTS for name in names)
    expect = {'fix~': FIRE, 'fix': SILENT, 'fixes': FIRE, 'fixes~': SILENT, 'init': SILENT}
    assert [e for _ref, _name, e in specs] == [expect[name] for name in names]
    if 'init' in names:
        assert specs[-1][0] == INITIAL_COMMIT


def test_backport_specs_pair_each_branch_and_carry_the_commit():
    specs = backport_specs(((B61, SHA1), (B510, SHA2)), resolvable=always)
    assert specs == [
        (f'{SHA1}~', f'bp~:{B61}@{SHA1}', FIRE),
        (SHA1, f'bp:{B61}@{SHA1}', SILENT),
        (f'{SHA2}~', f'bp~:{B510}@{SHA2}', FIRE),
        (SHA2, f'bp:{B510}@{SHA2}', SILENT),
    ]
    assert all(Leg(name, expect).gating for _ref, name, expect in specs)
    # What the clone cannot resolve gets no leg.
    assert backport_specs(((B61, SHA1),), resolvable=lambda r: r == SHA1) == []
    assert backport_specs(((B61, ''),), resolvable=always) == []


class FakeGit:
    """Records the argv it was called with and replays a canned answer."""

    def __init__(self, tags: str = '', commits: str = '') -> None:
        self.tags, self.commits = tags, commits
        self.calls: list[tuple[str, tuple]] = []

    def tag(self, *args: str) -> str:
        self.calls.append(('tag', args))
        return self.tags

    def log(self, *args: str) -> str:
        self.calls.append(('log', args))
        return self.commits


def ctx_with(sigs: dict | None = None, git: FakeGit | None = None) -> types.SimpleNamespace:
    """Just the parts of an OracleCtx the range functions read."""
    return types.SimpleNamespace(
        materializer=types.SimpleNamespace(sig=lambda ref, _files: sigs[ref]),
        repo=types.SimpleNamespace(git=git),
    )


def test_range_points_dedupe_exclude_and_subsample_deterministically():
    # 30 tags, the files change every 3 tags -> 10 distinct signatures; the first
    # one is the already-checked `fixes` signature, one has no rule files.
    sigs = {f'v{i}': (('a.c', f'blob{i // 3}'),) for i in range(30)}
    sigs['v15'] = ()  # files vanished at this tag: an empty signature
    ctx, refs = ctx_with(sigs), [f'v{i}' for i in range(30)]
    points = range_points(ctx, refs, ['a.c'], exclude={sigs['v0']}, max_points=16)
    assert [ref for ref, _sig in points] == [
        'v3',
        'v6',
        'v9',
        'v12',
        'v16',
        'v18',
        'v21',
        'v24',
        'v27',
    ]
    capped = range_points(ctx, refs, ['a.c'], exclude=set(), max_points=4)
    assert capped == range_points(ctx, refs, ['a.c'], exclude=set(), max_points=4)
    assert [ref for ref, _sig in capped] == ['v0', 'v6', 'v16', 'v21']


def test_range_points_uncapped_keeps_every_distinct_signature():
    """`max_points=0` is the suite's own coverage: no subsampling at all."""
    sigs = {f'v{i}': (('a.c', f'blob{i}'),) for i in range(40)}
    points = range_points(ctx_with(sigs), list(sigs), ['a.c'], exclude=set(), max_points=0)
    assert [ref for ref, _sig in points] == list(sigs)


def test_range_refs_tags_mode_asks_git_tag():
    git = FakeGit(tags='v5.10 v5.11\nv5.12\n')
    assert range_refs(ctx_with(git=git), 'fixsha', 'fixessha', ['a.c'], 'tags') == [
        'v5.10',
        'v5.11',
        'v5.12',
    ]
    kind, args = git.calls[0]
    assert kind == 'tag' and '--contains' in args and 'fixessha' in args
    assert '--merged' in args and 'fixsha~' in args


def test_range_refs_commits_mode_walks_the_ancestry_path_oldest_first():
    """test_05's --between-mode=commits: every non-merge commit touching the files."""
    git = FakeGit(commits='newest\nmiddle\noldest\n')
    refs = range_refs(ctx_with(git=git), 'fixsha', 'fixessha', ['a.c', 'b.c'], 'commits')
    assert refs == ['oldest', 'middle', 'newest']  # git log is newest first
    assert git.calls[0] == (
        'log',
        ('--format=%H', '--no-merges', '--ancestry-path', 'fixessha..fixsha~', '--', 'a.c', 'b.c'),
    )
    with pytest.raises(ValueError, match='range mode'):
        range_refs(ctx_with(git=git), 'fix', 'fixes', ['a.c'], 'weekly')


# -- the grade -----------------------------------------------------------------------


def scored(legs, t0_ok=True, t1_parse=True, has_query=True) -> Score:
    score = Score(cve='CVE-2022-1', rule_sha='x', legs=list(legs))
    score.t0_failures = [] if t0_ok else ['bad']
    score.t1_parse, score.t1_grep_query = t1_parse, has_query
    return score


def core(ok: bool = True) -> list[Leg]:
    return [
        Leg('fix~', FIRE, FIRE),
        Leg('fix', SILENT, SILENT if ok else FIRE),
        Leg('fixes', FIRE, FIRE),
        Leg('fixes~', SILENT, SILENT),
        Leg('init', SILENT, NO_FILES),
    ]


def acceptance_legs(verdict_of) -> list[Leg]:
    """Every acceptance leg a pool CVE with one backport has, verdicts by expectation."""
    specs = core_specs(FIX, FIXES, False, always) + backport_specs(((B61, SHA1),), always)
    legs = [Leg(name, expect, verdict_of(expect)) for _ref, name, expect in specs]
    return legs + [Leg(f'decoy:d{i}', SILENT, verdict_of(SILENT)) for i in range(8)]


def test_grade_without_backports_renormalises_to_the_old_total():
    g = grade(scored(core()))
    assert g.valid and g.hard_zero is None and g.reward == 1.0
    # A vacuous init silence neither earns nor costs.
    assert set(g.available) == {
        'structure',
        'parse',
        'grep_query',
        'fix~',
        'fix',
        'fixes',
        'fixes~',
    }


def test_grade_backport_legs_share_one_weight_and_gate():
    legs = core() + [
        Leg(f'bp~:{B61}@{SHA1}', FIRE, FIRE),
        Leg(f'bp:{B61}@{SHA1}', SILENT, SILENT),
        Leg(f'bp~:{B510}@{SHA2}', FIRE, SILENT),  # the backport spells it differently
        Leg(f'bp:{B510}@{SHA2}', SILENT, SILENT),
    ]
    g = grade(scored(legs))
    assert not g.valid and g.available['backports'] == WEIGHTS['backports']
    # One branch answered as a pair, the other did not: half, not three legs of four.
    assert g.earned['backports'] == WEIGHTS['backports'] / 2
    # A vacuous silence at the backport (files gone there) neither earns nor costs.
    vacuous = core() + [
        Leg(f'bp~:{B61}@{SHA1}', FIRE, FIRE),
        Leg(f'bp:{B61}@{SHA1}', SILENT, NO_FILES),
    ]
    g = grade(scored(vacuous))
    assert g.valid and g.earned['backports'] == WEIGHTS['backports']
    # But no files before the backport is a miss: the vulnerable stable tree was not seen.
    missing = core() + [
        Leg(f'bp~:{B61}@{SHA1}', FIRE, NO_FILES),
        Leg(f'bp:{B61}@{SHA1}', SILENT, SILENT),
    ]
    assert not grade(scored(missing)).valid


def test_grade_ignores_head_legs_entirely():
    loud = core() + [
        Leg(f'head:origin/master@{SHA1}', SILENT, FIRE),
        Leg(f'head:{B61}@{SHA2}', SILENT, TIMEOUT),
    ]
    a, b = grade(scored(core())), grade(scored(loud))
    assert a.valid and b.valid and a.reward == b.reward and b.hard_zero is None


@pytest.mark.parametrize('verdict', [TIMEOUT, TRUNCATED])
def test_an_unfinished_check_is_hard_on_acceptance_and_shaping_after_it(verdict):
    """A scan the engine did not finish is never a silence: on an acceptance leg it is
    a hard zero, after acceptance it withholds credit (Leg.ok cannot hold) but never
    validity."""
    g = grade(scored(core() + [Leg(f'bp:{B61}@{SHA1}', SILENT, verdict)]))
    assert g.hard_zero == verdict and g.reward == 0.0 and not g.valid
    late = core() + [Leg('range:v6.1', FIRE, verdict), Leg(f'tree:{B61}@{SHA1}', SILENT, verdict)]
    g = grade(scored(late))
    assert g.hard_zero is None and g.valid and g.reward < 1.0
    assert 'era' not in g.earned and 'tree' not in g.earned


def test_grade_orders_dead_below_over_broad_below_perfect():
    dead = grade(scored(acceptance_legs(lambda _expect: SILENT)))
    loud = grade(scored(acceptance_legs(lambda _expect: FIRE)))
    perfect = grade(scored(acceptance_legs(lambda expect: expect)))
    assert not dead.valid and not loud.valid and perfect.valid
    assert dead.reward < loud.reward < VALID_FLOOR < perfect.reward == 1.0
    # A rule that matches nothing earns the format credit and not one silence;
    # invalid rules share the band below the floor.
    assert set(dead.earned) == {'structure', 'parse', 'grep_query'}
    assert dead.reward == round(VALID_FLOOR * 0.20 / 1.05, 4)
    assert loud.reward == round(VALID_FLOOR * 0.50 / 1.05, 4)


def test_valid_is_a_floor_no_invalid_rule_reaches():
    """The post-acceptance tiers run only on valid rules, so one ratio over everything
    would let an invalid rule that never paid for them outscore a valid one that failed them."""
    one_decoy = acceptance_legs(lambda expect: expect)
    one_decoy[-1] = Leg('decoy:d7', SILENT, FIRE)
    nearly = grade(scored(one_decoy))
    weak = scored(
        acceptance_legs(lambda expect: expect)
        + [
            Leg('range:v6.1', FIRE, SILENT),
            Leg('range:v6.2', FIRE, SILENT),
            Leg(f'tree:{B61}@{SHA1}', SILENT, FIRE),
        ]
    )
    weak.t4_unrelated_files = 3
    weak.t0_anchored, weak.t0_wildcards = False, ['f']
    assert not nearly.valid and grade(weak).valid
    assert nearly.reward < VALID_FLOOR == grade(weak).reward  # nothing above the floor earned
    weak.legs[-3] = Leg('range:v6.1', FIRE, FIRE)
    assert VALID_FLOOR < grade(weak).reward < 1.0


def test_silence_credit_needs_the_paired_fire():
    legs = [
        Leg('fix~', FIRE, SILENT),
        Leg('fix', SILENT, SILENT),
        Leg('fixes', FIRE, SILENT),
        Leg('fixes~', SILENT, SILENT),
        Leg('init', SILENT, SILENT),
        Leg('decoy:d0', SILENT, SILENT),
    ]
    g = grade(scored(legs))
    assert not g.valid and set(g.earned) == {'structure', 'parse', 'grep_query'}
    assert {'fix', 'init', 'fixes~', 'decoys'} <= set(g.available)
    # fixes~ is fixes's silence, not fix~'s: it counts once fixes fires.
    legs[2] = Leg('fixes', FIRE, FIRE)
    g = grade(scored(legs))
    assert {'fixes', 'fixes~'} <= set(g.earned)
    assert not {'fix', 'init', 'decoys'} & set(g.earned)


def test_post_acceptance_tiers_shape_the_reward_only_when_they_ran():
    plain = grade(scored(core()))
    assert plain.reward == 1.0 and {'selective', 'era', 'tree'}.isdisjoint(plain.available)
    ran = scored(
        core()
        + [
            Leg('range:v6.1', FIRE, FIRE),
            Leg('range:v6.2', FIRE, SILENT),
            Leg(f'tree:{B61}@{SHA1}', SILENT, SILENT),
        ]
    )
    ran.t4_unrelated_files = 3
    g = grade(ran)
    assert g.valid  # never validity
    assert g.earned['era'] == WEIGHTS['era'] / 2 and g.earned['tree'] == WEIGHTS['tree']
    assert 'selective' in g.available and 'selective' not in g.earned and g.reward < 1.0
    ran.t4_unrelated_files = 0
    ran.legs[-2] = Leg('range:v6.2', FIRE, FIRE)
    assert grade(ran).reward == 1.0


def test_text_terms_are_graded_once_read():
    assert 'anchored' not in grade(scored(core())).available  # scored before the fields existed
    s = scored(core())
    s.t0_anchored, s.t0_wildcards = False, ['f']
    g = grade(s)
    assert g.valid and {'anchored', 'specific_star'} <= set(g.available)
    assert not {'anchored', 'specific_star'} & set(g.earned) and g.reward < 1.0
    s.t0_anchored, s.t0_wildcards = True, []
    assert grade(s).reward == 1.0


def test_grade_stops_at_structure_and_parse():
    g = grade(scored([], t0_ok=False, t1_parse=None, has_query=False))
    assert g.reward == 0.0 and not g.valid
    g = grade(scored([], t1_parse=False, has_query=False))
    assert g.earned == {'structure': WEIGHTS['structure']} and not g.valid
    g = grade(scored(core(ok=False), has_query=False))
    assert not g.valid and 'grep_query' not in g.earned and 'fix' not in g.earned


# -- the cost scan, the parse cache and the address-space cap -------------------------


class FakeSpatch:
    """A Popen stand-in that 'scans' by printing the given stderr and exiting 0."""

    def __init__(self, stderr: str) -> None:
        self.stderr_text, self.returncode, self.pid = stderr, 0, -1

    def __call__(self, *_args, **_kwargs) -> 'FakeSpatch':
        return self

    def communicate(self, timeout=None) -> tuple[None, str]:
        return None, self.stderr_text


SUMMARY = (
    'SPATCH-SUMMARY groups=2 handled=1 skipped=1 dropped={d} timeouts=0 unreadable={u} '
    'cache_healed=0\n'
)


@pytest.mark.parametrize(
    ('stderr', 'features', 'measured'),
    [
        ('100 files match\n', (), True),
        # A dropped file under-counts the cost exactly as a dropped timeout does.
        (
            f'EXN: {TORN} in /t/a.c\nAn error occurred when attempting to transform some files.\n',
            (),
            False,
        ),
        # A build that reports its scans is held to the report.
        ('100 files match\n' + SUMMARY.format(d=0, u=0), ('summary',), True),
        ('100 files match\n', ('summary',), False),
        (
            'SPATCH-DROP kind=unreadable reason="prefilter" file=/t/b.c\n'
            + SUMMARY.format(d=1, u=1),
            ('summary',),
            False,
        ),
    ],
    ids=['complete', 'truncated', 'summary-complete', 'summary-missing', 'summary-unreadable'],
)
def test_cost_scan_never_records_a_truncated_scan_as_a_cost(
    tmp_path, monkeypatch, stderr, features, measured
):
    ctx = types.SimpleNamespace(
        worktree=lambda _ref: str(tmp_path),
        work_root=str(tmp_path),
        hound=types.SimpleNamespace(spatch='spatch', features=frozenset(features)),
    )
    monkeypatch.setattr(reward.subprocess, 'Popen', FakeSpatch(stderr))
    rec = reward._cost_scan(ctx, 'r.cocci', jobs=1, wall=10)
    assert rec['truncated'] is (not measured)
    assert (rec['cpu_seconds'] is not None) is measured


def test_the_parse_cache_lives_under_the_work_root(monkeypatch, tmp_path):
    """No knob: every context parses into <work_root>/astcache/<spatch build>."""
    seen = {}

    def fake_hound(kernel, zygote=None, ast_cache=None):
        seen['ast_cache'] = ast_cache
        return types.SimpleNamespace(spatch='/bin/true', zygote=None)

    monkeypatch.setattr(reward, 'CVEhound', fake_hound)
    monkeypatch.setattr(reward, 'verdict_identity', lambda _hound: 'id')
    monkeypatch.setattr('cvehound.util.find_spatch', lambda _p: '/bin/true')
    monkeypatch.setattr('cvehound.util.spatch_identity', lambda _s: 'build-1')
    reader = types.SimpleNamespace(git=object())
    monkeypatch.setattr(reward, 'BlobMaterializer', lambda *_a, **_k: reader)
    monkeypatch.setattr(reward.antigaming, 'decoy_blobs', lambda *_a, **_k: [])
    monkeypatch.setattr('git.Repo', lambda *_a, **_k: reader)
    reward.make_ctx('/k', str(tmp_path), (), use_cache=False)
    assert seen['ast_cache'].startswith(str(tmp_path / 'astcache') + os.sep)
    assert os.path.isdir(seen['ast_cache'])
    # One build always lands in the same place; entries never cross builds.
    assert reward.astcache_path(str(tmp_path), '/bin/true') == seen['ast_cache']


def test_the_verdict_identity_ignores_the_parse_cache():
    """Toggling the AST cache must not orphan the verdicts it cannot change."""
    plain = types.SimpleNamespace(spatch='/bin/echo', zygote=None)
    cached = types.SimpleNamespace(spatch='/bin/echo', zygote=None, ast_cache='/w/astcache/b1')
    assert reward.verdict_identity(plain) == reward.verdict_identity(cached)


def capped_child(queue) -> None:
    """Module level so a spawn-context Process can pickle it."""
    reward.limit_address_space(4 * 1024**3)
    # What a grandchild (the zygote, a whole-tree scan) would inherit.
    queue.put(resource.getrlimit(resource.RLIMIT_AS))


def test_address_space_limit_is_inherited_by_children():
    """The cap must sit on the worker: cvehound forks the spatch zygote, not us."""
    ctx = mp.get_context('spawn')
    queue = ctx.Queue()
    proc = ctx.Process(target=capped_child, args=(queue,))
    proc.start()
    soft, _hard = queue.get(timeout=60)
    proc.join(timeout=60)
    assert soft == 4 * 1024**3
    # The test process itself keeps whatever it had.
    assert resource.getrlimit(resource.RLIMIT_AS)[0] != 4 * 1024**3
