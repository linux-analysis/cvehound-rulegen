"""Record types shared across the bench: corpus rows, examples, oracle scores."""

import dataclasses
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar

# Split labels, assigned once by corpus.assign_split and stored, never recomputed.
SPLIT_TRAIN = 'train'  # gold, fix_date < 2023
SPLIT_VAL = 'val'  # gold, 2023
SPLIT_TEST = 'test'  # gold, >= 2024
SPLIT_POOL = 'pool'  # unruled, fix_date < 2023 (expert-iteration / RL expansion)
SPLIT_RESERVE = 'reserve'  # unruled, 2023-2024 (kept out of both training and eval)
SPLIT_NEWRULE = 'newrule'  # unruled, >= 2025 (oracle-only generation eval)
SPLIT_NONE = 'none'  # rejected / no fix commit
# The rule-bearing splits, together: what `gold` means wherever a split is named.
GOLD_SPLITS = (SPLIT_TRAIN, SPLIT_VAL, SPLIT_TEST)

# The 'present since the start of git history' marker: such CVEs have no
# introducing diff, and the Fixes~ silence leg does not exist.
INITIAL_COMMIT = 'v2.6.12-rc2'
INITIAL_COMMIT_HASH = '1da177e4c3f41524e886b7f1b8a0c1fc7321cac2'

CVE_ID_RE = re.compile(r'CVE-\d{4}-\d{4,7}')

# The suite's DEFAULT_BRANCHES (cvehound tests/conftest.py): today's heads,
# scanned as information. The stable ones are also the branches whose
# backports the oracle judges (rulegen.sources.BACKPORT_BRANCHES).
DEFAULT_BRANCHES = (
    'origin/master',
    'next/master',
    'stable/linux-6.18.y',
    'stable/linux-6.12.y',
    'stable/linux-6.6.y',
    'stable/linux-6.1.y',
    'stable/linux-5.15.y',
    'stable/linux-5.10.y',
)


def _json_row(obj: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    row = dataclasses.asdict(obj)
    for key in keys:
        row[key] = json.dumps(row[key], sort_keys=True)
    return row


def _from_row(
    cls: type, row: Mapping[str, Any], keys: tuple[str, ...] = (), prefix: str = ''
) -> Any:
    """An instance of the dataclass `cls` from its row form.

    `prefix` is stripped from the keys (the sample log's `s_`), the JSON columns
    `keys` are decoded, a null JSON column keeps its default, and unknown keys
    are ignored so a row written by a newer schema still loads.
    """
    names = {f.name for f in dataclasses.fields(cls)}
    kwargs = {}
    for key, value in row.items():
        name = key.removeprefix(prefix) if key.startswith(prefix) else None
        if name not in names:
            continue
        if name in keys:
            if value is None:
                continue
            if isinstance(value, str):
                value = json.loads(value)
        kwargs[name] = value
    return cls(**kwargs)


@dataclass
class CveMeta:
    """Every source's word on one CVE, and the agreed values (rulegen.sources.merge)."""

    cve: str
    description: str = ''
    vulns_fix: list[str] = field(default_factory=list)
    vulns_introduced: list[str] = field(default_factory=list)
    vulns_backports: dict[str, list[str]] = field(default_factory=dict)
    vulns_rejected: bool = False
    cip_fix: list[str] = field(default_factory=list)
    cip_introduced: list[str] = field(default_factory=list)
    cip_backports: dict[str, list[str]] = field(default_factory=dict)
    cip_rejected: bool = False
    cip_note: str = ''
    trailer_fixes: list[str] = field(default_factory=list)  # Fixes: trailers of the agreed fix
    header_fix: str | None = None  # gold rules only
    header_fixes: str | None = None
    header_fixes_kind: str | None = None  # 'fixes' | 'detect-to'
    header_files: list[str] = field(default_factory=list)
    header_version: int = 0  # minimum spatch version from the header, 0 = any
    rule_path: str | None = None
    fix: str | None = None  # agreed fix commit (header wins for gold)
    introduced: str | None = None  # agreed introducing commit or Detect-To boundary
    introduced_kind: str | None = None  # 'fixes' | 'detect-to' | 'meta' | 'trailer'
    backports: dict[str, str] = field(default_factory=dict)  # branch -> the one fixing commit there
    fix_date: int = 0
    cmt_subject: str = ''
    issues: list[str] = field(default_factory=list)  # rulegen.sources issue codes
    eligible: bool = False

    _JSON_FIELDS: ClassVar[tuple[str, ...]] = (
        'vulns_fix',
        'vulns_introduced',
        'vulns_backports',
        'cip_fix',
        'cip_introduced',
        'cip_backports',
        'trailer_fixes',
        'header_files',
        'backports',
        'issues',
    )

    def to_row(self) -> dict[str, Any]:
        return _json_row(self, self._JSON_FIELDS)

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> 'CveMeta':
        return _from_row(cls, row, cls._JSON_FIELDS)


@dataclass
class CveRecord:
    cve: str
    fix: str | None = None
    fixes: str | None = None  # introducing commit, or Detect-To boundary
    fixes_kind: str | None = None  # 'fixes' | 'detect-to' (gold) | 'meta' | 'trailer' (unruled)
    cmt_subject: str = ''
    fix_date: int = 0
    rejected: bool = False
    exploit: bool = False
    has_rule: bool = False
    disputed: bool = False
    rule_path: str | None = None
    rule_version: int = 0  # minimum spatch version from the gold header, 0 = any
    files_gold: list[str] = field(default_factory=list)
    split: str = SPLIT_NONE
    # From data/cvemeta.parquet: the backport commit per stable branch (the
    # oracle's bp~/bp legs), and why the CVE is or is not usable.
    backports: dict[str, str] = field(default_factory=dict)
    eligible: bool = True
    meta_issues: list[str] = field(default_factory=list)

    _JSON_FIELDS: ClassVar[tuple[str, ...]] = ('backports', 'meta_issues')

    @property
    def initial_epoch(self) -> bool:
        return self.fixes in (INITIAL_COMMIT, INITIAL_COMMIT_HASH)

    @property
    def cocci_rule(self) -> bool:
        """Whether the gold rule is a semantic patch: .grep rules are out of the model's scope."""
        return bool(self.rule_path and self.rule_path.endswith('.cocci'))

    def to_row(self) -> dict[str, Any]:
        return _json_row(self, self._JSON_FIELDS)

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> 'CveRecord':
        return _from_row(cls, row, cls._JSON_FIELDS)


@dataclass
class ExampleRecord:
    """One model input, extracted deterministically from immutable git objects."""

    cve: str
    fix: str
    fixes: str | None
    initial_epoch: bool
    msg_subject: str
    msg_stripped: str
    syzbot: bool
    diff_a: str  # changed lines only (-U0, +/- payload)
    diff_b: str  # standard -U3 diff
    diff_c: str  # -W function-context diff
    diff_fallback_unrestricted: bool
    files_candidates: list[str]
    files_gold: list[str]
    historical_names: dict[str, list[str]]  # path -> older names in fixes..fix
    intermediate: list[str]  # '<sha> <subject>' lines, capped
    historical_symbols: list[str]  # identifiers seen only in in-range history
    survival_map: list[str]  # 'sym: present v4.4 v5.10 ...; absent ...' lines
    size_stats: dict[str, int]

    _JSON_FIELDS: ClassVar[tuple[str, ...]] = ('historical_names', 'size_stats')

    def to_row(self) -> dict[str, Any]:
        return _json_row(self, self._JSON_FIELDS)

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> 'ExampleRecord':
        return _from_row(cls, row, cls._JSON_FIELDS)


# Oracle verdict vocabulary for a single leg (one rule at one ref).
FIRE = 'fire'
SILENT = 'silent'
NO_FILES = 'no-files'  # none of the rule's Files: exist at the ref
ERROR = 'error'  # SpatchError; never scored as silence
TIMEOUT = 'timeout'  # SpatchTimeout; never scored as silence
TRUNCATED = 'truncated'  # SpatchTruncated: spatch dropped files mid-scan; never scored as silence
UNSUPPORTED = 'unsupported'  # rule's Version: exceeds this spatch
SKIPPED = 'skipped'
# The verdicts that are not an answer: the engine did not finish looking. Never
# silence, a hard zero on an acceptance leg, and they withhold strong_valid on
# T5/T6 because Leg.ok cannot hold for them.
HARD_VERDICTS = (TIMEOUT, ERROR, UNSUPPORTED, TRUNCATED)


def rule_sha(rule_text: str) -> str:
    """The identity of a candidate rule: same bytes, same sha, everywhere.

    The oracle's content-addressed rule file, the harness's dedup memo and
    Score.rule_sha must agree byte for byte, so they all come through here.
    """
    return hashlib.sha256(rule_text.encode()).hexdigest()


# Leg families. The name carries '<kind>:<ref>' for everything but the core
# pairs, so kind/ref are derived on construction and rows deserialize.
LEG_CORE = 'core'  # fix~ / fix / fixes / fixes~ / init
LEG_BP_PRE = 'bp~'  # T3, the stable branch just before its backport landed (must fire)
LEG_BP = 'bp'  # T3, the stable branch at its backport (must be silent)
LEG_DECOY = 'decoy'  # unrelated code served at the rule's own path
LEG_RANGE = 'range'  # T5, a tagged kernel inside Fixes..Fix~
LEG_TREE = 'tree'  # T6, the whole tree at a backport commit
LEG_HEAD = 'head'  # informational: the whole tree at today's branch head, never gating


# The ref of a backport leg is '<branch>@<sha>': the branch names the question,
# the sha records exactly which commit answered it.
def branch_of_ref(ref: str) -> str:
    return ref.partition('@')[0]


@dataclass
class Leg:
    name: str  # e.g. 'fix~', 'bp:stable/linux-6.6.y@<sha>', 'decoy:mm/slub.c', 'head:next/master'
    expect: str  # FIRE or SILENT
    verdict: str = SKIPPED
    seconds: float = 0.0
    kind: str = ''  # LEG_*; derived from the name when not given
    ref: str = ''  # what was checked: a git ref, a decoy source path, or the leg name
    # Why a hard verdict happened, in a line: the files and exception spatch
    # dropped, the budget a timeout blew, the exit code and last stderr line of a
    # crash. Empty for an answer. The engine's own stderr is otherwise discarded.
    detail: str = ''

    def __post_init__(self) -> None:
        prefix, sep, ref = self.name.partition(':')
        self.kind = self.kind or (prefix if sep else LEG_CORE)
        self.ref = self.ref or (ref if sep else self.name)

    @property
    def gating(self) -> bool:
        """Whether the leg can decide anything about the rule. Head legs are
        measured and reported (a fire there is a regression or a missing
        backport to look at) but never judge it."""
        return self.kind != LEG_HEAD

    @property
    def ok(self) -> bool:
        # No rule files at the ref means check_cve() returns False -- "not
        # detected" -- which is exactly what SILENT expects and what test_01
        # accepts on a branch predating the affected file. It never satisfies a
        # FIRE expectation, so a vulnerable ref whose files vanished still fails.
        effective = SILENT if self.verdict == NO_FILES else self.verdict
        return effective == self.expect


def leg_from_row(data: Mapping[str, Any]) -> Leg:
    """A Leg from its row form; keys this version does not know are ignored."""
    return _from_row(Leg, data)


def legs_from_json(value: Any) -> list[Leg]:
    """A Score's `legs` column, JSON text or already decoded, as Leg objects."""
    data = json.loads(value) if isinstance(value, str) else (value or [])
    return [leg if isinstance(leg, Leg) else leg_from_row(leg) for leg in data]


@dataclass
class Score:
    cve: str
    rule_sha: str
    rule_path: str = ''
    t0_failures: list[str] = field(default_factory=list)
    t1_parse: bool | None = None
    t1_grep_query: bool | None = None  # False = 'no inferred keywords'
    # What the text says about the bug, read at T0 (rulegen.tiers): a literal
    # name somewhere in the rule, and metavariables standing where a name
    # belongs on a report line. None / empty when the oracle never read the rule.
    t0_anchored: bool | None = None
    t0_wildcards: list[str] = field(default_factory=list)
    t4_unrelated_files: int | None = None  # lib/ probe survivors; None = not run or unanswered
    legs: list[Leg] = field(default_factory=list)
    # none | contract | structure | parse | error | timeout | truncated | unsupported | harness
    # 'contract' is set by the generation harness when a completion carries no
    # rule at all; 'harness' when scoring itself crashed (the Score is then a
    # placeholder that earns nothing, so a batch never loses its siblings).
    fail_class: str = 'none'
    reward: float = 0.0
    valid: bool = False
    wall_seconds: float = 0.0
    # Diagnostics and the optional tiers beyond acceptance. All scalar, so
    # to_row() keeps producing a flat parquet-ready dict.
    t1_stderr: str = ''  # spatch --parse-cocci stderr when t1_parse is False (repair feedback)
    t5_mode: str = ''  # T5 enumeration: 'tags' or 'commits' (the suite's --between-mode)
    t5_points: int | None = None  # T5 range sweep: distinct blob signatures checked in Fixes..Fix~
    t5_fired: int | None = None
    t6_trees: int | None = None  # T6 whole-tree scans run at backport commits
    t6_fired: int | None = None
    head_checked: int | None = None  # informational whole-tree scans at today's branch heads
    head_fires: int | None = None
    # Legs whose scan spatch did not finish (it dropped files and exited 0). An
    # environment fault, not the rule's: None when the oracle never ran.
    truncated_legs: int | None = None
    cost_prefilter_files: int | None = None  # files surviving the grep query on the cost tree
    cost_cpu_seconds: float | None = None  # one whole-tree scan, user+sys CPU
    cost_wall_seconds: float | None = None
    # valid AND selective (T4 == 0 or not run) AND fires at every range point AND
    # silent on every whole tree. False whenever any of those legs errored.
    strong_valid: bool = False
    # Set when a post-acceptance tier (T5/T6/cost) crashed in the harness rather
    # than judging the rule: strong_valid is then withheld, not earned or lost.
    strong_error: str = ''
    # Why the harness never asked the oracle (contract violation, adapter error,
    # crash). Distinct from t1_stderr, which is spatch's own parse output.
    note: str = ''

    # List fields are stored as JSON strings in a row so the row stays flat.
    _JSON_FIELDS: ClassVar[tuple[str, ...]] = ('legs', 't0_failures', 't0_wildcards')

    @classmethod
    def unscored(cls, cve: str, rule_text: str, fail_class: str, note: str = '') -> 'Score':
        """A zero Score for a candidate the oracle never ran on."""
        return cls(cve=cve, rule_sha=rule_sha(rule_text), fail_class=fail_class, note=note[:2000])

    def leg(self, name: str) -> Leg | None:
        return next((leg for leg in self.legs if leg.name == name), None)

    def legs_of(self, kind: str) -> list[Leg]:
        return [leg for leg in self.legs if leg.kind == kind]

    def to_row(self) -> dict[str, Any]:
        row = dataclasses.asdict(self)
        # An answer carries no detail; leaving the empty key out keeps a log of
        # a hundred thousand rows from paying for it on every leg.
        for leg in row['legs']:
            if not leg['detail']:
                del leg['detail']
        for key in self._JSON_FIELDS:
            row[key] = json.dumps(row[key], sort_keys=True)
        return row

    @classmethod
    def from_row(cls, row: Mapping[str, Any], prefix: str = '') -> 'Score':
        """Inverse of to_row(); `prefix` strips e.g. the sample log's `s_`. Unknown keys are ignored."""
        score = _from_row(cls, row, cls._JSON_FIELDS, prefix)
        score.legs = legs_from_json(score.legs)
        return score


@dataclass(frozen=True)
class ScoreRequest:
    """One candidate rule for the oracle, and the commits that frame its question."""

    cve: str
    fix: str
    fixes: str | None
    initial_epoch: bool
    rule_text: str
    # (branch, backport commit) pairs from the corpus (CveRecord.backports):
    # the T3 legs. Hashable so the request pickles through the spawn pool.
    backports: tuple[tuple[str, str], ...] = ()

    @classmethod
    def for_record(cls, rec: CveRecord, rule_text: str) -> 'ScoreRequest':
        """The request judging `rule_text` against the corpus row of its CVE."""
        backports = tuple(sorted((rec.backports or {}).items()))
        return cls(rec.cve, rec.fix or '', rec.fixes, rec.initial_epoch, rule_text, backports)
