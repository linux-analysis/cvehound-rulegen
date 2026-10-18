"""The CVE corpus: gold rules + merged metadata, with stored split assignment.

One row per CVE. Gold rows come from the cvehound checkout's rule files (the
editable install's own content set); every commit, date and backport comes from
data/cvemeta.parquet (rulegen.sources), the packaged archive only says `exploit`.
Splits are temporal by the fix commit's committer date and are assigned once,
here — experiments read the stored label and never recompute it.
"""

import datetime
import logging
import os

from cvehound import parse_rule_header as _cvehound_rule_header
from cvehound.util import get_cves_metadata, get_rule_cves

from rulegen import tables
from rulegen.schema import (
    SPLIT_NEWRULE,
    SPLIT_NONE,
    SPLIT_POOL,
    SPLIT_RESERVE,
    SPLIT_TEST,
    SPLIT_TRAIN,
    SPLIT_VAL,
    CveMeta,
    CveRecord,
)

log = logging.getLogger(__name__)


def _utc_ts(year: int) -> int:
    return int(datetime.datetime(year, 1, 1, tzinfo=datetime.UTC).timestamp())


# Temporal boundaries: gold train < 2023 <= val < 2024 <= test;
# unruled pool < 2023 <= reserve < 2025 <= newrule.
VAL_FROM = _utc_ts(2023)
TEST_FROM = _utc_ts(2024)
NEWRULE_FROM = _utc_ts(2025)


def parse_rule_header(path: str) -> dict[str, object]:
    """cvehound's own header parser, plus the Fixes:/Detect-To: distinction it
    folds away (last occurrence wins, like the fields themselves)."""
    meta = dict(_cvehound_rule_header(path))
    fixes_kind = None
    with open(path) as fh:
        for line in fh:
            if not line.startswith('///'):
                break
            if 'Fixes:' in line:
                fixes_kind = 'fixes'
            elif 'Detect-To:' in line:
                fixes_kind = 'detect-to'
    meta['fixes_kind'] = fixes_kind if meta.get('fixes') else None
    return meta


# The corpus table under the data directory.
CORPUS = 'cves.parquet'


def assign_split(rec: CveRecord) -> str:
    if not rec.eligible:
        # Rejected, unresolvable, non-ancestor, or the sources disagree: the
        # CVE is reported (meta_issues) and used nowhere -- gold rules included.
        return SPLIT_NONE
    if rec.has_rule:
        if not rec.cocci_rule:
            # .grep rules are out of the model's scope: not gold, but
            # not "unruled" either — they must stay out of pool/reserve/newrule.
            return SPLIT_NONE
        if not rec.fix_date:
            return SPLIT_NONE  # undatable gold rule: excluded rather than guessed
        if rec.fix_date < VAL_FROM:
            return SPLIT_TRAIN
        if rec.fix_date < TEST_FROM:
            return SPLIT_VAL
        return SPLIT_TEST
    if not rec.fix or not rec.fix_date:
        return SPLIT_NONE
    if rec.fix_date < VAL_FROM:
        return SPLIT_POOL
    if rec.fix_date < NEWRULE_FROM:
        return SPLIT_RESERVE
    return SPLIT_NEWRULE


def build_corpus(metas: list[CveMeta], metadata_path: str | None = None) -> list[CveRecord]:
    """One CveRecord per CVE from the merged sources (rulegen.sources).

    The packaged archive contributes only `exploit`; fix, introducing commit,
    rejection, dates, backports and the gold header all come from the agreed
    view, so a CVE the sources disagree on carries its issue codes here and
    lands in no split.
    """
    metadata = get_cves_metadata(metadata_path)
    _all_rules, _assigned, disputed = get_rule_cves()

    records = []
    for meta in metas:
        rec = CveRecord(
            cve=meta.cve,
            fix=meta.fix,
            fixes=meta.introduced,
            fixes_kind=meta.introduced_kind,
            cmt_subject=meta.cmt_subject,
            fix_date=meta.fix_date,
            rejected='rejected' in meta.issues,
            exploit=bool(metadata.get(meta.cve, {}).get('exploit', False)),
            backports=dict(meta.backports),
            eligible=meta.eligible,
            meta_issues=list(meta.issues),
        )
        if meta.rule_path:
            # .grep rules are recorded too (has_rule=True) so their CVEs cannot
            # masquerade as unruled; assign_split keeps them out of every split.
            rec.has_rule = True
            rec.disputed = meta.cve in disputed
            rec.rule_path = meta.rule_path
            rec.rule_version = meta.header_version
            rec.files_gold = list(meta.header_files)
        rec.split = assign_split(rec)
        records.append(rec)
    records.sort(key=lambda r: r.cve)
    log.info(
        'corpus: %d CVEs, %d eligible (%d from Fixes: trailers)',
        len(records),
        sum(r.eligible for r in records),
        sum(r.fixes_kind == 'trailer' for r in records),
    )
    return records


def save_corpus(records: list[CveRecord], path: str) -> None:
    tables.write_rows([rec.to_row() for rec in records], path)


def load_corpus(path: str) -> list[CveRecord]:
    return [CveRecord.from_row(row) for row in tables.read_rows(path)]


def load_records(data_dir: str) -> dict[str, CveRecord]:
    """The corpus of a data directory, by CVE id."""
    return {rec.cve: rec for rec in load_corpus(os.path.join(data_dir, CORPUS))}
