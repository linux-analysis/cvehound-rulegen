"""Seeded samples: quotas, era and shape strata, exclusions, nested subsets."""

import datetime as dt
import random

import pytest
from helpers import FIX

from rulegen import panel
from rulegen.schema import CveRecord
from rulegen.shapes import ShapeRecord
from rulegen.tiers import CLASSES


def ts(year: int) -> int:
    return int(dt.datetime(year, 6, 1, tzinfo=dt.UTC).timestamp())


def gold_corpus(n_per_class: int = 12) -> tuple[list[CveRecord], dict[str, str]]:
    records, classes = [], {}
    years = (2015, 2017, 2019, 2020, 2021, 2022, 2023, 2024)
    for cls in CLASSES:
        for i in range(n_per_class):
            year = years[i % len(years)]
            cve = f'CVE-{year}-{cls}{i:03d}'.replace('C2', 'X')
            split = 'train' if i % 3 else 'val'
            eligible = i != 11  # one ineligible per class
            records.append(
                CveRecord(
                    cve, fix=FIX, fix_date=ts(year), has_rule=True, split=split, eligible=eligible
                )
            )
            classes[cve] = cls
    records.append(CveRecord('CVE-2025-9999', fix=FIX, fix_date=ts(2025), split='newrule'))
    return records, classes


def shape_row(i: int, shape: str | None = None) -> ShapeRecord:
    year, sub = 2025 + (i % 2), ('drivers/net', 'fs/ext4', 'net/ipv4')[i % 3]
    shape = shape or ('adds', 'changes', 'removes', 'refactor')[i % 4]
    return ShapeRecord(f'CVE-{year}-{i:04d}', 'newrule', FIX, year, sub, shape, 1, 1, 1, [])


def test_allocate_is_deterministic_and_covers_every_stratum():
    strata = {'a': [f'a{i}' for i in range(10)], 'b': [f'b{i}' for i in range(3)], 'c': ['c0']}
    first = panel.allocate({k: list(v) for k, v in strata.items()}, 6, random.Random(0))
    again = panel.allocate({k: list(v) for k, v in strata.items()}, 6, random.Random(0))
    assert first == again and len(first) == 6
    assert any(x.startswith('b') for x in first) and 'c0' in first
    everything = panel.allocate({k: list(v) for k, v in strata.items()}, 99, random.Random(0))
    assert everything == sorted(x for v in strata.values() for x in v)


def test_largest_remainder_is_proportional_with_a_floor_of_one():
    quotas = panel.largest_remainder({'a': 10, 'b': 3, 'c': 1}, 6, ['a', 'b', 'c'])
    assert quotas == {'a': 4, 'b': 1, 'c': 1}
    # More strata than picks: every stratum keeps its floor, and the pick trims to n.
    assert panel.largest_remainder(dict.fromkeys('abcdef', 1), 3, 'abcdef') == dict.fromkeys(
        'abcdef', 1
    )


def test_sample_panel_honors_quotas_eligibility_and_exclusions():
    records, classes = gold_corpus()
    quotas = panel.parse_quota('A=4,B=6,C=2,C2=11,D=0,E=3')
    ids, report = panel.sample_panel(records, classes, quotas, seed=0, exclude={'CVE-2015-A000'})
    by_class = {cls: sum(1 for cve in ids if classes[cve] == cls) for cls in CLASSES}
    # C2 asks for 11 of the 11 eligible; D asks for none; the excluded A rule is absent.
    assert by_class == {'A': 4, 'B': 6, 'C': 2, 'C2': 11, 'D': 0, 'E': 3}
    assert 'CVE-2015-A000' not in ids and 'CVE-2025-9999' not in ids
    assert all(r.eligible for r in records if r.cve in set(ids))
    eras = {r['era'] for r in report if r['class'] == 'B' and r['picked']}
    assert len(eras) >= 3  # spread over the eras, not one slice
    assert ids == panel.sample_panel(records, classes, quotas, seed=0, exclude={'CVE-2015-A000'})[0]
    assert ids != panel.sample_panel(records, classes, quotas, seed=1, exclude={'CVE-2015-A000'})[0]


def test_nested_subset_and_year_helpers():
    records, classes = gold_corpus()
    ids, _ = panel.sample_panel(records, classes, panel.parse_quota('A=6,B=6,E=6'), seed=0)
    half = panel.nested_subset(ids, classes, 9, seed=1)
    assert len(half) == 9 and set(half) <= set(ids)
    assert {classes[c] for c in half} == {'A', 'B', 'E'}
    assert panel.year_of(ts(2019)) == 2019 and panel.year_of(0) == 0
    assert panel.era_of(2017) == '<=2018' and panel.era_of(2026) == '2023+'


def test_stratified_sample_is_deterministic_and_covers_strata():
    rows = [shape_row(i) for i in range(60)]
    picked = panel.stratified_sample(rows, n=12, seed=0)
    assert len(picked) == 12 and picked == panel.stratified_sample(rows, n=12, seed=0)
    assert picked != panel.stratified_sample(rows, n=12, seed=1)
    strata = {(r.year, r.subsystem, r.shape) for r in rows if r.cve in set(picked)}
    assert len(strata) == 12  # 24 strata, 12 picks: every pick from a different stratum
    excluded = set(picked[:4])
    assert not excluded & set(panel.stratified_sample(rows, n=12, seed=0, exclude=excluded))


@pytest.mark.parametrize('shape', ['none', 'deletes'])
def test_samples_never_draw_a_fix_no_rule_can_be_judged_on(shape):
    """No touched source, or only deleted ones: nothing fixed to be silent on."""
    rows = [shape_row(i) for i in range(30)] + [shape_row(99, shape)]
    unjudged = rows[-1].cve
    assert unjudged not in panel.stratified_sample(rows, n=30, seed=0)
    picked, report = panel.shape_panel(rows, {r.cve for r in rows}, 30, seed=0)
    assert unjudged not in picked and shape not in {r['class'] for r in report}


def test_doc_cited_cves_reads_the_public_files(tmp_path):
    (tmp_path / 'docs').mkdir()
    (tmp_path / 'docs' / 'WRITING_RULES.md').write_text('see CVE-2017-1000112 and CVE-2020-12912.')
    (tmp_path / 'contrib').mkdir()
    (tmp_path / 'contrib' / 'blank.cocci').write_text('/// CVE-2019-0001\n')
    (tmp_path / 'cvehound').mkdir()
    (tmp_path / 'cvehound' / 'CVE-2016-5195.cocci').write_text('not a doc\n')
    assert panel.doc_cited_cves(str(tmp_path)) == {
        'CVE-2017-1000112',
        'CVE-2020-12912',
        'CVE-2019-0001',
    }


def test_parse_quota_rejects_unknown_classes():
    with pytest.raises(ValueError, match='bad quota'):
        panel.parse_quota('A=1,Z=2')


def test_strata_markdown_lists_every_stratum_and_the_class_totals():
    text = panel.strata_markdown(
        't', [{'class': 'A', 'era': '<=2018', 'available': 3, 'picked': 2}]
    )
    assert '| A | <=2018 | 3 | 2 |' in text and 'Picked per class: A 2' in text
