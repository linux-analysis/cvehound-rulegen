"""The table conventions: parquet round trip, id lists, markdown, CSV file names, quantiles."""

import os

import pytest

from rulegen import tables
from rulegen.tables import Table, render_markdown, slug, write_csv


def test_parquet_round_trip_makes_the_parent_directory(tmp_path):
    path = str(tmp_path / 'a' / 'b' / 'rows.parquet')
    rows = [{'cve': 'CVE-2024-0001', 'n': 1}, {'cve': 'CVE-2024-0002', 'n': 2}]
    assert tables.write_rows(rows, path) == path
    assert tables.read_rows(path) == rows


def test_a_missing_table_names_the_command_that_builds_it(tmp_path):
    with pytest.raises(FileNotFoundError, match='rulegen shape-corpus') as err:
        tables.read_rows(str(tmp_path / 'shapes.parquet'))
    assert 'scripts/bootstrap.sh setup' in str(err.value)
    with pytest.raises(FileNotFoundError, match='rulegen build-dataset'):
        tables.read_rows(str(tmp_path / 'examples' / 'val.parquet'))
    with pytest.raises(FileNotFoundError, match='other.parquet does not exist$'):
        tables.read_rows(str(tmp_path / 'other.parquet'))


def test_markdown_renders_rows_and_the_note():
    text = render_markdown([Table('t', ['a', 'b'], [[1, None]], note='n')])
    assert text.startswith('### t\n') and '| 1 |  |' in text and '_n_' in text


def test_long_titles_keep_unique_file_names(tmp_path):
    stem = 'by context class s_valid ' + 'x' * 80
    a, b = f'{stem} -canon', f'{stem} -full'
    assert slug('Runs side by side') == 'runs-side-by-side'
    assert len(slug(a)) <= tables.SLUG_MAX and slug(a) != slug(b)
    paths = write_csv([Table(a, ['k'], [[1]]), Table(b, ['k'], [[2]])], str(tmp_path))
    assert len(set(paths)) == 2 and all(os.path.exists(p) for p in paths)


def test_id_lists_round_trip_with_their_header(tmp_path):
    path = str(tmp_path / 'lists' / 'panel.txt')
    tables.write_ids(path, ['CVE-2019-0001', 'CVE-2020-0002'], ['seed=0', 'two rules'])
    with open(path) as fh:
        assert fh.read() == '# seed=0\n# two rules\nCVE-2019-0001\nCVE-2020-0002\n'
    assert tables.read_ids(path) == {'CVE-2019-0001', 'CVE-2020-0002'}


@pytest.mark.parametrize(
    ('values', 'q', 'expected'),
    [
        ([], 0.5, None),
        ([3, 1, 2], 0.5, 2),
        ([1, 2, 3, 4], 0.5, 2),  # the lower median: a value the data holds
        (list(range(1, 11)), 0.9, 9),  # 0.9 * 10 must not round up past 9
        (list(range(1, 11)), 0.1, 1),
        ([5, 1], 1.0, 5),
        ([5, 1], 0.0, 1),
    ],
)
def test_quantile_is_nearest_rank(values, q, expected):
    assert tables.quantile(values, q) == expected
