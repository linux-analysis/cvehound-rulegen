"""The command line: missing inputs, and what a gold replay calls each Score."""

import pytest
from helpers import B61, B510, SHA1, SHA2

from rulegen import cli, corpus
from rulegen.cli.oracle import replay_status
from rulegen.schema import FIRE, SILENT, TRUNCATED, Leg, Score


def test_a_missing_input_is_one_line_naming_what_builds_it(tmp_path, capsys):
    corpus.save_corpus([], str(tmp_path / 'cves.parquet'))
    assert cli.main(['--data', str(tmp_path), 'coverage', '--split', 'val']) == 1
    err = capsys.readouterr().err.strip()
    assert err.startswith('rulegen coverage: ') and len(err.splitlines()) == 1
    assert 'examples/val.parquet does not exist' in err and 'rulegen build-dataset' in err


def test_verbose_keeps_the_traceback(tmp_path):
    corpus.save_corpus([], str(tmp_path / 'cves.parquet'))
    with pytest.raises(FileNotFoundError):
        cli.main(['--data', str(tmp_path), '-v', 'coverage', '--split', 'val'])


CORE = [Leg('fix~', FIRE, FIRE), Leg('fix', SILENT, SILENT)]
BP_SILENT = Leg(f'bp:{B61}@{SHA1}', SILENT, SILENT)


@pytest.mark.parametrize(
    ('fail_class', 'legs', 'status', 'bad'),
    [
        ('none', CORE, 'ok', []),
        ('none', [CORE[0], Leg('fix', SILENT, FIRE)], 'FAIL', ['fix']),
        ('timeout', CORE, 'FAIL', []),
        # spatch did not finish: still unexpected, but named for what it is.
        (TRUNCATED, CORE, 'TRUNCATED', []),
        ('none', [*CORE, Leg('range:v6.1', FIRE, TRUNCATED)], 'TRUNCATED', ['range:v6.1']),
        # A head fire is information; after a silent backport it may be a regression.
        ('none', [*CORE, Leg(f'head:{B510}@{SHA2}', SILENT, FIRE)], 'head-fire', []),
        (
            'none',
            [*CORE, BP_SILENT, Leg(f'head:{B61}@{SHA2}', SILENT, FIRE)],
            'head-fire-after-backport',
            [],
        ),
    ],
)
def test_replay_status(fail_class, legs, status, bad):
    score = Score(cve='CVE-2024-1', rule_sha='x', fail_class=fail_class, legs=list(legs))
    assert replay_status(score)[:2] == (status, bad)
