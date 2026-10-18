"""The sample log survives a kill mid-append, a resume does not make it worse, and rules export."""

import json

import pytest
from helpers import make_row

from rulegen.gen.log import SampleLog, export_rules


def test_truncated_final_line_is_dropped_on_read_and_cut_before_the_next_append(tmp_path):
    log = SampleLog(str(tmp_path))
    log.append([make_row(0), make_row(1)])
    with open(log.jsonl, 'rb+') as fh:
        fh.truncate(fh.seek(0, 2) - 20)  # a kill mid-write: partial last line, no newline
    assert [r['sample_index'] for r in log.rows()] == [0]
    assert log.done_keys() == {('CVE-2024-0001', 0, 0)}
    log.append([make_row(1)])  # the resume re-logs the lost row
    assert [r['sample_index'] for r in log.rows()] == [0, 1]
    with open(log.jsonl) as fh:
        assert all(json.loads(line)['run_id'] == 'r' for line in fh)  # every line is whole


def test_corruption_before_the_last_line_is_an_error(tmp_path):
    log = SampleLog(str(tmp_path))
    log.append([make_row(0), make_row(1)])
    with open(log.jsonl, 'r+') as fh:
        lines = fh.readlines()
        fh.seek(0)
        fh.truncate()
        fh.writelines([lines[0][:-10] + '\n', lines[1]])
    with pytest.raises(json.JSONDecodeError):
        log.rows()


def test_export_rules_prefers_a_valid_row_per_cve(tmp_path):
    rows = [
        make_row(0, rule_text='invalid rule\n', score={'valid': False}),
        make_row(1, rule_text='valid rule\n', score={'valid': True}),
        make_row(2, cve='CVE-2024-0002', score={'valid': False}),  # no rule: nothing to export
    ]
    run = tmp_path / 'run'
    SampleLog(str(run)).append(rows)
    written = export_rules(str(run), str(tmp_path / 'rules'))
    assert [p.rsplit('/', 1)[-1] for p in written] == ['CVE-2024-0001.cocci']
    with open(written[0]) as fh:
        assert fh.read() == 'valid rule\n'
