"""The shared SQLite verdict/probe store and the heavy-scan slots — no spatch."""

import multiprocessing as mp
import os

from cvehound.oracle.resultcache import ResultCache

from rulegen.oracle import verdicts


def _rows(cache: verdicts.SqliteVerdictCache) -> int:
    return cache.conn.execute(
        'SELECT COUNT(*) FROM verdicts WHERE ctx = ?', (cache.ctx,)
    ).fetchone()[0]


def test_keys_match_result_cache_byte_for_byte(tmp_path):
    rule = tmp_path / 'r.cocci'
    rule.write_text('/// Files: a.c\n@r@\n@@\n* x();\n')
    sig = (('a.c', 'oid1'), ('include/linux/kconfig.h', 'oidk'))
    old = ResultCache(str(tmp_path / 'rc'), 'spatch-x')
    new = verdicts.SqliteVerdictCache(str(tmp_path / 'db'), 'spatch-x')
    assert old.key(str(rule), sig) == new.key(str(rule), sig)
    assert old.dir.endswith(new.ctx)  # same context id derivation


def test_get_put_hits_misses_and_context_isolation(tmp_path):
    a = verdicts.SqliteVerdictCache(str(tmp_path), 'spatch-a')
    b = verdicts.SqliteVerdictCache(str(tmp_path), 'spatch-b')
    assert a.get('k1') is None and a.misses == 1
    a.put('k1', True)
    assert a.get('k1') is True and a.hits == 1
    assert b.get('k1') is None  # another spatch build never sees it
    a.put('k1', False)  # replace
    assert a.get('k1') is False and _rows(a) == 1


def test_probe_store_shares_the_file(tmp_path):
    cache = verdicts.SqliteVerdictCache(str(tmp_path), 'spatch-x')
    probes = verdicts.ProbeStore(str(tmp_path), cache.conn)
    assert probes.get('p1') is None
    probes.put('p1', {'key': 'p1', 'parse': True})
    probes.put('p1', {'key': 'p1', 'parse': False})  # replace
    assert verdicts.ProbeStore(str(tmp_path)).get('p1') == {'key': 'p1', 'parse': False}


def _writer(root: str, worker: int) -> None:
    cache = verdicts.SqliteVerdictCache(root, 'spatch-x', worker=f'w{worker}')
    for i in range(200):
        cache.put(f'w{worker}-{i}', i % 2 == 0)
    cache.close()


def test_two_processes_write_the_same_file(tmp_path):
    root = str(tmp_path)
    ctx = mp.get_context('spawn')
    procs = [ctx.Process(target=_writer, args=(root, w)) for w in range(2)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    cache = verdicts.SqliteVerdictCache(root, 'spatch-x')
    assert _rows(cache) == 400 and cache.get('w1-3') is False


def test_heavy_slots_bound_concurrency(tmp_path):
    slots = verdicts.HeavySlots(str(tmp_path), 1, poll_s=0.01)
    with slots.acquire() as a:
        assert a == 0
        try:
            with slots.acquire(timeout_s=0.05):
                raise AssertionError('second holder got a slot')
        except TimeoutError:
            pass
    with slots.acquire() as b:
        assert b == 0
    assert os.path.isdir(os.path.join(str(tmp_path), 'slots'))
    unbounded = verdicts.HeavySlots(str(tmp_path), 0)
    with unbounded.acquire() as c:
        assert c is None
