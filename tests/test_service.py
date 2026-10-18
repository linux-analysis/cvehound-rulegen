"""The service's housekeeping: the parse cache is bounded while a run lives."""

import logging
import time

from rulegen.oracle import reward, service
from rulegen.oracle.service import OracleConfig, OracleService


def start(monkeypatch, tmp_path, freed: int, cap_s: float = 5.0) -> tuple[OracleService, list]:
    """A worker-less service whose every prune frees `freed` bytes, base interval 10 ms."""
    calls: list[int] = []
    monkeypatch.setattr(service, '_init_worker', lambda cfg: None)
    monkeypatch.setattr(service, 'ASTCACHE_PRUNE_INTERVAL_S', 0.01)
    monkeypatch.setattr(service, 'ASTCACHE_PRUNE_INTERVAL_MAX_S', cap_s)
    monkeypatch.setattr(OracleService, '_prune_ast_cache', lambda self: calls.append(1) or freed)
    cfg = OracleConfig(kernel=str(tmp_path), work_root=str(tmp_path))
    return OracleService(cfg, jobs=1), calls


def wait_for(calls: list, n: int, timeout_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while len(calls) < n and time.monotonic() < deadline:
        time.sleep(0.01)


def test_prune_runs_while_the_service_lives_and_stops_with_it(monkeypatch, tmp_path):
    """Start and close alone are not a bound: one run can score for a day between them."""
    svc, calls = start(monkeypatch, tmp_path, freed=reward.ASTCACHE_LIMIT)
    wait_for(calls, 3)
    assert len(calls) >= 3, 'the loop never pruned beyond the one call in __init__'
    svc.close()
    settled = len(calls)
    time.sleep(0.05)
    assert len(calls) == settled, 'the prune loop outlived the service'


def test_prune_interval_backs_off_when_there_is_nothing_to_free(monkeypatch, tmp_path):
    """A quiet cache must not be walked every base interval forever."""
    svc, calls = start(monkeypatch, tmp_path, freed=0, cap_s=0.08)
    time.sleep(0.5)
    svc.close()
    # At the base interval 0.5 s would be ~50 walks; backing off 0.01 -> 0.08
    # caps it near a dozen. The bound is loose because the scheduler is not ours.
    assert 2 <= len(calls) <= 25, len(calls)


def test_prune_interval_stays_short_while_the_fill_outruns_it(monkeypatch, tmp_path):
    """A prune still freeing a quarter of the limit means the writers are ahead."""
    svc, calls = start(monkeypatch, tmp_path, freed=reward.ASTCACHE_LIMIT)
    wait_for(calls, 10)
    svc.close()
    assert len(calls) >= 10, 'the interval backed off although the cache kept filling'


def test_diag_loggers_survive_a_silenced_root(monkeypatch):
    """Workers set the root logger to ERROR; the engine diagnostics must still print."""
    for name in service.DIAG_LOGGERS:
        lg = logging.getLogger(name)
        monkeypatch.setattr(lg, 'handlers', list(lg.handlers))
        monkeypatch.setattr(lg, 'propagate', lg.propagate)
        monkeypatch.setattr(lg, 'level', lg.level)
    service.install_diag_handler('diag %(message)s')
    for name in service.DIAG_LOGGERS:
        lg = logging.getLogger(name)
        assert lg.level == logging.WARNING and not lg.propagate and len(lg.handlers) == 1
