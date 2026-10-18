"""Long-lived oracle service: one warm scoring context per worker process.

Each worker owns its own CVEhound (warm spatch zygote where supported), blob
materializer and result-cache file; workers share the content-addressed blob
store and cache directory, which both tolerate concurrent writers by design.
jobs=1 scores inline in this process — the debugging mode.

Failure containment: a worker that raises while scoring returns a placeholder
Score (fail_class='harness') instead of poisoning the batch, and the pool is a
ProcessPoolExecutor so a worker that dies outright (segfault, OOM kill)
surfaces as BrokenProcessPool in the caller rather than a hang — the caller
recreates the service and resumes from its own log.
"""

import concurrent.futures as cf
import dataclasses
import logging
import multiprocessing
import threading
from dataclasses import dataclass
from typing import Any

from rulegen.oracle import reward
from rulegen.schema import DEFAULT_BRANCHES, Score, ScoreRequest

log = logging.getLogger(__name__)

# How often a live service evicts from the parse cache. Pruning at start and
# close alone is not a bound: one service can score for a day, and coccinelle
# writes a parse per (file, tree) the whole time -- tens of GB per hour when
# whole-tree scans dominate. The interval adapts to the fill rate: it starts at
# the base, stays there while a prune still frees a large share of the limit,
# and backs off to the maximum once there is nothing left to free. A walk over a
# cache already at the limit costs about two seconds.
ASTCACHE_PRUNE_INTERVAL_S = 60
ASTCACHE_PRUNE_INTERVAL_MAX_S = 600


@dataclass(frozen=True, kw_only=True)
class OracleConfig(reward.OracleOptions):
    """Where the oracle runs, plus which tiers (OracleOptions)."""

    kernel: str
    work_root: str
    branches: tuple[str, ...] = DEFAULT_BRANCHES
    use_cache: bool = True
    zygote: str | None = None  # None -> cvehound's 'auto'
    worktrees: str | None = None  # default <work_root>/worktrees
    # How many workers may run a whole-tree scan (T6, head, cost) at once;
    # 0 = every worker. RLIMIT_AS bounds one scan, this bounds their sum.
    heavy_slots: int = 0
    # RLIMIT_AS for each worker and everything it spawns; 0 disables the cap.
    address_space_limit: int = reward.SPATCH_ADDRESS_SPACE_LIMIT


_CTX: reward.OracleCtx | None = None
_CFG: OracleConfig | None = None

# The rare per-scan faults: a leg the engine did not finish (rulegen.oracle.diag)
# and a scan cvehound reran or found truncated (cvehound.spatch). A worker
# silences the root logger, which would drop both, and they are the only record
# of why a verdict is missing.
DIAG_LOGGERS = ('rulegen.oracle.diag', 'cvehound.spatch')


def install_diag_handler(fmt: str = 'diag %(message)s') -> None:
    """Route the diagnostic loggers to stderr at WARNING, whatever the root does."""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt))
    for name in DIAG_LOGGERS:
        logger = logging.getLogger(name)
        logger.setLevel(logging.WARNING)
        logger.handlers = [handler]
        logger.propagate = False


def _init_worker(cfg_row: dict[str, Any]) -> None:
    global _CTX, _CFG
    # cvehound logs 'Checking:'/'Found:' to the root logger on every check; the
    # Score already carries every verdict, so keep workers quiet. Genuine spatch
    # errors surface as fail_class, not as log lines we would need here. With
    # jobs=1 this runs in the main process, whose root logger the CLI already
    # configured (`-v` raises it on purpose) — leave it alone there.
    import multiprocessing as mp

    if mp.parent_process() is not None:
        logging.getLogger().setLevel(logging.ERROR)
        install_diag_handler('diag w%(process)d %(message)s')
    _CFG = OracleConfig(**{**cfg_row, 'branches': tuple(cfg_row['branches'])})
    # Before any spatch exists: the cap has to be on this process so the zygote
    # cvehound forks inherits it. A whole-tree scan of a rule with an unselective
    # grep query can otherwise grow without bound.
    if _CFG.address_space_limit:
        reward.limit_address_space(
            reward.address_space_limit(_CFG.address_space_limit, _CFG.kernel)
        )
    _CTX = reward.make_ctx(
        _CFG.kernel,
        _CFG.work_root,
        _CFG.branches,
        use_cache=_CFG.use_cache,
        zygote=_CFG.zygote,
        worktrees_root=_CFG.worktrees,
        heavy_slots=_CFG.heavy_slots,
    )


def _score_one(req: ScoreRequest) -> Score:
    assert _CTX is not None and _CFG is not None
    try:
        return reward.score_rule(_CTX, req, _CFG)
    except Exception as err:  # noqa: BLE001 — containment is the point
        # A crash inside scoring must not take the sibling requests with it:
        # the candidate earns nothing and the note says why.
        log.error('%s: scoring crashed: %r', req.cve, err)
        return Score.unscored(req.cve, req.rule_text, 'harness', repr(err))


class OracleService:
    def __init__(self, cfg: OracleConfig, jobs: int = 1) -> None:
        self.cfg = cfg
        self.jobs = max(1, jobs)
        self._pool: cf.ProcessPoolExecutor | None = None
        # A run that crashed never reached close(): bound the parse cache before
        # the workers start growing it again.
        self._prune_ast_cache()
        self._stop_pruning = threading.Event()
        self._pruner: threading.Thread | None = None
        if self.jobs == 1:
            _init_worker(dataclasses.asdict(cfg))
        else:
            self._pool = cf.ProcessPoolExecutor(
                self.jobs,
                mp_context=multiprocessing.get_context('spawn'),
                initializer=_init_worker,
                initargs=(dataclasses.asdict(cfg),),
            )
        # Started after the pool: the workers inherit no thread of ours.
        self._pruner = threading.Thread(target=self._prune_loop, name='astcache-prune', daemon=True)
        self._pruner.start()

    def score(self, req: ScoreRequest) -> Score:
        return self.score_batch([req])[0]

    def score_batch(self, reqs: list[ScoreRequest]) -> list[Score]:
        """Scores in request order. Raises BrokenProcessPool if a worker died."""
        if self._pool is None:
            return [_score_one(req) for req in reqs]
        return list(self._pool.map(_score_one, reqs, chunksize=1))

    def close(self) -> None:
        self._stop_pruning.set()
        if self._pruner is not None:
            self._pruner.join(timeout=60)
            self._pruner = None
        if self._pool is not None:
            self._pool.shutdown(wait=True)
            self._pool = None
        self._prune_ast_cache()

    def _prune_loop(self) -> None:
        """Hold the cache at its limit while the workers fill it.

        Safe against the scans running beside it: an entry is a cache, and
        cvehound drops the pair dependency-first, so a worker racing the prune
        re-parses instead of reading a dependency whose value is gone.

        A prune that still frees more than a quarter of the limit means the
        writers are ahead, so the next one comes at the base interval; a prune
        with nothing to free doubles the wait, up to the maximum.
        """
        interval = float(ASTCACHE_PRUNE_INTERVAL_S)
        while not self._stop_pruning.wait(interval):
            freed = self._prune_ast_cache() or 0
            if freed > reward.ASTCACHE_LIMIT // 4:
                interval = float(ASTCACHE_PRUNE_INTERVAL_S)
            elif not freed:
                interval = min(interval * 2, float(ASTCACHE_PRUNE_INTERVAL_MAX_S))

    def _prune_ast_cache(self) -> int:
        """coccinelle never evicts from its parse cache; bound it ourselves.

        Returns the bytes freed, which is how _prune_loop learns whether it is
        keeping up. A failure returns 0 and is logged, never raised.
        """
        try:
            from cvehound.util import astcache_prune, find_spatch

            path = reward.astcache_path(self.cfg.work_root, find_spatch(None))
            freed = astcache_prune(path, reward.ASTCACHE_LIMIT)
            if freed:
                log.info('AST cache: pruned %.1f MB from %s', freed / 1e6, path)
            return int(freed or 0)
        except Exception as err:  # noqa: BLE001 — housekeeping must not fail a run
            log.warning('could not prune the AST cache: %r', err)
            return 0

    def __enter__(self) -> 'OracleService':
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
