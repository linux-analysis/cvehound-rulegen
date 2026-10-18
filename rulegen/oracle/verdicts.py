"""One SQLite file for every verdict and probe memo, shared by all oracle workers.

cvehound's ResultCache is append-only JSONL loaded whole into every process. A
verdict is one (key -> bool) lookup, so here it lives in a WAL-mode SQLite table
instead: the page cache is shared by every worker, a lookup costs a few
microseconds, and per-worker memory stays flat however many verdicts accumulate.

`SqliteVerdictCache` keeps ResultCache's interface (`key`, `get`, `put`,
`hits`/`misses`) and its key derivation byte for byte, so kerneltree's
`cached_check` cannot tell them apart. `ProbeStore` holds the T1/T4/cost memo on
the same file. `HeavySlots` bounds how many workers run a whole-tree scan at
once: address space is capped per worker, so the sum is what memory must cover.
"""

import contextlib
import json
import logging
import os
import sqlite3
import time
from collections.abc import Iterator
from typing import Any

from cvehound.oracle.resultcache import ResultCache, context_id

log = logging.getLogger(__name__)

DB_NAME = 'verdicts.sqlite'
BUSY_TIMEOUT_MS = 60_000


def _connect(path: str) -> sqlite3.Connection:
    from filelock import FileLock

    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None)
    conn.execute(f'PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}')
    # Switching a fresh file to WAL and creating the tables take exclusive
    # locks that the busy handler does not always cover; sixteen workers open
    # the store within the same second, so the first-open work is serialised.
    with FileLock(path + '.init.lock'):
        conn.execute('PRAGMA journal_mode = WAL')
        conn.execute(
            'CREATE TABLE IF NOT EXISTS verdicts ('
            'ctx TEXT NOT NULL, k TEXT NOT NULL, v INTEGER NOT NULL, t INTEGER NOT NULL, '
            'PRIMARY KEY (ctx, k)) WITHOUT ROWID'
        )
        conn.execute(
            'CREATE TABLE IF NOT EXISTS probes (k TEXT PRIMARY KEY, rec TEXT NOT NULL) '
            'WITHOUT ROWID'
        )
    conn.execute('PRAGMA synchronous = NORMAL')
    return conn


def db_path(root: str) -> str:
    return os.path.join(root, DB_NAME)


class SqliteVerdictCache(ResultCache):
    """ResultCache's contract over one shared SQLite file.

    Subclassed for `key()`: inheriting the derivation is the only way to be
    sure it stays byte-identical. ResultCache.__init__ is not called -- it
    would load every JSONL file of the context into memory, which is what this
    class exists to avoid.
    """

    def __init__(self, root: str, spatch_identity: str, worker: str = 'main') -> None:
        self.root = root
        self.ctx = context_id(spatch_identity)
        self.worker = worker
        self.conn = _connect(db_path(root))
        self._rule_hashes = {}
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> bool | None:
        row = self.conn.execute(
            'SELECT v FROM verdicts WHERE ctx = ? AND k = ?', (self.ctx, key)
        ).fetchone()
        if row is None:
            self.misses += 1
            return None
        self.hits += 1
        return bool(row[0])

    def put(self, key: str, verdict: bool) -> None:
        self.conn.execute(
            'INSERT OR REPLACE INTO verdicts (ctx, k, v, t) VALUES (?, ?, ?, ?)',
            (self.ctx, key, int(verdict), int(time.time())),
        )

    def close(self) -> None:
        self.conn.close()


class ProbeStore:
    """The T1 parse / T4 selectivity / cost memo: key -> JSON record, on the same file.

    Pass the verdict cache's connection to share it; a worker needs one.
    """

    def __init__(self, root: str, conn: sqlite3.Connection | None = None) -> None:
        self.conn = conn or _connect(db_path(root))

    def get(self, key: str) -> dict[str, Any] | None:
        row = self.conn.execute('SELECT rec FROM probes WHERE k = ?', (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, rec: dict[str, Any]) -> None:
        self.conn.execute(
            'INSERT OR REPLACE INTO probes (k, rec) VALUES (?, ?)', (key, json.dumps(rec))
        )


class HeavySlots:
    """At most `n` workers inside a whole-tree scan at once, across processes.

    Slots are lock files under `<root>/slots/`; a worker takes the first free
    one and holds it for the scan. RLIMIT_AS bounds one spatch; this bounds
    how many of those bounds can be in force together, which is what the
    host's memory has to cover.
    """

    def __init__(self, root: str, n: int, poll_s: float = 0.5) -> None:
        self.root = os.path.join(root, 'slots')
        self.n = max(0, n)  # 0: unbounded, and nothing on disk
        self.poll_s = poll_s
        if self.n:
            os.makedirs(self.root, exist_ok=True)

    @contextlib.contextmanager
    def acquire(self, timeout_s: float | None = None) -> Iterator[int | None]:
        if self.n == 0:
            yield None
            return
        from filelock import FileLock, Timeout

        started = time.monotonic()
        while True:
            for i in range(self.n):
                lock = FileLock(os.path.join(self.root, f'{i}.lock'))
                try:
                    lock.acquire(timeout=0)
                except Timeout:
                    continue
                try:
                    yield i
                finally:
                    lock.release()
                return
            if timeout_s is not None and time.monotonic() - started > timeout_s:
                raise TimeoutError(f'no heavy-scan slot free after {timeout_s}s')
            time.sleep(self.poll_s)
