"""Cross-process rate + concurrency limiter.

Enforces ``max_rps`` (fixed 1-second window) and ``max_concurrency`` across
processes by reading/writing the per-program ``rate_limit`` table in
``state/hunt.db`` under an ``BEGIN IMMEDIATE`` transaction.  This replaces the
old process-local ``HostRateLimiter``, which could not stop two runtimes from
exceeding the program's declared limits (P0.6).
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from ..errors import NetworkSafetyError

_WINDOW = 1.0
_MAX_WAIT = 10.0


class SharedRateLimiter:
    """One instance per broker; owns its own SQLite connection to hunt.db."""

    def __init__(self, db_path: Path, program: str) -> None:
        self.program = program
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=_MAX_WAIT)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        # Defensive: create the table if the migration hasn't run yet.
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS rate_limit ("
            " program TEXT NOT NULL, host TEXT NOT NULL, bucket_start REAL NOT NULL,"
            " count INTEGER NOT NULL DEFAULT 0, in_flight INTEGER NOT NULL DEFAULT 0,"
            " PRIMARY KEY (program, host))"
        )
        self._conn.commit()
        self._lock = threading.Lock()

    def close(self) -> None:
        self._conn.close()

    def acquire(self, host: str, max_rps: float, max_concurrency: int) -> None:
        """Block until a slot is free under both limits, then reserve it.

        The caller MUST pair this with ``release`` (even on failure)."""
        if max_rps <= 0:
            raise NetworkSafetyError("max_rps must be > 0")
        if max_concurrency < 1:
            raise NetworkSafetyError("max_concurrency must be >= 1")
        deadline = time.time() + _MAX_WAIT
        while True:
            now = time.time()
            if self._try_acquire(host, max_rps, max_concurrency, now):
                return
            if now >= deadline:
                raise NetworkSafetyError(f"rate/concurrency limit exceeded for {host!r}")
            time.sleep(0.05)

    def _try_acquire(self, host: str, max_rps: float, max_concurrency: int, now: float) -> bool:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT bucket_start, count, in_flight FROM rate_limit WHERE program=? AND host=?",
                    (self.program, host),
                ).fetchone()
                if row is None:
                    self._conn.execute(
                        "INSERT INTO rate_limit(program,host,bucket_start,count,in_flight) VALUES(?,?,?,0,0)",
                        (self.program, host, now),
                    )
                    row = self._conn.execute(
                        "SELECT bucket_start, count, in_flight FROM rate_limit WHERE program=? AND host=?",
                        (self.program, host),
                    ).fetchone()
                bucket_start = row["bucket_start"] or now
                count = row["count"]
                in_flight = row["in_flight"]
                if now - bucket_start >= _WINDOW:
                    bucket_start = now
                    count = 0
                if in_flight >= max_concurrency:
                    self._conn.execute("COMMIT")
                    return False
                if count + 1 > max_rps:
                    self._conn.execute("COMMIT")
                    return False
                self._conn.execute(
                    "UPDATE rate_limit SET bucket_start=?, count=?, in_flight=? WHERE program=? AND host=?",
                    (bucket_start, count + 1, in_flight + 1, self.program, host),
                )
                self._conn.execute("COMMIT")
                return True
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def release(self, host: str) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "UPDATE rate_limit SET in_flight = CASE WHEN in_flight > 0 THEN in_flight - 1 ELSE 0 END "
                    "WHERE program=? AND host=?",
                    (self.program, host),
                )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise


__all__ = ["SharedRateLimiter"]