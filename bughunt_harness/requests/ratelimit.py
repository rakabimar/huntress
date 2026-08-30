"""Crash-safe SQLite rate and concurrency limiter.

RPS accounting remains a shared fixed window. Concurrency uses expiring lease
rows, so a killed broker cannot hold a program slot forever.
"""

from __future__ import annotations

import sqlite3
import math
import threading
import time
import uuid
from pathlib import Path

from ..errors import NetworkSafetyError

_WINDOW = 1.0
_MAX_WAIT = 10.0
_DEFAULT_LEASE_TTL = 60.0


class SharedRateLimiter:
    def __init__(self, db_path: Path, program: str) -> None:
        self.program = program
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=_MAX_WAIT)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS rate_limit ("
            " program TEXT NOT NULL, host TEXT NOT NULL, bucket_start REAL NOT NULL,"
            " count INTEGER NOT NULL DEFAULT 0, in_flight INTEGER NOT NULL DEFAULT 0,"
            " PRIMARY KEY (program, host))"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS rate_limit_lease ("
            " lease_id TEXT PRIMARY KEY, program TEXT NOT NULL, host TEXT NOT NULL,"
            " session_id INTEGER, acquired_at REAL NOT NULL, expires_at REAL NOT NULL)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_rate_lease_host "
            "ON rate_limit_lease(program, host, expires_at)"
        )
        self._conn.commit()
        self._lock = threading.Lock()
        self._owned: dict[str, list[str]] = {}

    def close(self) -> None:
        self._conn.close()

    def acquire(
        self, host: str, max_rps: float, max_concurrency: int,
        *, session_id: int | None = None, lease_ttl: float = _DEFAULT_LEASE_TTL,
    ) -> str:
        if max_rps <= 0:
            raise NetworkSafetyError("max_rps must be > 0")
        if max_concurrency < 1:
            raise NetworkSafetyError("max_concurrency must be >= 1")
        if lease_ttl <= 0:
            raise NetworkSafetyError("lease_ttl must be > 0")
        deadline = time.time() + _MAX_WAIT
        while True:
            now = time.time()
            lease_id = self._try_acquire(
                host, max_rps, max_concurrency, now,
                session_id=session_id, lease_ttl=lease_ttl,
            )
            if lease_id:
                self._owned.setdefault(host, []).append(lease_id)
                return lease_id
            if now >= deadline:
                raise NetworkSafetyError(f"rate/concurrency limit exceeded for {host!r}")
            time.sleep(0.05)

    def _try_acquire(
        self, host: str, max_rps: float, max_concurrency: int, now: float,
        *, session_id: int | None, lease_ttl: float,
    ) -> str | None:
        lease_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "DELETE FROM rate_limit_lease WHERE program=? AND expires_at<=?",
                    (self.program, now),
                )
                row = self._conn.execute(
                    "SELECT bucket_start, count FROM rate_limit WHERE program=? AND host=?",
                    (self.program, host),
                ).fetchone()
                if row is None:
                    self._conn.execute(
                        "INSERT INTO rate_limit(program,host,bucket_start,count,in_flight) VALUES(?,?,?,0,0)",
                        (self.program, host, now),
                    )
                    bucket_start, count = now, 0
                else:
                    bucket_start, count = row["bucket_start"] or now, row["count"]
                window = max(_WINDOW, 1.0 / max_rps)
                capacity = max(1, math.floor(max_rps * window))
                if now - bucket_start >= window:
                    bucket_start, count = now, 0
                active = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM rate_limit_lease "
                    "WHERE program=? AND host=? AND expires_at>?",
                    (self.program, host, now),
                ).fetchone()["n"]
                if active >= max_concurrency or count + 1 > capacity:
                    self._conn.execute("COMMIT")
                    return None
                self._conn.execute(
                    "UPDATE rate_limit SET bucket_start=?, count=?, in_flight=? "
                    "WHERE program=? AND host=?",
                    (bucket_start, count + 1, active + 1, self.program, host),
                )
                self._conn.execute(
                    "INSERT INTO rate_limit_lease(lease_id,program,host,session_id,acquired_at,expires_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (lease_id, self.program, host, session_id, now, now + lease_ttl),
                )
                self._conn.execute("COMMIT")
                return lease_id
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def release(self, host: str, lease_id: str | None = None) -> None:
        if lease_id is None:
            owned = self._owned.get(host, [])
            lease_id = owned.pop() if owned else None
        if not lease_id:
            return
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "DELETE FROM rate_limit_lease WHERE lease_id=? AND program=? AND host=?",
                    (lease_id, self.program, host),
                )
                active = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM rate_limit_lease "
                    "WHERE program=? AND host=? AND expires_at>?",
                    (self.program, host, time.time()),
                ).fetchone()["n"]
                self._conn.execute(
                    "UPDATE rate_limit SET in_flight=? WHERE program=? AND host=?",
                    (active, self.program, host),
                )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def cleanup_stale(self) -> int:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM rate_limit_lease WHERE program=? AND expires_at<=?",
                (self.program, time.time()),
            )
            self._conn.commit()
            return cur.rowcount


__all__ = ["SharedRateLimiter"]
