"""Cross-process rate/concurrency limiter tests (P0.6).

Uses multiple OS processes sharing one hunt.db to prove the SQLite-backed
limiter enforces max_concurrency across processes, not just within one.
No real network I/O — these are timing/state assertions only.
"""

import multiprocessing as mp
import time
from pathlib import Path

from bughunt_harness.requests.ratelimit import SharedRateLimiter
from bughunt_harness.state.db import HuntDB


def _hold_worker(db_path: str, program: str, host: str, active, max_active, iterations: int) -> None:
    lim = SharedRateLimiter(Path(db_path), program)
    for _ in range(iterations):
        lim.acquire(host, max_rps=1000.0, max_concurrency=1)
        with active.get_lock():
            active.value += 1
            if active.value > max_active.value:
                max_active.value = active.value
        time.sleep(0.02)
        with active.get_lock():
            active.value -= 1
        lim.release(host)
    lim.close()


def test_cross_process_max_concurrency_is_one(tmp_path):
    db_path = str(tmp_path / "hunt.db")
    db = HuntDB(db_path, program_slug="acme-test")
    db.close()  # ensure schema (incl. rate_limit) exists before workers open it

    active = mp.Value("i", 0)
    max_active = mp.Value("i", 0)
    workers = [
        mp.Process(target=_hold_worker, args=(db_path, "acme-test", "example.test", active, max_active, 8))
        for _ in range(4)
    ]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=30)

    assert all(not w.is_alive() for w in workers), "a worker hung waiting for a slot"
    # With max_concurrency=1 the concurrent holder count must never exceed 1.
    assert max_active.value == 1


def test_single_process_respects_max_rps(tmp_path):
    db_path = tmp_path / "hunt.db"
    lim = SharedRateLimiter(db_path, "acme-test")
    # 6 acquires in a burst under max_rps=3 -> needs >= ~1.5s (2 windows) to pass.
    start = time.time()
    for _ in range(6):
        lim.acquire("example.test", max_rps=3.0, max_concurrency=5)
        lim.release("example.test")
    elapsed = time.time() - start
    assert elapsed >= 1.0  # at least one window boundary must be crossed
    lim.close()