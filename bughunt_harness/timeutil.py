"""Tiny shared time helper (kept separate to avoid import cycles)."""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def utcnow_iso_micro() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")