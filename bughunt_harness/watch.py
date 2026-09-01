"""Persistent foreground recon watch state; no distributed scheduler."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from .timeutil import utcnow


class ReconWatchService:
    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def configure(self, profile: str = "passive", interval_seconds: int = 21600) -> dict:
        if profile != "passive" and not self.ctx.engagement.roe.automation_allowed:
            raise ValueError("recurring active recon requires explicit automation permission")
        if interval_seconds < 60:
            raise ValueError("watch interval must be at least 60 seconds")
        now = datetime.now(timezone.utc)
        with self.ctx.db._lock:
            self.ctx.db._conn.execute(
                "INSERT INTO recon_watch(profile,interval_seconds,next_run,status,created_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(profile) DO UPDATE SET interval_seconds=excluded.interval_seconds,next_run=excluded.next_run,status='ACTIVE'",
                (profile, interval_seconds, now.isoformat(), "ACTIVE", utcnow()),
            ); self.ctx.db._conn.commit()
        return self.get(profile)

    def run_once(self, profile: str, runner) -> dict:
        watch = self.get(profile)
        if self.ctx.engagement.program.status != "active":
            raise RuntimeError("program is not active")
        before = {row["id"] for row in self.ctx.db._conn.execute("SELECT id FROM recon_change").fetchall()}
        try:
            result = runner(profile)
            after = [dict(row) for row in self.ctx.db._conn.execute("SELECT * FROM recon_change ORDER BY id").fetchall() if row["id"] not in before]
            leads = []
            for change in after:
                if change["interest_score"] >= self.ctx.engagement.recon.lead_threshold:
                    lead = self.ctx.db.add_lead(
                        f"Recon watch: {change['change_type']} on {change['entity_type']} {change['entity_id']}",
                        entity=f"{change['entity_type']}:{change['entity_id']}", source="recon-watch",
                        rationale="Observed change exceeded configured interest threshold",
                    )
                    leads.append(lead.public_id)
            self._finish(watch["id"], {"result": result, "changes": len(after), "leads": leads}, error=False)
            return {"watch": self.get(profile), "changes": after, "leads": leads}
        except Exception as exc:
            self._finish(watch["id"], {"error": f"{type(exc).__name__}: {exc}"}, error=True)
            raise

    def get(self, profile: str) -> dict:
        row = self.ctx.db._conn.execute("SELECT * FROM recon_watch WHERE profile=?", (profile,)).fetchone()
        if row is None: raise ValueError("watch profile is not configured")
        result = dict(row); result["last_result"] = json.loads(result["last_result"] or "{}")
        return result

    def _finish(self, watch_id: int, result: dict, *, error: bool) -> None:
        row = self.ctx.db._conn.execute("SELECT interval_seconds,error_count FROM recon_watch WHERE id=?", (watch_id,)).fetchone()
        now = datetime.now(timezone.utc)
        with self.ctx.db._lock:
            self.ctx.db._conn.execute(
                "UPDATE recon_watch SET last_run=?,next_run=?,last_result=?,error_count=? WHERE id=?",
                (now.isoformat(), (now + timedelta(seconds=row["interval_seconds"])).isoformat(),
                 json.dumps(result), row["error_count"] + int(error), watch_id),
            ); self.ctx.db._conn.commit()


__all__ = ["ReconWatchService"]
