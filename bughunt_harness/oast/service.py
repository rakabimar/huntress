"""Program-isolated, policy-gated OAST session/probe/evidence lifecycle."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..policy.engine import ALLOW, APPROVAL_REQUIRED, DENY
from ..redact import redact_headers, redact_text
from ..timeutil import utcnow
from .providers import OASTInteractionData, OASTProvider


class OASTService:
    def __init__(self, ctx, providers: dict[str, OASTProvider]) -> None:
        self.ctx = ctx
        self.providers = providers

    def capabilities(self) -> dict:
        return {name: provider.capabilities().__dict__ for name, provider in self.providers.items()}

    def create_session(
        self, provider_name: str, *, session_id: int, expires_in: int = 1800,
        approval_id: int | None = None,
    ) -> dict:
        self.ctx.db.require_session(session_id, program_slug=self.ctx.slug, running=True)
        provider = self.providers[provider_name]
        capability = provider.capabilities()
        if not capability.available:
            raise RuntimeError(capability.detail)
        if capability.third_party:
            decision = self.ctx.policy.check("third_party_communication")
            if decision.decision == DENY:
                raise RuntimeError(f"third-party OAST denied: {decision.reason}")
            if decision.decision == APPROVAL_REQUIRED:
                if approval_id is None:
                    pending = self.ctx.db.request_approval(
                        "third_party_communication", f"provider:{provider_name}",
                        program=self.ctx.slug, session_id=session_id,
                        requested_by="oast-service", note="provider observes callback traffic",
                        constraints={"max_requests": 1, "max_concurrency": 1,
                                     "duration_seconds": min(max(expires_in, 30), 86400),
                                     "provider": provider_name},
                    )
                    return {"decision": "approval_required", "approval_id": pending.public_id,
                            "provider": provider_name, "reason": decision.reason}
                self._require_approval(approval_id, "third_party_communication", provider_name)
        expires_in = max(30, min(int(expires_in), 86400))
        allocated = provider.create_session(expires_in=expires_in)
        now = datetime.now(timezone.utc)
        with self.ctx.db._lock:
            cur = self.ctx.db._conn.execute(
                "INSERT INTO oast_session(program,research_session_id,provider,provider_session_reference,"
                "created_at,expires_at,status,third_party_provider,approval_id,metadata) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (self.ctx.slug, session_id, provider_name, allocated["reference"], utcnow(),
                 (now + timedelta(seconds=expires_in)).isoformat(), "ACTIVE", int(capability.third_party),
                 approval_id, json.dumps({"base_domain": allocated.get("base_domain", "")})),
            )
            self.ctx.db._conn.commit()
        return self.get_session(int(cur.lastrowid))

    def create_probe(
        self, oast_session_id: int, *, hypothesis_id: int, research_test_id: int,
        expected_protocols: list[str] | None = None,
    ) -> dict:
        if not self.ctx.engagement.roe.out_of_band_testing or "oob_test" in self.ctx.engagement.roe.forbidden_actions:
            raise RuntimeError("OAST probes are disabled by the active program ROE")
        session = self.get_session(oast_session_id)
        if session["status"] != "ACTIVE" or _expired(session["expires_at"]):
            raise RuntimeError("OAST session is not active")
        test = self.ctx.db.get_test(research_test_id)
        if test.hypothesis_id != hypothesis_id:
            raise ValueError("OAST probe test/hypothesis correlation mismatch")
        provider = self.providers[session["provider"]]
        channels = set(provider.capabilities().channels)
        expected = [item.upper() for item in (expected_protocols or ["DNS", "HTTP", "HTTPS"])]
        if not set(expected) <= channels:
            raise ValueError(f"provider does not support requested channels: {sorted(set(expected) - channels)}")
        token = secrets.token_hex(16)  # opaque: no target/account data
        allocated = provider.allocate_probe(session["provider_session_reference"], token)
        now = datetime.now(timezone.utc)
        with self.ctx.db._lock:
            cur = self.ctx.db._conn.execute(
                "INSERT INTO oast_probe(oast_session_id,hypothesis_id,research_test_id,correlation_token,"
                "callback_domain,callback_urls,expected_protocols,created_at,expires_at,status) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (oast_session_id, hypothesis_id, research_test_id, token, allocated["domain"],
                 json.dumps(allocated.get("urls", {})), json.dumps(expected), utcnow(),
                 min(_parse_dt(session["expires_at"]), now + timedelta(hours=1)).isoformat(), "ACTIVE"),
            )
            self.ctx.db._conn.commit()
        return self.get_probe(int(cur.lastrowid))

    def link_request(self, probe_id: int, request_id: int) -> dict:
        probe = self.get_probe(probe_id)
        record = self.ctx.db.get_request_record(request_id)
        if record.program != self.ctx.slug:
            raise ValueError("cross-program request linkage denied")
        with self.ctx.db._lock:
            self.ctx.db._conn.execute("UPDATE oast_probe SET request_id=? WHERE id=?", (request_id, probe_id))
            self.ctx.db._conn.commit()
        return self.get_probe(probe_id)

    def poll_probe(self, probe_id: int, *, wait_seconds: int = 0) -> dict:
        probe = self.get_probe(probe_id)
        session = self.get_session(probe["oast_session_id"])
        if session["status"] != "ACTIVE" or _expired(probe["expires_at"]):
            with self.ctx.db._lock:
                self.ctx.db._conn.execute("UPDATE oast_probe SET status='EXPIRED' WHERE id=? AND status='ACTIVE'", (probe_id,))
                self.ctx.db._conn.commit()
            return {"probe": self.get_probe(probe_id), "new_interactions": [], "interactions": self.list_interactions(probe_id), "reason": "expired"}
        deadline = time.monotonic() + max(0, min(int(wait_seconds), 300))
        delays = iter((0, 2, 5, 10, 20, 30, 60))
        created: list[dict] = []
        while True:
            try:
                interactions = self.providers[session["provider"]].poll(session["provider_session_reference"])
            except Exception:
                with self.ctx.db._lock:
                    self.ctx.db._conn.execute("UPDATE oast_session SET status='FAILED' WHERE id=?", (session["id"],))
                    self.ctx.db._conn.commit()
                raise
            for interaction in interactions:
                if _matches_probe(interaction, probe):
                    stored = self._store_interaction(probe, session, interaction)
                    if stored:
                        created.append(stored)
            if created or time.monotonic() >= deadline:
                break
            delay = next(delays, 60)
            time.sleep(min(delay, max(0, deadline - time.monotonic())))
        return {"probe": self.get_probe(probe_id), "new_interactions": created, "interactions": self.list_interactions(probe_id)}

    def _store_interaction(self, probe: dict, session: dict, interaction: OASTInteractionData) -> dict | None:
        # A callback cannot become durable evidence until the exact target
        # request is linked to this exact probe/test/hypothesis tuple.
        if not probe.get("request_id"):
            return None
        safe_headers = redact_headers(interaction.headers, {"authorization", "cookie", "set-cookie"})
        raw = json.dumps({
            "protocol": interaction.protocol, "observed_at": interaction.observed_at,
            "hostname": interaction.hostname, "method": interaction.request_method,
            "path": interaction.path, "headers": safe_headers,
        }, sort_keys=True)
        fingerprint = interaction.provider_interaction_id or hashlib.sha256(raw.encode()).hexdigest()
        with self.ctx.db._lock:
            exists = self.ctx.db._conn.execute(
                "SELECT id FROM oast_interaction WHERE dedup_fingerprint=?", (fingerprint,),
            ).fetchone()
            if exists:
                return None
            cur = self.ctx.db._conn.execute(
                "INSERT INTO oast_interaction(probe_id,provider_interaction_id,protocol,observed_at,remote_address,"
                "request_method,hostname,path,sanitized_headers,content_hash,dedup_fingerprint,metadata) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (probe["id"], interaction.provider_interaction_id, interaction.protocol.upper(),
                 interaction.observed_at or utcnow(), interaction.remote_address, interaction.request_method,
                 interaction.hostname, interaction.path, json.dumps(safe_headers), hashlib.sha256(raw.encode()).hexdigest(),
                 fingerprint, json.dumps({"provider": session["provider"]})),
            )
            interaction_id = int(cur.lastrowid)
            self.ctx.db._conn.commit()
        artifact = Path(self.ctx.workspace) / "evidence" / f"oast-{interaction_id}.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(json.dumps({
            "schema": "bughunt.oast_interaction.v1", "program": self.ctx.slug,
            "probe_id": probe["id"], "request_id": probe["request_id"],
            "hypothesis_id": probe["hypothesis_id"], "research_test_id": probe["research_test_id"],
            "provider": session["provider"], "correlation_token_hash": hashlib.sha256(probe["correlation_token"].encode()).hexdigest(),
            "interaction": json.loads(raw),
        }, indent=2) + "\n", encoding="utf-8")
        evidence = self.ctx.db.add_evidence(
            "request_response", str(artifact),
            description=f"exact-correlated {interaction.protocol.upper()} OAST interaction for probe {probe['id']}",
            preview="OAST interaction correlated to one probe; target content remains untrusted",
        )
        with self.ctx.db._lock:
            self.ctx.db._conn.execute(
                "UPDATE oast_interaction SET artifact_ref=?,evidence_id=? WHERE id=?",
                (str(artifact), evidence.id, interaction_id),
            )
            self.ctx.db._conn.commit()
        return {"id": interaction_id, "evidence_id": evidence.public_id, "protocol": interaction.protocol.upper()}

    def get_session(self, session_id: int) -> dict:
        row = self.ctx.db._conn.execute("SELECT * FROM oast_session WHERE id=?", (session_id,)).fetchone()
        if row is None or row["program"] != self.ctx.slug:
            raise ValueError("unknown OAST session for active program")
        result = _row(row)
        if result["status"] == "ACTIVE" and _expired(result["expires_at"]):
            with self.ctx.db._lock:
                self.ctx.db._conn.execute("UPDATE oast_session SET status='EXPIRED' WHERE id=?", (session_id,)); self.ctx.db._conn.commit()
            result["status"] = "EXPIRED"
        return result

    def get_probe(self, probe_id: int) -> dict:
        row = self.ctx.db._conn.execute(
            "SELECT p.* FROM oast_probe p JOIN oast_session s ON s.id=p.oast_session_id "
            "WHERE p.id=? AND s.program=?", (probe_id, self.ctx.slug),
        ).fetchone()
        if row is None:
            raise ValueError("unknown OAST probe for active program")
        return _row(row)

    def list_interactions(self, probe_id: int) -> list[dict]:
        self.get_probe(probe_id)
        rows = self.ctx.db._conn.execute("SELECT * FROM oast_interaction WHERE probe_id=? ORDER BY id", (probe_id,)).fetchall()
        return [_row(row, omit={"metadata"}) for row in rows]

    def close_session(self, oast_session_id: int) -> dict:
        session = self.get_session(oast_session_id)
        self.providers[session["provider"]].close(session["provider_session_reference"])
        with self.ctx.db._lock:
            self.ctx.db._conn.execute("UPDATE oast_session SET status='CLOSED' WHERE id=?", (oast_session_id,))
            self.ctx.db._conn.execute("UPDATE oast_probe SET status='CLOSED' WHERE oast_session_id=?", (oast_session_id,))
            self.ctx.db._conn.commit()
        return self.get_session(oast_session_id)

    def _require_approval(self, approval_id: int | None, action: str, provider_name: str) -> None:
        if approval_id is None:
            raise RuntimeError(f"{action} requires explicit human approval")
        approval = self.ctx.db.get_approval(approval_id)
        if (approval.status != "approved" or approval.action != action or approval.program != self.ctx.slug
                or approval.target != f"provider:{provider_name}"
                or approval.constraints.get("provider") != provider_name):
            raise RuntimeError("approval does not authorize this OAST provider action")
        self.ctx.db.record_approval_use(approval_id)


def _matches_probe(interaction: OASTInteractionData, probe: dict) -> bool:
    token = probe["correlation_token"]
    host = interaction.hostname.lower().rstrip(".")
    domain = probe["callback_domain"].lower().rstrip(".")
    return interaction.correlation_token == token or host == domain or host.startswith(token.lower() + ".")


def _row(row, omit: set[str] | None = None) -> dict:
    result = {key: row[key] for key in row.keys() if key not in (omit or set())}
    for key in ("metadata", "callback_urls", "expected_protocols", "sanitized_headers"):
        if key in result and isinstance(result[key], str):
            try:
                result[key] = json.loads(result[key])
            except json.JSONDecodeError:
                pass
    # Provider references and opaque correlation tokens are not returned by
    # generic summaries. Internal calls access them through get_* and need the
    # values, so callers expose only selected keys at MCP/CLI boundaries.
    return result


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _expired(value: str) -> bool:
    return _parse_dt(value) <= datetime.now(timezone.utc)


__all__ = ["OASTService"]
