"""Optional authenticated-session lifecycle; raw credentials stay broker-side."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

from ..timeutil import utcnow


class AuthSessionManager:
    REFRESH_SKEW_SECONDS = 60

    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def status(self, auth_context: str | None = None) -> list[dict]:
        query = "SELECT * FROM auth_session"
        args: tuple = ()
        if auth_context:
            query += " WHERE auth_context=?"; args = (auth_context,)
        rows = self.ctx.db._conn.execute(query + " ORDER BY id", args).fetchall()
        return [_safe_row(row) for row in rows]

    def login(self, auth_context: str, *, session_id: int, agent_role: str = "auth-identity-specialist") -> dict:
        account = self._account(auth_context)
        auth = account.auth
        if auth is None:
            raise ValueError("account has no auth configuration")
        if auth.strategy == "STATIC":
            return self._upsert(auth_context, "STATIC", "VALID", self._credential_ref(auth), metadata={"static": True})
        if auth.strategy == "MANUAL_BROWSER":
            return self._upsert(auth_context, auth.strategy, "WAITING_HUMAN", "", metadata={"reason": "manual browser/MFA action required"})
        login = auth.login
        if login is None:
            raise ValueError("lifecycle login configuration missing")
        username = self.ctx.broker.secrets.resolve(str(login.username_ref)) or ""
        password = self.ctx.broker.secrets.resolve(str(login.password_ref)) or ""
        body = {login.username_field: username, login.password_field: password}
        selectors, names = self._selectors_and_names(auth_context, auth, refresh=True)
        result = self.ctx.broker.execute(
            target=login.url, method=login.method, action="authentication_test",
            json_body=body if login.body_type == "json" else None,
            body=None if login.body_type == "json" else _form(body),
            headers={"Content-Type": "application/json" if login.body_type == "json" else "application/x-www-form-urlencoded"},
            session_id=session_id, agent_role=agent_role, secret_extract=selectors,
            secret_store_names=names, extra_secret_values=[username, password],
        )
        if not result.ok or result.status_code != login.success_status:
            state = "WAITING_HUMAN" if auth.metadata.get("mfa_required") else "FAILED"
            return self._upsert(auth_context, auth.strategy, state, "", error=f"login failed: {result.status_code or result.reason}")
        credential_ref = result.session_secret_refs.get("access") or result.session_secret_refs.get("cookie") or ""
        expires_at = self._expiry(credential_ref, auth.metadata.get("ttl_seconds"))
        return self._upsert(
            auth_context, auth.strategy, "VALID", credential_ref,
            issued_at=utcnow(), expires_at=expires_at,
            metadata={"refresh_ref": result.session_secret_refs.get("refresh", ""), "last_login_request": result.request_id},
        )

    def refresh(self, auth_context: str, *, session_id: int, agent_role: str = "auth-identity-specialist") -> dict:
        account = self._account(auth_context); auth = account.auth
        if auth is None or auth.login is None:
            raise ValueError("refresh is not configured")
        login = auth.login
        if not login.refresh_url:
            return self.login(auth_context, session_id=session_id, agent_role=agent_role)
        current = self._session(auth_context)
        refresh_ref = str((current.get("metadata") or {}).get("refresh_ref") or login.refresh_token_ref or "")
        refresh_token = self.ctx.broker.secrets.resolve(refresh_ref) if refresh_ref else None
        if not refresh_token:
            return self.login(auth_context, session_id=session_id, agent_role=agent_role)
        selectors, names = self._selectors_and_names(auth_context, auth, refresh=True)
        body = {login.refresh_token_field: refresh_token}
        result = self.ctx.broker.execute(
            target=login.refresh_url, method=login.refresh_method, action="session_test",
            json_body=body, headers={"Content-Type": "application/json"},
            session_id=session_id, agent_role=agent_role, secret_extract=selectors,
            secret_store_names=names, extra_secret_values=[refresh_token],
        )
        if not result.ok or result.status_code != login.success_status:
            return self._upsert(auth_context, auth.strategy, "FAILED", "", error="bounded refresh failed")
        credential_ref = result.session_secret_refs.get("access") or result.session_secret_refs.get("cookie") or ""
        refreshed = self._upsert(
            auth_context, auth.strategy, "VALID", credential_ref, issued_at=utcnow(),
            expires_at=self._expiry(credential_ref, auth.metadata.get("ttl_seconds")),
            last_refresh=utcnow(), increment_refresh=True,
            metadata={"refresh_ref": result.session_secret_refs.get("refresh", refresh_ref), "last_refresh_request": result.request_id},
        )
        self._event(refreshed["id"], "REFRESHED", _request_num(result.request_id))
        return refreshed

    def execute_with_session(self, auth_context: str, *, session_id: int, **broker_kwargs):
        session = self._session(auth_context, required=False)
        if session and self._needs_refresh(session):
            self.refresh(auth_context, session_id=session_id)
        result = self.ctx.broker.execute(auth_context=auth_context, session_id=session_id, **broker_kwargs)
        confidently_expired = result.status_code == 401 or (
            result.status_code == 403 and "invalid_token" in str(result.response_headers.get("WWW-Authenticate", "")).lower()
        )
        if not confidently_expired:
            return result
        refreshed = self.refresh(auth_context, session_id=session_id)
        if refreshed["state"] != "VALID":
            return result
        parent = _request_num(result.request_id)
        return self.ctx.broker.execute(
            auth_context=auth_context, session_id=session_id,
            parent_request_id=parent, root_request_id=parent, replay_depth=1,
            mutation_summary="auth-refresh-retry", **broker_kwargs,
        )

    def invalidate(self, auth_context: str) -> dict:
        current = self._session(auth_context)
        return self._upsert(auth_context, current["strategy"], "INVALID", "", error="invalidated by user")

    def _account(self, auth_context: str):
        account_id = auth_context
        if auth_context.upper().startswith("AUTH-"):
            account_id = self.ctx.db.get_auth_context(int(auth_context.split("-", 1)[1])).account_id
        account = self.ctx.engagement.accounts.by_id().get(account_id)
        if account is None or not account.enabled:
            raise ValueError("unknown or disabled auth account")
        return account

    def _credential_ref(self, auth) -> str:
        return str(auth.bearer_ref or auth.cookie_ref or "")

    def _selectors_and_names(self, context: str, auth, *, refresh: bool) -> tuple[dict[str, str], dict[str, str]]:
        login = auth.login
        selectors: dict[str, str] = {}; names: dict[str, str] = {}
        if auth.type == "bearer":
            if not login.bearer_json_path:
                raise ValueError("bearer lifecycle requires bearer_json_path")
            selectors["access"] = "json:" + login.bearer_json_path
            names["access"] = _file_name(auth.bearer_ref)
        elif auth.type in {"cookie", "browser_session"}:
            if not login.cookie_name:
                raise ValueError("cookie lifecycle requires cookie_name")
            selectors["cookie"] = "cookie:" + login.cookie_name
            names["cookie"] = _file_name(auth.cookie_ref)
        else:
            raise ValueError("lifecycle currently supports bearer/cookie output")
        if refresh and login.refresh_json_path:
            selectors["refresh"] = "json:" + login.refresh_json_path
            names["refresh"] = _file_name(login.refresh_token_ref or f"file:{context}-refresh")
        return selectors, names

    def _expiry(self, ref: str, ttl_seconds) -> str | None:
        if ttl_seconds:
            return (datetime.now(timezone.utc) + timedelta(seconds=int(ttl_seconds))).isoformat()
        try:
            token = self.ctx.broker.secrets.resolve(ref) or ""
            payload = token.split(".")[1]; payload += "=" * (-len(payload) % 4)
            exp = json.loads(base64.urlsafe_b64decode(payload))["exp"]
            return datetime.fromtimestamp(int(exp), timezone.utc).isoformat()
        except Exception:
            return None

    def _needs_refresh(self, row: dict) -> bool:
        if row["state"] != "VALID":
            return True
        if not row.get("expires_at"):
            return False
        expiry = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        return expiry <= datetime.now(timezone.utc) + timedelta(seconds=self.REFRESH_SKEW_SECONDS)

    def _session(self, context: str, *, required: bool = True) -> dict | None:
        row = self.ctx.db._conn.execute("SELECT * FROM auth_session WHERE auth_context=?", (context,)).fetchone()
        if row is None:
            if required:
                raise ValueError("auth session has not been initialized")
            return None
        return _row(row)

    def _upsert(
        self, context: str, strategy: str, state: str, credential_ref: str,
        *, issued_at: str | None = None, expires_at: str | None = None,
        last_refresh: str | None = None, error: str = "", metadata: dict | None = None,
        increment_refresh: bool = False,
    ) -> dict:
        with self.ctx.db._lock:
            self.ctx.db._conn.execute(
                "INSERT INTO auth_session(auth_context,strategy,state,issued_at,expires_at,last_refresh,credential_ref,refresh_count,last_error,metadata) "
                "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(auth_context) DO UPDATE SET strategy=excluded.strategy,state=excluded.state,"
                "issued_at=COALESCE(excluded.issued_at,auth_session.issued_at),expires_at=excluded.expires_at,"
                "last_refresh=COALESCE(excluded.last_refresh,auth_session.last_refresh),credential_ref=excluded.credential_ref,"
                "refresh_count=auth_session.refresh_count+?,last_error=excluded.last_error,metadata=excluded.metadata",
                (context, strategy, state, issued_at, expires_at, last_refresh, credential_ref,
                 int(increment_refresh), error, json.dumps(metadata or {}), int(increment_refresh)),
            )
            self.ctx.db._conn.commit()
        return self._session(context)

    def _event(self, auth_session_id: int, event: str, request_id: int | None) -> None:
        with self.ctx.db._lock:
            self.ctx.db._conn.execute(
                "INSERT INTO auth_session_event(auth_session_id,event,request_id,created_at,metadata) VALUES(?,?,?,?,?)",
                (auth_session_id, event, request_id, utcnow(), "{}"),
            ); self.ctx.db._conn.commit()


def _file_name(ref: object) -> str:
    value = str(ref or "")
    if not value.startswith("file:"):
        raise ValueError("refreshed session outputs require a protected file: secret reference")
    return value[5:]


def _form(values: dict[str, str]) -> str:
    from urllib.parse import urlencode
    return urlencode(values)


def _row(row) -> dict:
    result = {key: row[key] for key in row.keys()}
    result["metadata"] = json.loads(result.get("metadata") or "{}")
    return result


def _safe_row(row) -> dict:
    result = _row(row)
    result.pop("credential_ref", None)
    if "refresh_ref" in result["metadata"]:
        result["metadata"]["refresh_available"] = bool(result["metadata"].pop("refresh_ref"))
    return result


def _request_num(value: str | None) -> int | None:
    return int(value.rsplit("-", 1)[1]) if value else None


__all__ = ["AuthSessionManager"]
