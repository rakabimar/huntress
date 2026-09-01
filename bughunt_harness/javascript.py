"""Compact deterministic JavaScript bundle intelligence with provenance."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .recon import normalize_endpoint_path
from .timeutil import utcnow

ANALYSIS_VERSION = "js-intel-v2"


class JavaScriptAnalyzer:
    ROUTE = re.compile(r"[\"'`]((?:/|https?://)[A-Za-z0-9_./?&=:{\}-]{2,})[\"'`]")
    WS = re.compile(r"[\"'`](wss?://[^\"'`\s]+)[\"'`]")
    GRAPHQL_OP = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_]\w*)")
    SOURCEMAP = re.compile(r"sourceMappingURL=([^\s*]+)")
    SECRET = re.compile(r"(?i)\b(api[_-]?key|secret|token)\b\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})")

    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def analyze_url(self, url: str, *, session_id: int, recon_run_id: int | None = None) -> dict:
        result = self.ctx.broker.execute(target=url, action="read_http", session_id=session_id, agent_role="recon-specialist")
        if not result.ok or not result.request_id:
            return {"ok": False, "decision": result.decision, "reason": result.reason}
        record = self.ctx.db.get_request_record(int(result.request_id.rsplit("-", 1)[1]))
        artifact = Path(self.ctx.workspace) / "evidence" / f"{record.evidence_ref}.json"
        doc = json.loads(artifact.read_text(encoding="utf-8"))
        analyzed = self.analyze_text(url, str(doc["response"].get("body", "")), recon_run_id=recon_run_id)
        source_map_url = analyzed.get("observations", {}).get("source_map_url", "")
        if source_map_url and self.ctx.scope.check(source_map_url).allowed:
            analyzed["source_map"] = self.analyze_source_map(source_map_url, session_id=session_id)
        return analyzed

    def analyze_source_map(self, url: str, *, session_id: int) -> dict:
        result = self.ctx.broker.execute(target=url, action="read_http", session_id=session_id, agent_role="recon-specialist")
        if not result.ok or not result.request_id:
            return {"ok": False, "decision": result.decision, "reason": result.reason}
        record = self.ctx.db.get_request_record(int(result.request_id.rsplit("-", 1)[1]))
        artifact = Path(self.ctx.workspace) / "evidence" / f"{record.evidence_ref}.json"
        body = json.loads(artifact.read_text(encoding="utf-8"))["response"].get("body", "")
        try: document = json.loads(body)
        except json.JSONDecodeError: return {"ok": False, "reason": "invalid source map JSON", "request_id": result.request_id}
        private = Path(self.ctx.workspace) / "recon" / "javascript" / (hashlib.sha256(url.encode()).hexdigest() + ".map.json")
        private.parent.mkdir(parents=True, exist_ok=True); private.write_text(json.dumps(document) + "\n", encoding="utf-8")
        return {"ok": True, "request_id": result.request_id, "artifact_ref": str(private),
                "sources": list(document.get("sources") or [])[:500], "names_count": len(document.get("names") or []),
                "sources_content_count": sum(item is not None for item in (document.get("sourcesContent") or [])),
                "version_mapping_required": True}

    def analyze_text(self, url: str, text: str, *, recon_run_id: int | None = None) -> dict:
        digest = hashlib.sha256(text.encode()).hexdigest()
        existing = self.ctx.db._conn.execute("SELECT * FROM js_artifact WHERE url=?", (url,)).fetchone()
        if existing and existing["content_hash"] == digest and existing["analysis_version"] == ANALYSIS_VERSION:
            return {"id": existing["id"], "unchanged": True, "observations": json.loads(existing["observations"])}
        endpoints = []
        structural_strings = _javascript_strings(text)
        for candidate in structural_strings:
            if not re.fullmatch(r"(?:/|https?://)[A-Za-z0-9_./?&=:{\}-]{2,}", candidate):
                continue
            if candidate.startswith("//") or candidate.endswith((".png", ".jpg", ".css")):
                continue
            endpoints.append({"url": urljoin(url, candidate), "raw": candidate, "confidence": 0.75})
        # Minified or syntactically incomplete bundles may not parse cleanly;
        # retain the deliberately conservative lexical fallback.
        for match in self.ROUTE.finditer(text):
            candidate = match.group(1)
            if candidate.startswith("//") or candidate.endswith((".png", ".jpg", ".css")):
                continue
            endpoints.append({"url": urljoin(url, candidate), "raw": candidate, "confidence": 0.65})
        observations = {
            "endpoints": _unique(endpoints, "url"),
            "websockets": sorted(set(self.WS.findall(text))),
            "graphql_operations": [{"type": a, "name": b} for a, b in self.GRAPHQL_OP.findall(text)],
            "source_map_url": urljoin(url, self.SOURCEMAP.search(text).group(1)) if self.SOURCEMAP.search(text) else "",
            "secret_candidates": [{"kind": kind.lower(), "fingerprint": hashlib.sha256(value.encode()).hexdigest()[:16]} for kind, value in self.SECRET.findall(text)],
            "analysis_method": "tree-sitter+regex" if structural_strings else "conservative-regex",
        }
        now = utcnow(); changed = bool(existing and existing["content_hash"] != digest)
        with self.ctx.db._lock:
            self.ctx.db._conn.execute(
                "INSERT INTO js_artifact(url,host,content_hash,size,source_map_url,first_seen,last_seen,analysis_version,observations,metadata) "
                "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET content_hash=excluded.content_hash,size=excluded.size,"
                "source_map_url=excluded.source_map_url,last_seen=excluded.last_seen,analysis_version=excluded.analysis_version,"
                "observations=excluded.observations",
                (url, urlsplit(url).hostname or "", digest, len(text.encode()), observations["source_map_url"],
                 now, now, ANALYSIS_VERSION, json.dumps(observations), json.dumps({"source": "javascript"})),
            ); self.ctx.db._conn.commit()
        row = self.ctx.db._conn.execute("SELECT id FROM js_artifact WHERE url=?", (url,)).fetchone()
        if recon_run_id is not None:
            self._feed_inventory(int(row["id"]), observations, recon_run_id, changed)
        return {"id": row["id"], "unchanged": False, "changed": changed, "observations": observations}

    def _feed_inventory(self, artifact_id: int, observations: dict, recon_run_id: int, changed: bool) -> None:
        for candidate in observations["endpoints"]:
            parsed = urlsplit(candidate["url"]); host = parsed.hostname
            if not host or not self.ctx.scope.check(candidate["url"]).allowed:
                continue
            asset, _ = self.ctx.db.upsert_asset(type="host", value=host, normalized_value=host.lower(), scope_status="in_scope", confidence=candidate["confidence"], metadata={"source": "javascript", "artifact_id": artifact_id})
            normalized, _confidence = normalize_endpoint_path(parsed.path or "/")
            endpoint, created = self.ctx.db.upsert_endpoint(host_asset_id=asset["id"], scheme=parsed.scheme, method="GET", normalized_path=normalized, metadata={"source": "javascript", "artifact_id": artifact_id})
            if created or changed:
                self.ctx.db.add_recon_change(recon_run_id=recon_run_id, change_type="JS_ENDPOINT_ADDED" if created else "JS_ENDPOINT_CHANGED", entity_type="endpoint", entity_id=endpoint["id"], new_value=candidate["url"], interest_score=60)


def _unique(items: list[dict], key: str) -> list[dict]:
    seen = set(); out = []
    for item in items:
        if item[key] not in seen:
            seen.add(item[key]); out.append(item)
    return out


def _javascript_strings(text: str) -> list[str]:
    """Return parser-confirmed JS string/template literals when available."""
    try:
        from tree_sitter_language_pack import get_parser
        tree = get_parser("javascript").parse(text.encode("utf-8", errors="replace"))
    except Exception:
        return []
    source = text.encode("utf-8", errors="replace")
    stack = [tree.root_node]
    values: list[str] = []
    while stack:
        node = stack.pop()
        if node.type in {"string", "template_string"}:
            raw = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
            if len(raw) >= 2 and raw[0] in {'"', "'", "`"} and raw[-1] == raw[0]:
                value = raw[1:-1]
                if "${" not in value and value not in values:
                    values.append(value)
        stack.extend(reversed(node.children))
    return values


__all__ = ["JavaScriptAnalyzer", "ANALYSIS_VERSION"]
