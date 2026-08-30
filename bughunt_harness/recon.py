"""Persistent scope-aware attack-surface intelligence.

Recon tools are capability implementations, never model-facing shells. This
module owns fixed argv builders, passive seed derivation, policy gates,
normalization, artifact capture, inventory correlation, deterministic scoring,
and contextual lead promotion. Target output is always untrusted data.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import posixpath
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlsplit, urlunsplit

from .redact import redact_text
from .timeutil import utcnow

PASSIVE_TOOLS = ("subfinder", "assetfinder", "amass")
HISTORICAL_TOOLS = ("gau", "waybackurls")
OPTIONAL_ACTIVE_TOOLS = ("dnsx", "httpx", "katana", "nuclei", "ffuf", "naabu", "nmap")


@dataclass(frozen=True)
class ToolCapability:
    name: str
    binary: str
    capabilities: tuple[str, ...]
    risk_class: str
    profiles: tuple[str, ...]
    install: str


TOOL_REGISTRY: dict[str, ToolCapability] = {
    "subfinder": ToolCapability("subfinder", "subfinder", ("passive_dns",), "R0", ("passive", "light", "standard", "deep"), "https://docs.projectdiscovery.io/tools/subfinder/install"),
    "assetfinder": ToolCapability("assetfinder", "assetfinder", ("passive_dns",), "R0", ("passive", "light", "standard", "deep"), "https://github.com/tomnomnom/assetfinder"),
    "amass": ToolCapability("amass", "amass", ("passive_dns",), "R0", ("passive", "light", "standard", "deep"), "https://github.com/owasp-amass/amass/blob/master/doc/install.md"),
    "dnsx": ToolCapability("dnsx", "dnsx", ("dns",), "R2", ("light", "standard", "deep"), "https://docs.projectdiscovery.io/tools/dnsx/install"),
    "httpx": ToolCapability("httpx", "httpx", ("http", "tls", "technology"), "R2", ("light", "standard", "deep"), "https://docs.projectdiscovery.io/tools/httpx/install"),
    "gau": ToolCapability("gau", "gau", ("archives",), "R0", ("standard", "deep"), "https://github.com/lc/gau"),
    "waybackurls": ToolCapability("waybackurls", "waybackurls", ("archives",), "R0", ("standard", "deep"), "https://github.com/tomnomnom/waybackurls"),
    "katana": ToolCapability("katana", "katana", ("crawl", "javascript"), "R2", ("standard", "deep"), "https://docs.projectdiscovery.io/tools/katana/install"),
    "nuclei": ToolCapability("nuclei", "nuclei", ("scanner_observation",), "R3", ("deep",), "https://docs.projectdiscovery.io/tools/nuclei/install"),
    "ffuf": ToolCapability("ffuf", "ffuf", ("content_discovery",), "R3", ("deep",), "https://github.com/ffuf/ffuf"),
    "naabu": ToolCapability("naabu", "naabu", ("ports",), "R3", ("deep",), "https://docs.projectdiscovery.io/tools/naabu/install"),
    "nmap": ToolCapability("nmap", "nmap", ("service_enrichment",), "R3", ("deep",), "https://nmap.org/download.html"),
}

PROFILE_STAGES = {
    "passive": ("passive",),
    "light": ("passive", "dns", "http", "crawl", "burp", "score", "leads"),
    "standard": ("passive", "dns", "http", "historical", "crawl", "js", "burp", "technology", "score", "leads"),
    "deep": ("passive", "dns", "http", "historical", "crawl", "js", "burp", "technology", "nuclei", "ffuf", "ports", "score", "leads"),
}
STAGE_ACTION = {
    "passive": "passive_recon", "historical": "historical_url_recon",
    "dns": "active_recon", "http": "active_recon", "validate": "active_recon",
    "crawl": "crawl", "js": "crawl", "burp": "passive_recon",
    "technology": "passive_recon", "score": "passive_recon", "leads": "passive_recon",
    "nuclei": "bounded_scan", "ffuf": "bounded_scan", "ports": "bounded_scan",
}


@dataclass
class ReconResult:
    ok: bool
    mode: str
    stage: str
    profile: str = ""
    run_id: str = ""
    candidates: list[str] = field(default_factory=list)
    in_scope: list[str] = field(default_factory=list)
    filtered_count: int = 0
    leads: list[str] = field(default_factory=list)
    artifact: str = ""
    tools: list[dict] = field(default_factory=list)
    reason: str = ""
    counts: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def _probe_version(path: str, name: str) -> tuple[str, str, list[str]]:
    if name in {"assetfinder", "waybackurls"}:
        return "unknown (no safe local version probe)", "version probe skipped to avoid network activity", []
    observed: list[str] = []
    for args in (["-version"], ["--version"], ["version"]):
        try:
            proc = subprocess.run([path, *args], capture_output=True, text=True, timeout=4, check=False)
        except Exception:
            continue
        output = "\n".join(x for x in (proc.stdout, proc.stderr) if x).strip()
        if output:
            observed.append(output)
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if proc.returncode == 0 and lines:
            return lines[0][:200], "", observed
    return (observed[0].splitlines()[0][:200] if observed else ""), "", observed


def _executable_candidates(binary: str) -> list[str]:
    """Enumerate every executable candidate instead of stopping at PATH's first."""
    candidates: list[str] = []
    path_dirs = [Path(item) for item in os.environ.get("PATH", "").split(os.pathsep) if item]
    extra = Path.home() / ".local" / "bin"
    if extra not in path_dirs:
        path_dirs.append(extra)
    for directory in path_dirs:
        candidate = directory / binary
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                resolved = str(candidate.resolve())
                if resolved not in candidates:
                    candidates.append(resolved)
        except OSError:
            continue
    return candidates


def detect_recon_tools() -> dict[str, dict]:
    """Detect capabilities without downloading or invoking network-like probes."""
    result: dict[str, dict] = {}
    for name, spec in TOOL_REGISTRY.items():
        candidates = _executable_candidates(spec.binary)
        path = None
        item = {
            "name": name, "binary": spec.binary, "available": False,
            "installed": bool(candidates), "path": None, "detected_version": "", "version": "",
            "capabilities": list(spec.capabilities), "risk_class": spec.risk_class,
            "profiles": list(spec.profiles), "recommended_install_reference": spec.install, "note": "",
            "candidates": [],
        }
        for candidate in candidates:
            version, note, observed = _probe_version(candidate, name)
            accepted = True
            reason = note
            if name == "httpx":
                identity = "\n".join(observed).lower()
                if "projectdiscovery" not in identity and "current version" not in identity:
                    accepted = False
                    reason = "rejected: Python/non-ProjectDiscovery HTTPX CLI"
            item["candidates"].append({
                "path": candidate, "version": version,
                "selected": accepted and path is None, "reason": reason or ("selected" if accepted else "rejected"),
            })
            if accepted and path is None:
                path = candidate
                item["path"] = path
                item["available"] = True
                item["version"] = item["detected_version"] = version
                item["note"] = note
        if candidates and path is None and name == "httpx":
            item["note"] = "non-ProjectDiscovery httpx candidates ignored; no ProjectDiscovery candidate found"
        result[name] = item
    return result


def normalize_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not host or len(host) > 253 or any(ch in host for ch in "/?#@"):
        raise ValueError("invalid hostname")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid IDNA hostname") from exc
    labels = host.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        raise ValueError("invalid hostname")
    return host


def normalize_url(value: str) -> dict:
    """Return a secret-minimized URL observation and canonical endpoint pieces."""
    if len(value) > 8192:
        raise ValueError("URL too long")
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("absolute HTTP(S) URL required")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL userinfo forbidden")
    scheme, host = parsed.scheme.lower(), normalize_host(parsed.hostname)
    port = parsed.port
    if port == (443 if scheme == "https" else 80):
        port = None
    host_for_url = f"[{host}]" if ":" in host else host
    netloc = host_for_url + (f":{port}" if port else "")
    raw_path = parsed.path or "/"
    if re.search(r"%(?:2f|5c|00)", raw_path, re.I) or "\\" in raw_path:
        raise ValueError("ambiguous encoded path")
    decoded_path = unquote(raw_path)
    if re.search(r"%[0-9a-fA-F]{2}", decoded_path) or "//" in decoded_path or any(ord(ch) < 32 for ch in decoded_path):
        raise ValueError("ambiguous encoded path")
    trailing = decoded_path.endswith("/")
    normalized_path = posixpath.normpath(decoded_path)
    if not normalized_path.startswith("/"): normalized_path = "/" + normalized_path
    if trailing and normalized_path != "/": normalized_path += "/"
    path = quote(normalized_path, safe="/%:@!$&'()*+,;=-._~{}")
    keys = sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if key})
    canonical = urlunsplit((scheme, netloc, path, "&".join(f"{quote(k)}=" for k in keys), ""))
    return {"url": canonical, "scheme": scheme, "host": host, "port": port, "path": path, "query_keys": keys}


_PATH_ID = re.compile(r"(?i)^(?:[0-9]{4,}|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,})$")
_PATH_EMAIL = re.compile(r"^[^/@\s]+@[^/@\s]+\.[^/@\s]+$")
_PATH_OPAQUE = re.compile(r"^[A-Za-z0-9_-]{24,}$")


def normalize_endpoint_path(path: str) -> tuple[str, float]:
    """Conservatively shape high-confidence IDs; ordinary short numbers remain literal."""
    pieces, changed = [], False
    for piece in (path or "/").split("/"):
        if _PATH_ID.fullmatch(piece):
            pieces.append("{id}"); changed = True
        elif _PATH_EMAIL.fullmatch(unquote(piece)):
            pieces.append("{email}"); changed = True
        elif _PATH_OPAQUE.fullmatch(piece):
            pieces.append("{opaque}"); changed = True
        else:
            pieces.append(piece)
    shaped = "/".join(pieces) or "/"
    if not shaped.startswith("/"):
        shaped = "/" + shaped
    return shaped, (0.9 if changed else 1.0)


def extract_parameters(url: str) -> list[dict]:
    return [classify_parameter(name, "query") for name in normalize_url(url)["query_keys"]]


def classify_parameter(name: str, location: str) -> dict:
    lower = name.strip().lower()
    object_id = bool(re.search(r"(?:^|_)(?:id|uuid)$", lower) or lower in {"user", "account", "order", "invoice"})
    sensitive = bool(re.search(r"pass|secret|token|api.?key|authorization|cookie|session", lower))
    categories = []
    patterns = {
        "redirect": r"redirect|return|next|callback|continue|dest|url|uri",
        "file_path": r"file|path|folder|dir|upload|attachment",
        "money_quantity": r"amount|price|cost|quantity|qty|discount",
        "role_permission": r"role|permission|privilege|admin|scope",
        "pagination": r"page|limit|offset|cursor",
    }
    for category, pattern in patterns.items():
        if re.search(pattern, lower): categories.append(category)
    if object_id: categories.append("object_identifier")
    return {"name": name[:200], "location": location, "object_identifier_candidate": object_id, "sensitive_name": sensitive, "metadata": {"categories": categories}}


def _record_parameter(ctx, recon_run_id: int, endpoint_id: int, parameter: dict, **overrides) -> tuple[dict, bool]:
    payload = dict(parameter); payload.update(overrides)
    record, created = ctx.db.upsert_endpoint_parameter(endpoint_id=endpoint_id, **payload)
    if created:
        ctx.db.add_recon_change(recon_run_id=recon_run_id, change_type="NEW_PARAMETER", entity_type="endpoint_parameter", entity_id=record["id"], new_value=record["name"], interest_score=15)
    return record, created


def _record_technology(ctx, recon_run_id: int, **payload) -> tuple[dict, bool]:
    record, created = ctx.db.add_technology_observation(**payload)
    if created:
        ctx.db.add_recon_change(recon_run_id=recon_run_id, change_type="NEW_TECHNOLOGY", entity_type="technology_observation", entity_id=record["id"], new_value=record["technology"], interest_score=5)
    return record, created


def derive_passive_discovery_seeds(scope_or_engine) -> list[str]:
    """Derive passive roots without changing active ScopeEngine semantics."""
    model = getattr(scope_or_engine, "scope", scope_or_engine)
    include = getattr(model, "include", model)
    values: list[str] = []
    values += list(getattr(include, "domains", [])) + list(getattr(include, "subdomains", []))
    values += [w[2:] if w.startswith("*.") else w for w in getattr(include, "wildcards", [])]
    for url in list(getattr(include, "urls", [])) + list(getattr(include, "path_urls", [])):
        try: values.append(urlsplit(url).hostname or "")
        except ValueError: continue
    seeds = []
    for value in values:
        try: host = normalize_host(value)
        except ValueError: continue
        if host not in seeds: seeds.append(host)
    return seeds


def extract_js_signals(text: str, base_url: str = "") -> dict:
    """Deterministic string/route extraction; content remains untrusted data."""
    routes: set[str] = set()
    websockets: set[str] = set()
    params: set[str] = set()
    graphql_arguments: set[str] = set()
    source_maps: set[str] = set()
    route_names: set[str] = set()
    hostnames: set[str] = set()
    pattern = r"(?:(?:https?|wss?)://[^\s\"'`<>]+|/[A-Za-z0-9_~!$&'()*+,;=:@%./{}?-]{2,})"
    for match in re.findall(pattern, text[:2_000_000]):
        clean = match.rstrip("),;\"'")
        if clean.startswith(("ws://", "wss://")): websockets.add(clean); continue
        if clean.startswith("/") and not re.search(r"\.(?:png|jpe?g|gif|svg|css|woff2?)(?:\?|$)", clean, re.I):
            routes.add(urljoin(base_url, clean) if base_url else clean)
        elif clean.startswith(("http://", "https://")):
            routes.add(clean)
            try:
                host = urlsplit(clean).hostname
                if host: hostnames.add(normalize_host(host))
            except ValueError:
                pass
    for name in re.findall(r"[?&]([A-Za-z_][A-Za-z0-9_.-]{0,100})=", text): params.add(name)
    for name in re.findall(r"(?:(?:params|query|body)\s*\.\s*|[\"'])([A-Za-z_][A-Za-z0-9_.-]{1,100})(?:[\"']\s*:|\b)", text[:2_000_000]):
        if len(name) <= 100: params.add(name)
    for name in re.findall(r"\$([A-Za-z_][A-Za-z0-9_]{0,100})\s*:", text): graphql_arguments.add(name)
    for hint in re.findall(r"(?im)(?:sourceMappingURL\s*=\s*|[\"'])([^\s\"']+\.map)(?:[\"']|$)", text[:2_000_000]):
        source_maps.add(urljoin(base_url, hint) if base_url else hint)
    for name in re.findall(r"(?i)(?:route|path|name)\s*:\s*[\"']([A-Za-z0-9_.:/-]{2,120})[\"']", text[:2_000_000]):
        route_names.add(name)
    auth = sorted(url for url in routes if re.search(r"/(?:login|logout|auth|oauth|oidc|token|session|password|mfa)(?:/|\?|$)", url, re.I))
    uploads = sorted(url for url in routes if re.search(r"/(?:upload|attachment|import|media|file)(?:/|\?|$)", url, re.I))
    return {
        "urls": sorted(routes), "websockets": sorted(websockets),
        "parameter_names": sorted(params), "graphql_arguments": sorted(graphql_arguments),
        "source_maps": sorted(source_maps), "route_names": sorted(route_names),
        "auth_endpoints": auth, "upload_endpoints": uploads,
        "hostnames": sorted(hostnames),
    }


def fingerprint_text(text: str) -> list[dict]:
    markers = (
        ("Next.js", "framework", r"/_next/|__NEXT_DATA__"),
        ("React", "framework", r"react(?:\.production)?\.min\.js|data-reactroot"),
        ("Vue", "framework", r"vue(?:\.runtime)?(?:\.min)?\.js|data-v-"),
        ("Angular", "framework", r"ng-version|angular(?:\.min)?\.js"),
        ("GraphQL", "api", r"/graphql\b|__schema\b"),
        ("OpenAPI", "api_schema", r"openapi\s*[\"']?\s*:\s*[\"']?3\.|swagger-ui"),
    )
    return [{"technology": name, "category": category, "confidence": 0.7, "source": "content_marker"} for name, category, pattern in markers if re.search(pattern, text[:500000], re.I)]


def extract_html_forms(text: str, base_url: str) -> list[dict]:
    forms: list[dict] = []
    for attrs, body in re.findall(r"(?is)<form\b([^>]*)>(.*?)</form>", text[:1_000_000]):
        action = re.search(r"(?i)\baction\s*=\s*[\"']([^\"']*)", attrs)
        method = re.search(r"(?i)\bmethod\s*=\s*[\"']([^\"']*)", attrs)
        names = re.findall(r"(?i)<(?:input|select|textarea)\b[^>]*\bname\s*=\s*[\"']([^\"']+)", body)
        forms.append({"url": urljoin(base_url, action.group(1) if action else ""), "method": (method.group(1) if method else "GET").upper(), "parameter_names": sorted(set(names))})
    return forms


def ingest_openapi_document(ctx, document: dict | str, *, recon_run_id: int, base_url: str, source: str = "openapi") -> dict:
    try: spec = json.loads(document) if isinstance(document, str) else document
    except json.JSONDecodeError: return {"new_endpoints": 0, "parameters": 0}
    if not isinstance(spec, dict) or not (spec.get("openapi") or spec.get("swagger")):
        return {"new_endpoints": 0, "parameters": 0}
    new_endpoints = parameter_count = 0
    for path, path_item in list((spec.get("paths") or {}).items())[:1000]:
        if not isinstance(path_item, dict): continue
        common = path_item.get("parameters", [])
        for method, operation in path_item.items():
            if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} or not isinstance(operation, dict): continue
            endpoint, created = _record_url(ctx, recon_run_id, urljoin(base_url, str(path)), tool=source, source_type="api_schema", method=method.upper(), metadata={"schema_observed": True})
            if not endpoint: continue
            new_endpoints += int(created)
            for parameter in list(common) + list(operation.get("parameters", [])):
                if not isinstance(parameter, dict) or not parameter.get("name"): continue
                location = {"body": "json"}.get(str(parameter.get("in", "other")), str(parameter.get("in", "other")))
                _, created_param = _record_parameter(ctx, recon_run_id, endpoint["id"], classify_parameter(str(parameter["name"]), location), observed_types=[str((parameter.get("schema") or {}).get("type") or parameter.get("type") or "unknown")], user_controlled=True)
                parameter_count += int(created_param)
            content = (operation.get("requestBody") or {}).get("content", {})
            for media, detail in content.items():
                schema = detail.get("schema", {}) if isinstance(detail, dict) else {}
                for name, prop in (schema.get("properties") or {}).items():
                    _, created_param = _record_parameter(ctx, recon_run_id, endpoint["id"], classify_parameter(str(name), "json" if "json" in media else "form"), observed_types=[str(prop.get("type", "unknown"))] if isinstance(prop, dict) else [], user_controlled=True)
                    parameter_count += int(created_param)
            _record_technology(ctx, recon_run_id, asset_id=endpoint["host_asset_id"], endpoint_id=endpoint["id"], technology="OpenAPI", category="api_schema", confidence=0.95, source=source)
    return {"new_endpoints": new_endpoints, "parameters": parameter_count}


def _safe_raw(value: str) -> str:
    try:
        data = normalize_url(value)
        shaped, _ = normalize_endpoint_path(data["path"])
        parsed = urlsplit(data["url"])
        return urlunsplit((parsed.scheme, parsed.netloc, shaped, parsed.query, ""))
    except ValueError: return value.strip()[:2048]


def _command(stage: str, tool: str, seed: str, *, max_rps: float = 1.0, concurrency: int = 1) -> list[str]:
    rate, concurrency = max(1, int(max_rps)), max(1, min(int(concurrency), 10))
    if stage == "passive":
        if tool == "subfinder": return [tool, "-silent", "-d", seed, "-max-time", "2"]
        if tool == "assetfinder": return [tool, "--subs-only", seed]
        if tool == "amass": return [tool, "enum", "-passive", "-d", seed, "-timeout", "2"]
    if stage == "historical":
        if tool == "gau": return [tool, "--subs", "--threads", str(concurrency), seed]
        if tool == "waybackurls": return [tool, seed]
    if stage == "dns" and tool == "dnsx":
        return [tool, "-silent", "-json", "-a", "-aaaa", "-cname", "-retries", "1", "-rate-limit", str(rate)]
    if stage in {"http", "validate"} and tool == "httpx":
        return [tool, "-silent", "-json", "-status-code", "-title", "-content-type", "-server", "-tech-detect", "-ip", "-cname", "-tls-probe", "-favicon", "-rate-limit", str(rate), "-threads", str(concurrency), "-no-color"]
    if stage == "crawl" and tool == "katana":
        dangerous = r"(?i)(?:^|/)(?:logout|signout|delete|purchase|redeem|send|invite|checkout|transfer)(?:/|$)"
        return [tool, "-silent", "-jsonl", "-u", seed, "-d", "2", "-c", str(concurrency), "-rl", str(rate), "-fs", "fqdn", "-cos", dangerous, "-jc"]
    if stage == "nuclei" and tool == "nuclei":
        return [tool, "-silent", "-jsonl", "-u", seed, "-tags", "tech,exposure,misconfig", "-exclude-tags", "cve,intrusive,dos,fuzz,headless", "-rate-limit", str(rate), "-c", str(concurrency), "-bulk-size", "1", "-retries", "1", "-timeout", "5"]
    if stage == "ffuf" and tool == "ffuf":
        wordlist = str(Path(__file__).with_name("data") / "recon-small.txt")
        return [tool, "-s", "-w", wordlist, "-u", seed.rstrip("/") + "/FUZZ", "-rate", str(rate), "-t", str(concurrency), "-maxtime", "60", "-of", "json", "-o", "-"]
    if stage == "ports" and tool == "naabu":
        return [tool, "-silent", "-json", "-host", seed, "-top-ports", "100", "-rate", str(rate), "-c", str(concurrency), "-retries", "1"]
    if stage == "ports" and tool == "nmap":
        host, port = seed.rsplit(":", 1)
        return [tool, "-Pn", "-sV", "--version-light", "--max-retries", "1", "--host-timeout", "30s", "-p", port, "-oX", "-", host]
    raise ValueError(f"unsupported recon tool/stage: {stage}/{tool}")


def _run_tool(argv: list[str], *, stdin_lines: list[str] | None, timeout: int, max_lines: int) -> dict:
    try:
        proc = subprocess.run(argv, input=("\n".join(stdin_lines) + "\n" if stdin_lines else None), capture_output=True, text=True, timeout=max(1, min(timeout, 900)), check=False, shell=False)
        all_lines = proc.stdout.splitlines()
        return {"argv": argv, "exit_code": proc.returncode, "lines": all_lines[:max_lines], "stderr": proc.stderr[:4096], "partial": len(all_lines) > max_lines}
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return {"argv": argv, "exit_code": "timeout", "lines": output.splitlines()[:max_lines], "stderr": "timeout", "partial": True}


def _artifact_dir(ctx, public_id: str) -> Path:
    path = ctx.workspace / "recon" / "runs" / public_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_artifact(path: Path, lines: Iterable[str]) -> str:
    path.write_text("\n".join(_sanitize_artifact_line(str(line)) for line in lines) + "\n", encoding="utf-8")
    return str(path)


def _sanitize_artifact_line(line: str) -> str:
    """Redact common secrets and discard URL values while retaining shape."""
    sensitive = re.compile(r"pass|secret|token|api.?key|authorization|cookie|session", re.I)
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        value = None
    def clean(item: Any, key: str = "") -> Any:
        if sensitive.search(key): return "[REDACTED]"
        if isinstance(item, dict): return {str(k): clean(v, str(k)) for k, v in item.items()}
        if isinstance(item, list): return [clean(v, key) for v in item[:200]]
        if isinstance(item, str):
            if item.startswith(("http://", "https://")):
                try: return _safe_raw(item)
                except ValueError: pass
            return redact_text(item)
        return item
    if value is not None: return json.dumps(clean(value), separators=(",", ":"))
    stripped = line.strip()
    if stripped.startswith(("http://", "https://")):
        try: return _safe_raw(stripped)
        except ValueError: pass
    safe = re.sub(r"(?i)(Authorization|Cookie|Set-Cookie):\s*\S+", r"\1: [REDACTED]", stripped)
    return redact_text(safe)


def _record_host(ctx, run_id: int, host: str, *, tool: str, source_type: str, artifact: str = "", metadata: dict | None = None, owning_target: str = "") -> tuple[dict | None, bool]:
    try: normalized = normalize_host(host)
    except ValueError: return None, False
    scope_target = owning_target or f"https://{normalized}"
    if not ctx.scope.check(scope_target).allowed: return None, False
    scope_status = "in_scope" if not owning_target else "in_scope_via_url"
    asset, created = ctx.db.upsert_asset(type="host", value=host, normalized_value=normalized, scope_status=scope_status, confidence=0.6, metadata=metadata)
    if created:
        asset, _ = ctx.db.upsert_asset(type="host", value=host, normalized_value=normalized, scope_status=scope_status, confidence=0.6, metadata={**(metadata or {}), "newly_discovered": True, "discovery_run_id": run_id})
    elif asset.get("metadata", {}).get("discovery_run_id") != run_id:
        asset, _ = ctx.db.upsert_asset(type="host", value=host, normalized_value=normalized, scope_status=scope_status, confidence=0.6, metadata={**(metadata or {}), "newly_discovered": False})
    ctx.db.add_asset_observation(asset_id=asset["id"], recon_run_id=run_id, source_tool=tool, source_type=source_type, observation_type="host", raw_value=normalized, artifact_ref=artifact, metadata=metadata)
    if created: ctx.db.add_recon_change(recon_run_id=run_id, change_type="NEW_ASSET", entity_type="asset", entity_id=asset["id"], new_value=normalized, interest_score=15)
    return asset, created


def _record_url(ctx, run_id: int, url: str, *, tool: str, source_type: str, method: str = "GET", artifact: str = "", metadata: dict | None = None, auth_observed: bool = False, auth_required: bool | None = None, content_type: str = "") -> tuple[dict | None, bool]:
    try: data = normalize_url(url)
    except (ValueError, TypeError): return None, False
    if not ctx.scope.check(data["url"]).allowed: return None, False
    asset, _ = _record_host(ctx, run_id, data["host"], tool=tool, source_type=source_type, artifact=artifact, metadata=metadata, owning_target=data["url"])
    if not asset: return None, False
    shaped, confidence = normalize_endpoint_path(data["path"])
    parsed = urlsplit(data["url"])
    safe_url = urlunsplit((parsed.scheme, parsed.netloc, shaped, parsed.query, ""))
    url_asset, url_created = ctx.db.upsert_asset(type="url", value=safe_url, normalized_value=safe_url, scope_status="in_scope", confidence=0.7, metadata={"host_asset_id": asset["id"]})
    ctx.db.add_asset_observation(asset_id=url_asset["id"], recon_run_id=run_id, source_tool=tool, source_type=source_type, observation_type="url", raw_value=safe_url, artifact_ref=artifact, metadata=metadata)
    if url_created: ctx.db.add_recon_change(recon_run_id=run_id, change_type="NEW_ASSET", entity_type="asset", entity_id=url_asset["id"], new_value=safe_url, interest_score=10)
    observed_url = urlunsplit((parsed.scheme, parsed.netloc, data["path"], parsed.query, ""))
    emeta = dict(metadata or {}); emeta.update({
        "sources": [tool], "shape_confidence": confidence,
        "observed_url": _safe_raw(observed_url),
    })
    endpoint, created = ctx.db.upsert_endpoint(host_asset_id=asset["id"], scheme=data["scheme"], method=method, normalized_path=shaped, auth_required=auth_required, auth_observed=auth_observed, content_type=content_type, metadata=emeta)
    if created:
        endpoint, _ = ctx.db.upsert_endpoint(host_asset_id=asset["id"], scheme=data["scheme"], method=method, normalized_path=shaped, auth_required=auth_required, auth_observed=auth_observed, content_type=content_type, metadata={**emeta, "newly_discovered": True, "discovery_run_id": run_id})
        ctx.db.add_recon_change(recon_run_id=run_id, change_type="NEW_ENDPOINT", entity_type="endpoint", entity_id=endpoint["id"], new_value=f"{method.upper()} {data['host']}{shaped}", interest_score=20)
    elif endpoint.get("metadata", {}).get("discovery_run_id") != run_id:
        endpoint, _ = ctx.db.upsert_endpoint(host_asset_id=asset["id"], scheme=data["scheme"], method=method, normalized_path=shaped, auth_required=auth_required, auth_observed=auth_observed, content_type=content_type, metadata={**emeta, "newly_discovered": False})
    for param in (classify_parameter(name, "query") for name in data["query_keys"]):
        _record_parameter(ctx, run_id, endpoint["id"], param)
    for name in re.findall(r"\{([A-Za-z_][A-Za-z0-9_.-]{0,100})\}", shaped):
        _record_parameter(ctx, run_id, endpoint["id"], classify_parameter(name, "path"), user_controlled=True)
    return endpoint, created


def parse_dnsx_line(line: str) -> dict | None:
    try: raw = json.loads(line)
    except json.JSONDecodeError: return None
    host = raw.get("host") or raw.get("input")
    if not host: return None
    def values(key: str) -> list[str]:
        value = raw.get(key, [])
        return [str(item) for item in value] if isinstance(value, list) else ([str(value)] if value else [])
    cname = values("cname")
    providers = ("amazonaws.com", "azurewebsites.net", "github.io", "herokudns.com", "cloudfront.net", "fastly.net", "netlify.app")
    provider_hint = next((provider for provider in providers if any(str(name).lower().rstrip(".").endswith(provider) for name in cname)), "")
    a, aaaa = values("a"), values("aaaa")
    return {"host": host, "a": a, "aaaa": aaaa, "cname": cname, "provider_hint": provider_hint, "status": raw.get("status_code") or ("resolved" if any((a, aaaa, cname)) else "unresolved")}


def parse_httpx_line(line: str) -> dict | None:
    try: raw = json.loads(line)
    except json.JSONDecodeError: return None
    url = raw.get("url") or raw.get("input")
    if not url: return None
    tech = raw.get("tech", [])
    if isinstance(tech, str): tech = [tech]
    tls_raw = raw.get("tls", {}) if isinstance(raw.get("tls", {}), dict) else {}
    tls = {key: tls_raw.get(key) for key in ("subject_cn", "issuer_cn", "not_before", "not_after", "tls_version") if tls_raw.get(key) is not None}
    return {"url": url, "status_code": raw.get("status_code"), "title": redact_text(str(raw.get("title", ""))[:500]), "content_type": str(raw.get("content_type", ""))[:200], "server": redact_text(str(raw.get("webserver") or raw.get("server") or "")[:200]), "technologies": [str(item)[:200] for item in tech[:100]], "ip": raw.get("host_ip") or raw.get("a"), "cname": raw.get("cname"), "redirect": raw.get("location") or raw.get("final_url"), "favicon_hash": raw.get("favicon"), "tls": tls}


def parse_katana_line(line: str) -> dict | None:
    try:
        raw = json.loads(line)
        request = raw.get("request", {}) if isinstance(raw, dict) else {}
        endpoint = request.get("endpoint") or request.get("url") or raw.get("url")
        if endpoint: return {"url": endpoint, "method": request.get("method", "GET"), "source": raw.get("source", "")}
    except json.JSONDecodeError:
        pass
    return {"url": line.strip(), "method": "GET", "source": ""} if line.strip().startswith(("http://", "https://")) else None


def score_endpoint(endpoint: dict, parameters: list[dict], weights: dict[str, int] | None = None) -> tuple[int, list[str], list[str], str]:
    score, reasons, skills = 0, [], []
    weights = weights or {}
    path, method = endpoint["normalized_path"].lower(), endpoint["method"].upper()
    def add(key: str, points: int, reason: str):
        nonlocal score
        score += int(weights.get(key, points)); reasons.append(reason)
    if endpoint.get("auth_observed"): add("authenticated", 20, "authenticated surface")
    elif endpoint.get("auth_required"): add("auth_required", 10, "authentication-required surface")
    if "/api/" in path or path.startswith("/api") or endpoint.get("content_type", "").endswith("json"): add("api", 15, "API surface")
    if "graphql" in path: add("graphql", 24, "GraphQL endpoint"); skills.append("graphql")
    if any(x in path for x in ("swagger", "openapi", "api-docs")): add("api_schema", 22, "API schema")
    if any(x in path for x in ("admin", "manage", "internal")): add("admin_route", 18, "administrative route")
    if any(x in path for x in ("upload", "attachment", "import")): add("upload", 18, "file/upload surface"); skills.append("file-upload")
    if any(x in path for x in ("login", "reset", "oauth", "authorize", "token")): add("identity", 14, "identity surface"); skills.extend(["authentication", "oauth-oidc"])
    if method not in {"GET", "HEAD", "OPTIONS"}: add("state_changing", 15, "state-changing method")
    if any(p.get("object_identifier_candidate") for p in parameters): add("object_identifier", 22, "object identifier parameter"); skills.append("api-authorization")
    categories = {c for p in parameters for c in p.get("metadata", {}).get("categories", [])}
    if "role_permission" in categories: add("role_permission", 18, "role/permission parameter"); skills.append("access-control")
    if "redirect" in categories: add("redirect_callback", 12, "redirect/callback parameter"); skills.append("ssrf")
    if "file_path" in categories: add("file_path", 12, "file/path parameter"); skills.append("file-upload")
    if "money_quantity" in categories: add("business_operation", 12, "business-operation parameter"); skills.append("business-logic")
    if len(parameters) >= 4: add("parameter_rich", 8, "parameter-rich endpoint")
    if endpoint.get("metadata", {}).get("newly_discovered"): add("new_endpoint", 10, "newly discovered endpoint")
    if endpoint.get("metadata", {}).get("explicit_validation_seed"):
        add("explicit_validation_seed", 40, "explicitly requested validation surface")
    specialist = "recon-observer"
    if "api-authorization" in skills: specialist = "api-authz-specialist"
    elif any(s in skills for s in ("authentication", "oauth-oidc")): specialist = "auth-identity-specialist"
    elif "business-logic" in skills: specialist = "business-logic-specialist"
    elif endpoint.get("metadata", {}).get("source") == "javascript": specialist = "client-side-specialist"
    return min(score, 100), reasons, sorted(set(skills)), specialist


def score_inventory(ctx) -> dict:
    scored = 0
    weights = getattr(getattr(ctx.engagement, "recon", None), "interest_weights", {})
    offset = 0
    while True:
        batch = ctx.db.list_endpoints(limit=1000, offset=offset)
        if not batch: break
        for endpoint in batch:
            params = ctx.db.list_endpoint_parameters(endpoint["id"], limit=500)
            score, reasons, skills, specialist = score_endpoint(endpoint, params, weights)
            ctx.db.update_surface_score("endpoint", endpoint["id"], score, reasons, metadata_updates={"suggested_skills": skills, "suggested_specialist": specialist}); scored += 1
        offset += len(batch)
    offset = 0
    while True:
        assets = ctx.db.list_assets(limit=1000, offset=offset)
        if not assets: break
        for asset in assets:
            score, reasons = 0, []
            host = asset["normalized_value"].lower()
            if any(x in host for x in ("staging", "stage", "dev", "legacy", "internal")): score += int(weights.get("environment_name", 28)); reasons.append("environment/legacy naming")
            if any(x in host for x in ("api", "graphql")): score += int(weights.get("api_host", 18)); reasons.append("API-like host")
            if any(x in host for x in ("static", "cdn", "images", "analytics")): score += int(weights.get("static_host", -15)); reasons.append("static/supporting host")
            if asset.get("metadata", {}).get("newly_discovered"): score += int(weights.get("new_asset", 15)); reasons.append("newly discovered asset")
            dns = asset.get("metadata", {}).get("dns", {})
            if dns.get("cname") and not dns.get("a") and not dns.get("aaaa") and dns.get("provider_hint"):
                score += int(weights.get("takeover_candidate", 35)); reasons.append("unresolved provider CNAME takeover candidate (not a vulnerability)")
            ctx.db.update_surface_score("asset", asset["id"], max(0, score), reasons)
        offset += len(assets)
    return {"endpoints_scored": scored}


def generate_contextual_leads(ctx, recon_run_id: int, *, threshold: int = 40, limit: int = 30, endpoint_ids: set[int] | None = None) -> list[str]:
    existing = {(lead.entity, lead.source): lead for lead in ctx.db.list_leads()}
    made: list[str] = []
    for endpoint in ctx.db.list_endpoints(interesting=True, min_score=threshold, limit=limit):
        if endpoint_ids is not None and endpoint["id"] not in endpoint_ids: continue
        entity = f"{endpoint['method']} {endpoint['scheme']}://{endpoint['host']}{endpoint['normalized_path']}"
        source = "recon:inventory"
        prior = existing.get((entity, source))
        changes = ctx.db.recon_changes_for_endpoint(recon_run_id, endpoint["id"])
        meaningful = [c for c in changes if c["change_type"] in {"NEW_PARAMETER", "NEW_ENDPOINT", "STATUS_CHANGE", "REACTIVATED_ASSET"}]
        if prior is not None:
            if meaningful:
                try: rationale_data = json.loads(prior.rationale or "{}")
                except json.JSONDecodeError: rationale_data = {"previous_rationale": prior.rationale}
                rationale_data.update({
                    "latest_recon_run_id": f"RECON-{recon_run_id:03d}",
                    "interest_score": endpoint["interest_score"],
                    "recon_change_ids": [c["public_id"] for c in meaningful],
                    "change_reasons": [f"{c['change_type']}: {c['new_value']}" for c in meaningful],
                })
                ctx.db.update_lead(
                    prior.id, priority="high" if endpoint["interest_score"] >= 60 else prior.priority,
                    rationale=json.dumps(rationale_data, separators=(",", ":")),
                )
                for change in meaningful:
                    if prior.status == "closed":
                        prior = ctx.db.reopen_lead_for_recon_change(prior.id, change["id"])
                    else:
                        ctx.db.link_lead_recon_change(prior.id, change["id"])
                made.append(prior.public_id)
            continue
        reasons = endpoint.get("metadata", {}).get("interest_reasons", [])
        parameters = ctx.db.list_endpoint_parameters(endpoint["id"], limit=100)
        title_bits = []
        if endpoint.get("auth_observed"): title_bits.append("Authenticated")
        if any("object identifier" in x for x in reasons): title_bits.append("object-ID")
        if "graphql" in endpoint["normalized_path"].lower(): title_bits.append("GraphQL")
        if any(x in endpoint["normalized_path"].lower() for x in ("admin", "manage")): title_bits.append("administrative")
        title = " ".join(title_bits + ["research surface"]).strip().capitalize()
        account_hints = [
            account.id for account in ctx.engagement.accounts.accounts if account.enabled
        ][:10]
        rationale = json.dumps({
            "recon_run_id": f"RECON-{recon_run_id:03d}",
            "recon_change_ids": [change["public_id"] for change in changes],
            "asset_id": endpoint["host_asset_id"], "endpoint_id": endpoint["id"],
            "method": endpoint["method"], "normalized_path": endpoint["normalized_path"],
            "observed_url": endpoint.get("metadata", {}).get("observed_url", ""),
            "parameter_names": [item["name"] for item in parameters],
            "auth_context_hints": account_hints,
            "new_change_status": "new" if endpoint.get("metadata", {}).get("newly_discovered") else "known",
            "interest_score": endpoint["interest_score"], "reasons": reasons,
            "suggested_skills": endpoint.get("metadata", {}).get("suggested_skills", []),
            "suggested_specialist": endpoint.get("metadata", {}).get("suggested_specialist", "recon-observer"),
            "recommended_first_question": (
                "Does the same minimal read return an object owned by a different configured account?"
                if any(item.get("object_identifier_candidate") for item in parameters)
                else "What security boundary does one minimal differential observation test?"
            ),
        }, separators=(",", ":"))
        lead = ctx.db.add_lead(title, entity=entity, source=source, priority="high" if endpoint["interest_score"] >= 70 else "medium", rationale=rationale)
        for change in changes:
            ctx.db.link_lead_recon_change(lead.id, change["id"])
        made.append(lead.public_id); existing[(entity, source)] = lead
    remaining = 0 if endpoint_ids is not None else max(0, limit - len(made))
    for asset in ctx.db.list_assets(type="host", interesting=True, min_score=max(50, threshold), limit=remaining):
        entity, source = asset["normalized_value"], "recon:inventory"
        if (entity, source) in existing: continue
        reasons = asset.get("metadata", {}).get("interest_reasons", [])
        lead = ctx.db.add_lead(
            "High-interest host requiring surface triage", entity=entity, source=source,
            priority="high" if asset["interest_score"] >= 70 else "medium",
            rationale=json.dumps({"recon_run_id": f"RECON-{recon_run_id:03d}", "asset_id": asset["id"], "interest_score": asset["interest_score"], "reasons": reasons, "suggested_specialist": "recon-observer"}, separators=(",", ":")),
        )
        made.append(lead.public_id); existing.add((entity, source))
    return made


def _json_keys(value: Any, depth: int = 0) -> list[str]:
    if depth > 4: return []
    keys: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items(): keys.append(str(key)[:200]); keys.extend(_json_keys(child, depth + 1))
    elif isinstance(value, list) and value: keys.extend(_json_keys(value[0], depth + 1))
    return sorted(set(keys))


def ingest_burp_recon(ctx, result: Any, *, recon_run_id: int, auth_context: str = "", source_tool: str = "burp") -> dict:
    """Ingest structured/text history by owning request target, never body URLs."""
    items = result.get("items", result.get("content", [])) if isinstance(result, dict) else result
    if not isinstance(items, list): items = [items]
    endpoints, filtered = 0, 0
    for item in items:
        raw = item.get("text", "") if isinstance(item, dict) and item.get("type") == "text" else item
        if isinstance(raw, str):
            url_match = re.search(r"(?im)^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?://\S+|/\S*)", raw)
            host_match = re.search(r"(?im)^Host:\s*([^\s]+)", raw)
            method_match = re.search(r"(?im)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", raw)
            if not url_match: filtered += 1; continue
            candidate = url_match.group(1)
            if candidate.startswith("/"):
                if not host_match: filtered += 1; continue
                candidate = "https://" + host_match.group(1) + candidate
            method = method_match.group(1) if method_match else "GET"
            content_type_match = re.search(r"(?im)^Content-Type:\s*([^\r\n;]+)", raw)
            content_type = content_type_match.group(1).strip() if content_type_match else ""
            response_status = re.search(r"(?im)^HTTP/\d(?:\.\d)?\s+(\d{3})", raw)
            auth_required = bool(response_status and response_status.group(1) in {"401", "403"}) or None
            endpoint, created = _record_url(ctx, recon_run_id, candidate, tool=source_tool, source_type="burp_http", method=method, auth_observed=bool(auth_context), auth_required=auth_required, content_type=content_type, metadata={"auth_context": auth_context} if auth_context else {})
            if endpoint:
                endpoints += int(created)
                for cookie_name in re.findall(r"(?im)^(?:Cookie|Set-Cookie):\s*([A-Za-z0-9_.-]+)=", raw):
                    _record_technology(ctx, recon_run_id, asset_id=endpoint["host_asset_id"], endpoint_id=endpoint["id"], technology=f"cookie:{cookie_name}", category="auth_mechanism", confidence=0.6, source="burp_header")
                if re.search(r"(?im)^Authorization:\s*Bearer\b", raw):
                    _record_technology(ctx, recon_run_id, asset_id=endpoint["host_asset_id"], endpoint_id=endpoint["id"], technology="Bearer token", category="auth_mechanism", confidence=0.8, source="burp_header")
                body_match = re.search(r"\r?\n\r?\n(.+)$", raw[:200000], re.S)
                if body_match and "json" in content_type.lower():
                    try: keys = _json_keys(json.loads(body_match.group(1)))
                    except (json.JSONDecodeError, TypeError): keys = []
                    for key in keys: _record_parameter(ctx, recon_run_id, endpoint["id"], classify_parameter(key, "json"), user_controlled=True)
                if body_match and ("javascript" in content_type.lower() or urlsplit(candidate).path.lower().endswith((".js", ".mjs"))):
                    signals = extract_js_signals(body_match.group(1), candidate)
                    for discovered in signals["urls"]:
                        _record_url(ctx, recon_run_id, discovered, tool="javascript", source_type="javascript", metadata={"discovered_from_endpoint_id": endpoint["id"]})
                    for websocket in signals["websockets"]:
                        _record_url(ctx, recon_run_id, re.sub(r"^ws", "http", websocket), tool="javascript", source_type="javascript", metadata={"websocket": True, "discovered_from_endpoint_id": endpoint["id"]})
        elif isinstance(raw, dict):
            url = raw.get("url") or raw.get("request_url") or raw.get("target")
            if not url: filtered += 1; continue
            auth = raw.get("auth_context") or auth_context
            status = raw.get("status") or raw.get("status_code")
            endpoint, created = _record_url(ctx, recon_run_id, url, tool=source_tool, source_type="burp_http", method=raw.get("method", "GET"), auth_observed=bool(auth), auth_required=True if status in {401, 403, "401", "403"} else None, content_type=raw.get("response_content_type") or raw.get("content_type", ""), metadata={"auth_context": auth} if auth else {})
            endpoints += int(bool(endpoint and created))
            if endpoint:
                for key in raw.get("json_keys", []): _record_parameter(ctx, recon_run_id, endpoint["id"], classify_parameter(str(key), "json"), user_controlled=True)
                for key in raw.get("form_keys", []): _record_parameter(ctx, recon_run_id, endpoint["id"], classify_parameter(str(key), "form"), user_controlled=True)
        else: filtered += 1
    return {"new_endpoints": endpoints, "filtered_items": filtered}


def ingest_burp_websocket_recon(ctx, result: Any, *, recon_run_id: int, auth_context: str = "") -> dict:
    items = result.get("items", result.get("content", [])) if isinstance(result, dict) else result
    if not isinstance(items, list): items = [items]
    observed = 0
    for item in items:
        text = item.get("text") or item.get("message") or "" if isinstance(item, dict) else str(item)
        explicit_url = (item.get("url") or item.get("websocket_url") or "") if isinstance(item, dict) else ""
        match = re.search(r"wss?://[^\s\"'<>]+", explicit_url or text)
        if not match: continue
        metadata = {"websocket": True}
        if auth_context: metadata["auth_context"] = auth_context
        if isinstance(item, dict) and item.get("direction"): metadata["direction"] = str(item["direction"])[:40]
        try: metadata["message_keys"] = _json_keys(json.loads(text))
        except (json.JSONDecodeError, TypeError): pass
        endpoint, _ = _record_url(ctx, recon_run_id, re.sub(r"^ws", "http", match.group(0)), tool="burp", source_type="burp_websocket", metadata=metadata, auth_observed=bool(auth_context))
        if endpoint: observed += 1
    return {"websockets_observed": observed}


def get_recon_summary(ctx, *, limit: int = 10) -> dict:
    latest = ctx.db.list_recon_runs(status="completed", limit=1)
    counts = ctx.db.recon_counts(recon_run_id=latest[0]["id"] if latest else None)
    changes = counts.get("changes", {})
    return {
        "program": ctx.slug, "content_trust": "UNTRUSTED_TARGET_DATA", "latest_run": latest[0]["public_id"] if latest else None,
        "hosts": {"total": counts["hosts"], "interesting": counts["interesting_hosts"]},
        "endpoints": {"total": counts["endpoints"], "authenticated": counts["authenticated_endpoints"], "state_changing": counts["state_changing_endpoints"], "object_id_surfaces": counts["object_id_surfaces"]},
        "parameters": {"total": counts["parameters"]},
        "new_since_last_run": {kind: int(changes.get(kind, 0)) for kind in ("NEW_ASSET", "NEW_ENDPOINT", "NEW_PARAMETER", "NEW_TECHNOLOGY", "NEW_PORT", "STATUS_CHANGE", "REMOVED_ASSET", "REACTIVATED_ASSET")},
        "top_research_surfaces": [{"id": e["public_id"], "method": e["method"], "host": e["host"], "path": e["normalized_path"], "score": e["interest_score"], "reasons": e.get("metadata", {}).get("interest_reasons", [])} for e in ctx.db.list_endpoints(interesting=True, limit=limit)],
    }


def recon_is_fresh(ctx, profile: str, max_age_hours: int | None = None) -> bool:
    from datetime import datetime, timezone
    config = getattr(ctx.engagement, "recon", None)
    ages = {name: getattr(config, f"{name}_max_age_hours", default) for name, default in {"passive": 24, "light": 12, "standard": 24, "deep": 168}.items()}
    runs = [run for run in ctx.db.list_recon_runs(status="completed", limit=100) if run["profile"] == profile]
    if not runs: return False
    stamp = datetime.fromisoformat(runs[0]["completed_at"].replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - stamp).total_seconds() <= 3600 * (max_age_hours or ages.get(profile, 24))


def _reconcile_run_changes(ctx, run: dict, profile: str, inactive_before: set[int], *, complete: bool) -> dict:
    current_obs = ctx.db.list_asset_observations(recon_run_id=run["id"], limit=2000)
    current_ids = {item["asset_id"] for item in current_obs}
    reactivated = 0
    for asset_id in current_ids & inactive_before:
        asset = ctx.db.get_asset(asset_id)
        ctx.db.add_recon_change(recon_run_id=run["id"], change_type="REACTIVATED_ASSET", entity_type="asset", entity_id=asset_id, old_value="inactive", new_value=asset["normalized_value"], interest_score=20)
        reactivated += 1
    previous = [item for item in ctx.db.list_recon_runs(limit=100) if item["id"] != run["id"] and item["profile"] == profile and item["status"] == "completed"]
    removed = 0
    if complete and profile and previous:
        previous_ids = {item["asset_id"] for item in ctx.db.list_asset_observations(recon_run_id=previous[0]["id"], limit=2000)}
        for asset_id in previous_ids - current_ids:
            asset = ctx.db.set_asset_active(asset_id, False)
            ctx.db.add_recon_change(recon_run_id=run["id"], change_type="REMOVED_ASSET", entity_type="asset", entity_id=asset_id, old_value=asset["normalized_value"], new_value="inactive", interest_score=5)
            removed += 1
        previous_http = {item["asset_id"]: item.get("metadata", {}).get("status_code") for item in ctx.db.list_asset_observations(recon_run_id=previous[0]["id"], limit=2000) if item["source_tool"] == "httpx"}
        current_http = {item["asset_id"]: item.get("metadata", {}).get("status_code") for item in current_obs if item["source_tool"] == "httpx"}
        for asset_id in previous_http.keys() & current_http.keys():
            if previous_http[asset_id] is not None and previous_http[asset_id] != current_http[asset_id]:
                ctx.db.add_recon_change(recon_run_id=run["id"], change_type="STATUS_CHANGE", entity_type="asset", entity_id=asset_id, old_value=str(previous_http[asset_id]), new_value=str(current_http[asset_id]), interest_score=10)
    return {"removed_assets": removed, "reactivated_assets": reactivated}


def _active_seeds(ctx, seeds: list[str]) -> tuple[list[str], str | None]:
    safe: list[str] = []
    for seed in seeds:
        target = seed if "://" in seed else f"https://{seed}"
        if not ctx.scope.check(target).allowed: return [], f"seed is out of scope: {seed}"
        try:
            data = normalize_url(target)
            shaped, _ = normalize_endpoint_path(data["path"])
            if shaped != data["path"]:
                return [], f"seed path may contain an identifier/secret and is unsafe for bulk recon: {seed}"
            parsed = urlsplit(data["url"])
            safe.append(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")))
        except ValueError:
            return [], f"invalid active seed: {seed}"
    return safe, None


def _inventory_active_seeds(ctx, *, include_urls: bool, limit: int) -> list[str]:
    candidates: list[str] = []
    if include_urls:
        candidates.extend(asset["normalized_value"] for asset in ctx.db.list_assets(type="url", limit=limit))
    candidates.extend(f"https://{asset['normalized_value']}" for asset in ctx.db.list_assets(type="host", limit=limit))
    safe: list[str] = []
    for candidate in candidates:
        if ctx.scope.check(candidate).allowed and candidate not in safe:
            safe.append(candidate)
        if len(safe) >= limit: break
    return safe


def _configured_active_seeds(ctx, *, limit: int) -> list[str]:
    """Seed active validation from exact configured scope, preserving URL ports."""
    include = ctx.engagement.scope.include
    candidates = list(include.urls) + list(include.path_urls)
    exact_hosts = {
        (urlsplit(value).hostname or "").lower()
        for value in candidates
        if value.startswith(("http://", "https://"))
    }
    candidates.extend(
        f"https://{host}" for host in list(include.domains) + list(include.subdomains)
        if host.lower() not in exact_hosts
    )
    candidates.extend(
        f"https://{address}" for address in include.ipv4 if address not in exact_hosts
    )
    candidates.extend(
        f"https://[{address}]" for address in getattr(include, "ipv6", [])
        if address.lower() not in exact_hosts
    )
    safe, _ = _active_seeds(ctx, candidates[:limit])
    return safe


def _non_public_host(value: str) -> bool:
    """True for fixture/IP names where public passive/archive tools are inapplicable."""
    host = (urlsplit(value).hostname or value).strip("[]").lower().rstrip(".")
    if host in {"localhost", "::1"} or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(address.is_loopback or address.is_private or address.is_link_local or address.is_reserved)


def _program_is_non_public(ctx) -> bool:
    return bool(
        _configured_active_seeds(ctx, limit=500)
        and all(_non_public_host(seed) for seed in _configured_active_seeds(ctx, limit=500))
    )


def _execute_stage(ctx, run: dict, stage: str, seeds: list[str], *, session_id: int, max_results: int, timeout_seconds: int, broker=None, detected: dict | None = None, concurrency_limit: int | None = None) -> dict:
    detected = detected or detect_recon_tools()
    run_dir = _artifact_dir(ctx, run["public_id"])
    raw_count = new_assets = updated_assets = new_endpoints = filtered = 0
    tools_used: list[dict] = []; errors: list[str] = []; candidates: list[str] = []
    roe = ctx.engagement.roe
    concurrency = min(roe.max_concurrency, concurrency_limit or roe.max_concurrency)
    if stage in {"passive", "historical"}:
        tool_names = PASSIVE_TOOLS if stage == "passive" else HISTORICAL_TOOLS
        passive_seeds = [normalize_host(urlsplit(s).hostname or s) for s in seeds] if seeds else derive_passive_discovery_seeds(ctx.engagement.scope)
        local_only = bool(passive_seeds) and all(_non_public_host(seed) for seed in passive_seeds)
        if local_only:
            # Public passive/archive providers have no meaningful data for
            # loopback, private IPs, or reserved fixture names. Seed the exact
            # configured URLs so later brokered stages retain ports and paths.
            tools_used.append({"tool": "scope-config", "mode": f"{stage}-seed", "reason": "non-public scope"})
            if stage == "passive":
                for target in _configured_active_seeds(ctx, limit=max_results):
                    endpoint, created = _record_url(
                        ctx, run["id"], target, tool="scope-config", source_type="configured_scope",
                    )
                    if endpoint:
                        candidates.append(_safe_raw(target)); new_endpoints += int(created)
        else:
            for tool in tool_names:
                if not detected[tool]["available"]: continue
                for seed in passive_seeds:
                    execution = _run_tool(_command(stage, tool, seed, max_rps=roe.max_rps, concurrency=concurrency), stdin_lines=None, timeout=timeout_seconds, max_lines=max_results)
                    artifact = _write_artifact(run_dir / f"{stage}-{tool}-{hashlib.sha256(seed.encode()).hexdigest()[:8]}.txt", execution["lines"])
                    tools_used.append({"tool": tool, "version": detected[tool]["version"], "arguments": execution["argv"][1:], "exit_code": execution["exit_code"], "artifact_ref": artifact})
                    if execution["exit_code"] not in {0}: errors.append(f"{tool} exit={execution['exit_code']}")
                    for line in execution["lines"]:
                        raw_count += 1
                        if stage == "passive":
                            asset, created = _record_host(ctx, run["id"], line.strip(), tool=tool, source_type="passive", artifact=artifact)
                            if asset: candidates.append(asset["normalized_value"]); new_assets += int(created); updated_assets += int(not created)
                            else: filtered += 1
                        else:
                            endpoint, created = _record_url(ctx, run["id"], line.strip(), tool=tool, source_type="archive", artifact=artifact)
                            if endpoint: candidates.append(_safe_raw(line)); new_endpoints += int(created)
                            else: filtered += 1
            if not tools_used: errors.append(f"no {stage} tool is installed")
    elif stage in {"dns", "http"}:
        defaults = _inventory_active_seeds(ctx, include_urls=stage == "http", limit=max_results)
        if not defaults:
            defaults = _configured_active_seeds(ctx, limit=max_results)
        active, error = _active_seeds(ctx, seeds or defaults)
        if error: return {"mode": "DENY", "errors": [error]}
        if not active:
            return {"mode": "AUTO", "raw_count": 0, "new_assets": 0, "updated_assets": 0, "new_endpoints": 0, "filtered": 0, "tools_used": [], "errors": [f"no in-scope active seeds for {stage}"], "candidates": []}
        tool = "dnsx" if stage == "dns" else "httpx"
        non_public_active = all(_non_public_host(item) for item in active)
        loopback_http = stage == "http" and all(
            (urlsplit(item).hostname or "") in {"127.0.0.1", "localhost", "::1"}
            for item in active
        )
        if detected[tool]["available"] and roe.max_rps >= 1 and not loopback_http and not (stage == "dns" and non_public_active) and not (roe.required_headers and stage != "dns"):
            inputs = [urlsplit(s).hostname or s for s in active] if stage == "dns" else active
            execution = _run_tool(_command(stage, tool, "", max_rps=roe.max_rps, concurrency=concurrency), stdin_lines=inputs, timeout=timeout_seconds, max_lines=max_results)
            artifact = _write_artifact(run_dir / f"{tool}.jsonl", execution["lines"])
            tools_used.append({"tool": tool, "version": detected[tool]["version"], "arguments": execution["argv"][1:], "exit_code": execution["exit_code"], "artifact_ref": artifact})
            if execution["exit_code"] != 0: errors.append(f"{tool} exit={execution['exit_code']}")
            for line in execution["lines"]:
                raw_count += 1
                if tool == "dnsx":
                    item = parse_dnsx_line(line)
                    if not item: filtered += 1; continue
                    asset, created = _record_host(ctx, run["id"], item["host"], tool=tool, source_type="dns", artifact=artifact, metadata={"dns": item})
                    if asset:
                        new_assets += int(created); updated_assets += int(not created)
                        for ip in item["a"] + item["aaaa"]:
                            try: normalized_ip = str(ipaddress.ip_address(ip))
                            except ValueError: continue
                            ip_asset, ip_new = ctx.db.upsert_asset(type="ip", value=normalized_ip, normalized_value=normalized_ip, scope_status="derived_not_active_authority", confidence=0.8, metadata={"resolved_from": item["host"]})
                            ctx.db.add_asset_observation(asset_id=ip_asset["id"], recon_run_id=run["id"], source_tool=tool, source_type="dns", observation_type="resolution", raw_value=normalized_ip, artifact_ref=artifact)
                            if ip_new: ctx.db.add_recon_change(recon_run_id=run["id"], change_type="NEW_ASSET", entity_type="asset", entity_id=ip_asset["id"], new_value=normalized_ip, interest_score=5)
                            new_assets += int(ip_new)
                    else: filtered += 1
                else:
                    item = parse_httpx_line(line)
                    if not item: filtered += 1; continue
                    http_metadata = {k: v for k, v in item.items() if k not in {"url", "technologies", "redirect"}}
                    if seeds:
                        http_metadata["explicit_validation_seed"] = True
                    if item.get("redirect"):
                        target = urljoin(item["url"], str(item["redirect"]))
                        http_metadata["redirect"] = {
                            "target": _safe_raw(target),
                            "scope_status": "in_scope" if ctx.scope.check(target).allowed else "out_of_scope",
                        }
                    endpoint, created = _record_url(ctx, run["id"], item["url"], tool=tool, source_type="http", artifact=artifact, auth_required=True if item["status_code"] in {401, 403, "401", "403"} else None, content_type=item["content_type"], metadata=http_metadata)
                    if not endpoint: filtered += 1; continue
                    new_endpoints += int(created); candidates.append(_safe_raw(item["url"])); asset_id = endpoint["host_asset_id"]
                    for tech in item["technologies"]:
                        _record_technology(ctx, run["id"], asset_id=asset_id, endpoint_id=endpoint["id"], technology=str(tech)[:200], category="httpx", confidence=0.8, source="httpx")
                    if item["server"]:
                        _record_technology(ctx, run["id"], asset_id=asset_id, endpoint_id=endpoint["id"], technology=item["server"], category="server", confidence=0.7, source="http_header")
        if stage == "http" and not candidates:
            if roe.required_headers:
                errors.append("ProjectDiscovery httpx bypassed: mandatory headers kept inside the Request Broker secret seam")
            elif not detected[tool]["available"]:
                errors.append("ProjectDiscovery httpx unavailable; used bounded Request Broker fallback")
            elif roe.max_rps < 1:
                errors.append("ProjectDiscovery httpx bypassed: fractional max_rps enforced by Request Broker fallback")
            elif loopback_http:
                errors.append("ProjectDiscovery httpx bypassed for deterministic loopback fixture; used Request Broker")
            active_broker = broker or ctx.broker()
            for target in active[:max_results]:
                result = active_broker.execute(target=target, method="HEAD", action="active_recon", session_id=session_id, agent_role="recon-executor", allow_redirects=True, timeout=min(timeout_seconds, 30))
                tools_used.append({"tool": "request-broker", "target": target, "decision": result.decision, "status": result.status_code, "evidence_id": result.evidence_id})
                if result.ok:
                    endpoint, created = _record_url(ctx, run["id"], result.url, tool="request-broker", source_type="http", metadata={"explicit_validation_seed": True})
                    new_endpoints += int(bool(endpoint and created))
        elif stage == "dns" and not non_public_active and (not detected[tool]["available"] or roe.max_rps < 1):
            errors.append(f"{tool} unavailable or cannot enforce max_rps below 1")
    elif stage == "crawl":
        active, error = _active_seeds(ctx, seeds or _inventory_active_seeds(ctx, include_urls=True, limit=min(max_results, 50)))
        if error: return {"mode": "DENY", "errors": [error]}
        if not active:
            return {"mode": "AUTO", "raw_count": 0, "new_assets": 0, "updated_assets": 0, "new_endpoints": 0, "filtered": 0, "tools_used": [], "errors": ["no in-scope active seeds for crawl"], "candidates": []}
        non_public_active = all(_non_public_host(item) for item in active)
        if detected["katana"]["available"] and roe.max_rps >= 1 and not roe.required_headers and not non_public_active:
            for target in active[:50]:
                execution = _run_tool(_command("crawl", "katana", target, max_rps=roe.max_rps, concurrency=concurrency), stdin_lines=None, timeout=timeout_seconds, max_lines=max_results)
                artifact = _write_artifact(run_dir / f"katana-{hashlib.sha256(target.encode()).hexdigest()[:8]}.jsonl", execution["lines"])
                tools_used.append({"tool": "katana", "version": detected["katana"]["version"], "arguments": execution["argv"][1:], "exit_code": execution["exit_code"], "artifact_ref": artifact})
                if execution["exit_code"] != 0: errors.append(f"katana exit={execution['exit_code']}")
                for line in execution["lines"]:
                    raw_count += 1; item = parse_katana_line(line)
                    if not item: filtered += 1; continue
                    endpoint, created = _record_url(ctx, run["id"], item["url"], tool="katana", source_type="crawl", method=item["method"], artifact=artifact)
                    if endpoint: new_endpoints += int(created); candidates.append(_safe_raw(item["url"]))
                    else: filtered += 1
        else:
            if roe.required_headers:
                errors.append("Katana bypassed: mandatory headers kept inside the Request Broker secret seam")
            elif not detected["katana"]["available"]:
                errors.append("Katana unavailable; used shallow Request Broker fallback")
            elif roe.max_rps < 1:
                errors.append("Katana bypassed: fractional max_rps enforced by Request Broker fallback")
            elif non_public_active:
                errors.append("Katana bypassed for deterministic non-public fixture; used Request Broker fallback")
            active_broker = broker or ctx.broker()
            for target in active[:min(20, max_results)]:
                result = active_broker.execute(target=target, method="GET", action="crawl", session_id=session_id, agent_role="recon-executor", allow_redirects=True, timeout=min(timeout_seconds, 30))
                tools_used.append({"tool": "request-broker-fallback", "target": target, "decision": result.decision, "status": result.status_code, "evidence_id": result.evidence_id})
                if not result.ok: continue
                urls = [result.url]
                urls.extend(urljoin(result.url, x) for x in re.findall(r"(?i)(?:href|src)=[\"']([^\"']+)", result.body_preview))
                js_signals = extract_js_signals(result.body_preview, result.url)
                urls.extend(js_signals["urls"])
                forms = extract_html_forms(result.body_preview, result.url)
                root_endpoint, _ = _record_url(ctx, run["id"], result.url, tool="fallback-crawler", source_type="crawl")
                if root_endpoint:
                    for fingerprint in fingerprint_text(result.body_preview):
                        _record_technology(ctx, run["id"], asset_id=root_endpoint["host_asset_id"], endpoint_id=root_endpoint["id"], **fingerprint)
                try:
                    schema_stats = ingest_openapi_document(ctx, result.body_preview, recon_run_id=run["id"], base_url=result.url)
                    new_endpoints += schema_stats["new_endpoints"]
                except (TypeError, ValueError):
                    pass
                for form in forms:
                    form_endpoint, created = _record_url(ctx, run["id"], form["url"], tool="html-form", source_type="crawl", method=form["method"])
                    if form_endpoint:
                        new_endpoints += int(created)
                        location = "query" if form["method"] == "GET" else "form"
                        for name in form["parameter_names"]:
                            _record_parameter(ctx, run["id"], form_endpoint["id"], classify_parameter(name, location), user_controlled=True)
                for url in urls[:max_results]:
                    endpoint, created = _record_url(ctx, run["id"], url, tool="fallback-crawler", source_type="crawl")
                    if endpoint:
                        new_endpoints += int(created); candidates.append(_safe_raw(url))
                        if "graphql" in endpoint["normalized_path"].lower():
                            for name in js_signals["graphql_arguments"]:
                                _record_parameter(ctx, run["id"], endpoint["id"], classify_parameter(name, "graphql_argument"), user_controlled=True)
                    else: filtered += 1
    elif stage == "burp":
        if _program_is_non_public(ctx):
            return {"mode": "AUTO", "raw_count": 0, "new_assets": 0, "updated_assets": 0, "new_endpoints": 0, "filtered": 0, "tools_used": [{"tool": "burp-mcp", "mode": "skipped", "reason": "non-public fixture isolation"}], "errors": [], "candidates": []}
        try:
            from .config import get_config
            from .integrations.burp import BurpMCPClient
            client = BurpMCPClient(get_config().burp_mcp or "http://127.0.0.1:9876")
            try:
                client.connect(); names = {t.get("name") for t in client.tools}
                if "get_proxy_http_history" in names:
                    stats = ingest_burp_recon(ctx, client.call_read_tool("get_proxy_http_history", {"count": min(max_results, 500), "offset": 0}), recon_run_id=run["id"])
                    new_endpoints += stats["new_endpoints"]; filtered += stats["filtered_items"]
                if "get_proxy_websocket_history" in names:
                    ingest_burp_websocket_recon(ctx, client.call_read_tool("get_proxy_websocket_history", {"count": min(max_results, 500), "offset": 0}), recon_run_id=run["id"])
                tools_used.append({"tool": "burp-mcp", "mode": "read-only history"})
            finally: client.close()
        except Exception as exc: errors.append(f"Burp ingest unavailable: {type(exc).__name__}: {exc}")
    elif stage == "nuclei":
        active, error = _active_seeds(ctx, seeds)
        if error: return {"mode": "DENY", "errors": [error]}
        if not active:
            return {"mode": "AUTO", "raw_count": 0, "new_assets": 0, "updated_assets": 0, "new_endpoints": 0, "filtered": 0, "tools_used": [], "errors": ["nuclei requires an explicit approved in-scope target"], "candidates": []}
        if detected["nuclei"]["available"] and roe.max_rps >= 1:
            for target in active[:20]:
                execution = _run_tool(_command("nuclei", "nuclei", target, max_rps=roe.max_rps, concurrency=concurrency), stdin_lines=None, timeout=timeout_seconds, max_lines=max_results)
                artifact = _write_artifact(run_dir / f"nuclei-{hashlib.sha256(target.encode()).hexdigest()[:8]}.jsonl", execution["lines"])
                tools_used.append({"tool": "nuclei", "arguments": execution["argv"][1:], "exit_code": execution["exit_code"], "artifact_ref": artifact, "semantics": "observation/lead only"})
                for line in execution["lines"]:
                    raw_count += 1
                    try: item = json.loads(line)
                    except json.JSONDecodeError: continue
                    url = item.get("matched-at") or item.get("host")
                    endpoint, _ = _record_url(ctx, run["id"], url, tool="nuclei", source_type="scanner_observation", artifact=artifact, metadata={"template_id": item.get("template-id"), "scanner_severity": item.get("info", {}).get("severity")}) if url else (None, False)
                    if endpoint: ctx.db.update_surface_score("endpoint", endpoint["id"], max(endpoint["interest_score"], 40), ["scanner observation requiring independent hypothesis validation"])
        else: errors.append("nuclei unavailable or cannot enforce max_rps below 1")
    elif stage == "ffuf":
        active, error = _active_seeds(ctx, seeds or _inventory_active_seeds(ctx, include_urls=True, limit=20))
        if error: return {"mode": "DENY", "errors": [error]}
        if not active:
            return {"mode": "AUTO", "raw_count": 0, "new_assets": 0, "updated_assets": 0, "new_endpoints": 0, "filtered": 0, "tools_used": [], "errors": ["ffuf requires an explicit approved in-scope target"], "candidates": []}
        if detected["ffuf"]["available"] and roe.max_rps >= 1:
            for target in active[:10]:
                execution = _run_tool(_command("ffuf", "ffuf", target, max_rps=roe.max_rps, concurrency=concurrency), stdin_lines=None, timeout=min(timeout_seconds, 90), max_lines=max_results)
                artifact = _write_artifact(run_dir / f"ffuf-{hashlib.sha256(target.encode()).hexdigest()[:8]}.json", execution["lines"])
                tools_used.append({"tool": "ffuf", "arguments": execution["argv"][1:], "exit_code": execution["exit_code"], "artifact_ref": artifact})
                try: payload = json.loads("\n".join(execution["lines"])); results = payload.get("results", [])
                except json.JSONDecodeError: results = []
                for item in results[:max_results]:
                    endpoint, created = _record_url(ctx, run["id"], item.get("url", ""), tool="ffuf", source_type="content_discovery", artifact=artifact, metadata={"status": item.get("status"), "length": item.get("length")})
                    if endpoint: new_endpoints += int(created)
        else: errors.append("ffuf unavailable or cannot enforce max_rps below 1")
    elif stage == "ports":
        active, error = _active_seeds(ctx, seeds or _inventory_active_seeds(ctx, include_urls=False, limit=20))
        if error: return {"mode": "DENY", "errors": [error]}
        if not active:
            return {"mode": "AUTO", "raw_count": 0, "new_assets": 0, "updated_assets": 0, "new_endpoints": 0, "filtered": 0, "tools_used": [], "errors": ["port discovery requires an explicit approved in-scope host"], "candidates": []}
        discovered_services: list[tuple[dict, str]] = []
        if detected["naabu"]["available"] and roe.max_rps >= 1:
            for target in active[:20]:
                host = urlsplit(target).hostname or target
                execution = _run_tool(_command("ports", "naabu", host, max_rps=roe.max_rps, concurrency=concurrency), stdin_lines=None, timeout=timeout_seconds, max_lines=max_results)
                artifact = _write_artifact(run_dir / f"naabu-{hashlib.sha256(host.encode()).hexdigest()[:8]}.jsonl", execution["lines"])
                tools_used.append({"tool": "naabu", "arguments": execution["argv"][1:], "exit_code": execution["exit_code"], "artifact_ref": artifact})
                for line in execution["lines"]:
                    try: item = json.loads(line); port = int(item.get("port")); found_host = normalize_host(item.get("host") or item.get("ip") or host)
                    except (json.JSONDecodeError, ValueError, TypeError): continue
                    service, created = ctx.db.upsert_asset(type="service", value=f"{found_host}:{port}", normalized_value=f"{found_host}:{port}", scope_status="derived_from_in_scope_host", confidence=0.7, metadata={"host": found_host, "port": port})
                    ctx.db.add_asset_observation(asset_id=service["id"], recon_run_id=run["id"], source_tool="naabu", source_type="port", observation_type="service", raw_value=f"{found_host}:{port}", artifact_ref=artifact)
                    if created:
                        ctx.db.add_recon_change(recon_run_id=run["id"], change_type="NEW_ASSET", entity_type="asset", entity_id=service["id"], new_value=service["normalized_value"], interest_score=10)
                        ctx.db.add_recon_change(recon_run_id=run["id"], change_type="NEW_PORT", entity_type="asset", entity_id=service["id"], new_value=str(port), interest_score=15)
                    discovered_services.append((service, f"{found_host}:{port}"))
            if detected["nmap"]["available"]:
                for service, address in discovered_services[:10]:
                    execution = _run_tool(_command("ports", "nmap", address), stdin_lines=None, timeout=min(timeout_seconds, 40), max_lines=2000)
                    artifact = _write_artifact(run_dir / f"nmap-{hashlib.sha256(address.encode()).hexdigest()[:8]}.xml", execution["lines"])
                    tools_used.append({"tool": "nmap", "arguments": execution["argv"][1:], "exit_code": execution["exit_code"], "artifact_ref": artifact})
                    xml = "\n".join(execution["lines"])
                    match = re.search(r'<service\s+name="([^"]+)"(?:\s+product="([^"]*)")?', xml)
                    if match:
                        technology = " ".join(part for part in match.groups() if part)[:200]
                        _record_technology(ctx, run["id"], asset_id=service["id"], technology=technology, category="network_service", confidence=0.75, source="nmap")
        else: errors.append("naabu unavailable or cannot enforce max_rps below 1")
    elif stage == "score": score_inventory(ctx)
    # js and technology are recomputation boundaries; their deterministic
    # signals are populated by crawl, HTTP, and Burp ingestion.
    return {"mode": "AUTO", "raw_count": raw_count, "new_assets": new_assets, "updated_assets": updated_assets, "new_endpoints": new_endpoints, "filtered": filtered, "tools_used": tools_used, "errors": errors, "candidates": list(dict.fromkeys(candidates))[:max_results]}


def run_authorized_recon(ctx, *, stage: str | None = None, profile: str | None = None, seeds: list[str] | None = None, session_id: int, max_results: int = 200, timeout_seconds: int = 120, broker=None, approval_id: int | None = None) -> ReconResult:
    """Run one stage or profile, recording partial failures durably."""
    seeds = list(seeds or [])
    max_results = int(max_results); timeout_seconds = int(timeout_seconds)
    if not 1 <= max_results <= 500:
        return ReconResult(False, "DENY", stage or "", profile=profile or "", reason="max_results must be 1..500")
    if not 1 <= timeout_seconds <= 900:
        return ReconResult(False, "DENY", stage or "", profile=profile or "", reason="timeout_seconds must be 1..900")
    if ctx.record.status != "active": return ReconResult(False, "DENY", stage or "", profile=profile or "", reason="program is not active")
    ctx.db.require_session(session_id, program_slug=ctx.slug, running=True)
    if bool(stage) == bool(profile): return ReconResult(False, "DENY", stage or "", profile=profile or "", reason="select exactly one of stage or profile")
    if profile and profile not in PROFILE_STAGES: return ReconResult(False, "DENY", "", profile=profile, reason="unsupported recon profile")
    if stage == "validate": stage = "http"
    stages = PROFILE_STAGES[profile] if profile else (stage,)
    if any(item not in STAGE_ACTION for item in stages): return ReconResult(False, "DENY", stage or "", profile=profile or "", reason="unsupported recon stage")
    if seeds and any(item in {"passive", "historical"} for item in stages):
        derived = set(derive_passive_discovery_seeds(ctx.engagement.scope))
        for seed in seeds:
            try: host = normalize_host(urlsplit(seed).hostname or seed)
            except ValueError: return ReconResult(False, "DENY", stage or "", profile=profile or "", reason=f"invalid passive seed: {seed}")
            if host not in derived and not ctx.scope.check(f"https://{host}").allowed:
                return ReconResult(False, "DENY", stage or "", profile=profile or "", reason=f"passive seed is unrelated to configured scope: {seed}")
    approved_deep = False
    concurrency_limit: int | None = None
    if approval_id is not None:
        approval = ctx.db.get_approval(approval_id)
        expected = profile or stage
        approved_deep = (
            approval.status == "approved" and approval.action == "bounded_scan"
            and approval.program == ctx.slug and approval.session_id == session_id
            and (approval.constraints.get("recon_profile") == expected or approval.constraints.get("recon_stage") == expected)
        )
        if not approved_deep:
            return ReconResult(False, "DENY", stage or "", profile=profile or "", reason="approval does not match this bounded recon plan/session")
        approved_targets = list(approval.constraints.get("targets", [])) or ([approval.target] if approval.target else [])
        if not seeds and approved_targets:
            seeds = approved_targets
        if not seeds and not approval.constraints.get("scope_wide", False):
            return ReconResult(False, "DENY", stage or "", profile=profile or "", reason="approved deep plan has no explicit targets")
        if approved_targets:
            approved_hosts = {urlsplit(target if "://" in target else f"https://{target}").hostname for target in approved_targets}
            requested_hosts = {urlsplit(target if "://" in target else f"https://{target}").hostname for target in seeds}
            if not requested_hosts <= approved_hosts:
                return ReconResult(False, "DENY", stage or "", profile=profile or "", reason="requested deep target exceeds approved target set")
        max_results = min(max_results, int(approval.constraints.get("max_requests", max_results)))
        timeout_seconds = min(timeout_seconds, int(approval.constraints.get("duration_seconds", timeout_seconds)))
        concurrency_limit = int(approval.constraints.get("max_concurrency", ctx.engagement.roe.max_concurrency))
    for item in stages:
        policy = ctx.policy.check(STAGE_ACTION[item])
        mode = policy.as_dict()["mode"]
        if mode == "ASK" and STAGE_ACTION[item] == "bounded_scan" and approved_deep:
            continue
        if mode != "AUTO": return ReconResult(False, mode, item, profile=profile or "", reason=policy.reason)
    if approved_deep:
        ctx.db.consume_approval(approval_id)  # one bounded plan, one auditable consumption
    requested = [name for name, spec in TOOL_REGISTRY.items() if profile and profile in spec.profiles]
    run = ctx.db.start_recon_run(profile=profile or "", stage=stage or "", tools_requested=requested, metadata={"session_id": session_id, "stages": list(stages)})
    autonomy_run = ctx.db.active_autonomy_run(session_id)
    if autonomy_run is not None:
        ctx.db.record_autonomy_activity(
            autonomy_run.id, session_id, "RECON_ESCALATED", "recon_run", run["id"],
            {"profile": profile or "", "stage": stage or "", "stages": list(stages)},
        )
    detected = detect_recon_tools(); all_tools: list[dict] = []; all_errors: list[str] = []; candidates: list[str] = []
    inactive_before = {asset["id"] for asset in ctx.db.list_assets(limit=1000) if not asset["active"]}
    totals = {"raw_observation_count": 0, "new_asset_count": 0, "updated_asset_count": 0, "new_endpoint_count": 0}; filtered_total = 0; mode = "AUTO"
    try:
        for item in stages:
            stage_seeds = list(seeds)
            if item in {"passive", "historical"} and not stage_seeds: stage_seeds = derive_passive_discovery_seeds(ctx.engagement.scope)
            result = _execute_stage(ctx, run, item, stage_seeds, session_id=session_id, max_results=max_results, timeout_seconds=timeout_seconds, broker=broker, detected=detected, concurrency_limit=concurrency_limit)
            if result.get("mode") != "AUTO": mode = result["mode"]; all_errors.extend(result.get("errors", [])); break
            totals["raw_observation_count"] += result["raw_count"]; totals["new_asset_count"] += result["new_assets"]; totals["updated_asset_count"] += result["updated_assets"]; totals["new_endpoint_count"] += result["new_endpoints"]
            filtered_total += result["filtered"]
            all_tools.extend(result["tools_used"]); all_errors.extend(result["errors"]); candidates.extend(result["candidates"])
        score_inventory(ctx)
        threshold = getattr(getattr(ctx.engagement, "recon", None), "lead_threshold", 40)
        leads = generate_contextual_leads(ctx, run["id"], threshold=threshold)
        diff_stats = _reconcile_run_changes(ctx, run, profile or "", inactive_before, complete=not all_errors and mode == "AUTO")
        run_changes = ctx.db.list_recon_changes(recon_run_id=run["id"], limit=2000)
        new_asset_ids = {change["entity_id"] for change in run_changes if change["change_type"] == "NEW_ASSET" and change["entity_type"] == "asset"}
        observed_asset_ids = {observation["asset_id"] for observation in ctx.db.list_asset_observations(recon_run_id=run["id"], limit=2000)}
        totals["new_asset_count"] = len(new_asset_ids)
        totals["updated_asset_count"] = len(observed_asset_ids - new_asset_ids)
        totals["new_endpoint_count"] = sum(change["change_type"] == "NEW_ENDPOINT" for change in run_changes)
        manifest = _artifact_dir(ctx, run["public_id"]) / "manifest.json"
        manifest.write_text(json.dumps({"program": ctx.slug, "run": run["public_id"], "profile": profile, "stage": stage, "stages": stages, "tools": all_tools, "errors": all_errors, "counts": totals}, indent=2) + "\n", encoding="utf-8")
        status = "failed" if mode != "AUTO" else "partial" if all_errors else "completed"
        ctx.db.finish_recon_run(run["id"], status=status, tools_used=all_tools, lead_count=len(leads), error_count=len(all_errors), artifact_refs=[str(manifest)], metadata={"stages": list(stages), "filtered_count": filtered_total, **diff_stats}, **totals)
        return ReconResult(mode == "AUTO", mode, stage or "profile", profile=profile or "", run_id=run["public_id"], candidates=list(dict.fromkeys(candidates))[:max_results], in_scope=list(dict.fromkeys(candidates))[:max_results], filtered_count=filtered_total, leads=leads, artifact=str(manifest), tools=all_tools, reason="completed" if status == "completed" else status, counts={**totals, "lead_count": len(leads), "error_count": len(all_errors)}, errors=all_errors)
    except Exception as exc:
        ctx.db.finish_recon_run(run["id"], status="failed", tools_used=all_tools, error_count=len(all_errors) + 1, metadata={"error": f"{type(exc).__name__}: {exc}"})
        raise


def diff_recon_runs(ctx, first_id: int, second_id: int) -> dict:
    first, second = ctx.db.get_recon_run(first_id), ctx.db.get_recon_run(second_id)
    changes = ctx.db.list_recon_changes(recon_run_id=second_id, limit=2000)
    return {"from": first, "to": second, "changes": changes, "counts": {kind: sum(c["change_type"] == kind for c in changes) for kind in sorted({c["change_type"] for c in changes})}}


def recon_readiness() -> dict:
    tools = detect_recon_tools(); passive = any(tools[name]["available"] for name in PASSIVE_TOOLS)
    standard = passive and tools["dnsx"]["available"] and tools["httpx"]["available"] and tools["katana"]["available"]
    deep = standard and any(tools[name]["available"] for name in ("nuclei", "ffuf", "naabu", "nmap"))
    return {"RECON_CORE_READY": passive, "RECON_STANDARD_READY": standard, "RECON_DEEP_READY": deep, "tools": tools}


__all__ = [
    "PASSIVE_TOOLS", "HISTORICAL_TOOLS", "OPTIONAL_ACTIVE_TOOLS", "PROFILE_STAGES", "TOOL_REGISTRY",
    "ReconResult", "detect_recon_tools", "derive_passive_discovery_seeds", "normalize_host", "normalize_url",
    "normalize_endpoint_path", "extract_parameters", "classify_parameter", "extract_js_signals", "parse_dnsx_line",
    "fingerprint_text", "extract_html_forms", "ingest_openapi_document",
    "parse_httpx_line", "parse_katana_line", "score_endpoint", "score_inventory", "generate_contextual_leads",
    "ingest_burp_recon", "ingest_burp_websocket_recon", "get_recon_summary", "recon_is_fresh",
    "run_authorized_recon", "diff_recon_runs", "recon_readiness",
]
