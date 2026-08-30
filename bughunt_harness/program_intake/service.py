"""End-to-end intake, review, approval, refresh, and activation safety service."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Callable
from urllib.parse import urlparse

from ..config import HarnessConfig, get_config
from ..engagement.models import Engagement
from ..engagement.workspace import create_workspace, load_engagement, slug_ok, workspace_path_for
from ..errors import EngagementValidationError, ProgramIntakeError, ProgramNotFoundError
from ..registry import ProgramRegistry
from ..state.db import open_hunt_db
from ..timeutil import utcnow
from .adapters import adapter_for, detect_platform
from .adapters.base import PlatformAdapter
from .ambiguity import detect_ambiguities
from .config_mapper import build_engagement, config_hashes, promote_bundle, write_draft_bundle
from .credentials import PlatformCredentialStore
from .diff import save_diff, semantic_diff, write_protective_overlay
from .fetcher import IntakeFetcher
from .models import AmbiguityStatus, IntakeStatus, ProgramIntakeDraft
from .normalizer import normalize_payload
from .policy_parser import PARSER_VERSION
from .provenance import SnapshotWriter
from .reviewer import review_summary
from .store import IntakeStore


class ProgramIntakeService:
    def __init__(self, config: HarnessConfig | None = None) -> None:
        self.config = config or get_config()
        self.credentials = PlatformCredentialStore(self.config)

    def import_program(
        self, *, platform: str | None = None, handle: str | None = None,
        url: str | None = None, credential_name: str | None = None,
        from_file: Path | None = None, slug: str | None = None,
        confirm_generic_url: bool = False, refresh: bool = False,
        adapter: PlatformAdapter | None = None, fetcher: IntakeFetcher | None = None,
        llm_extract: Callable[[str], dict[str, Any]] | None = None,
    ) -> dict:
        selected = (platform or (detect_platform(url) if url else None) or ("generic" if from_file else None))
        if not selected:
            raise ProgramIntakeError("program import requires --platform, a recognized --url, or --from-file")
        selected = selected.lower()
        if selected in {"generic", "custom"} and url and not confirm_generic_url:
            raise ProgramIntakeError("generic URL retrieval requires explicit --confirm-generic-url")
        chosen = adapter or adapter_for(selected)
        resolved_handle = chosen.resolve_handle(handle=handle, url=url)
        program_slug = slug or _slugify(resolved_handle)
        if not slug_ok(program_slug):
            raise ProgramIntakeError(f"derived program slug {program_slug!r} is invalid; pass --slug")
        workspace, created = self._ensure_program(program_slug, selected, resolved_handle, url, refresh)
        db = open_hunt_db(workspace, program_slug)
        store = IntakeStore(db)
        import_id = store.next_import_id()
        previous = store.latest_import(approved_only=True)
        source_locator = url or (str(from_file.resolve()) if from_file else resolved_handle)
        store.create_import(
            public_id=import_id, program_slug=program_slug, platform=selected,
            platform_handle=resolved_handle, source_locator=source_locator,
            adapter_version=chosen.version, parser_version=PARSER_VERSION,
            status=IntakeStatus.FETCHING.value,
            supersedes_import_id=previous["public_id"] if refresh and previous else None,
            metadata={"credential_name": credential_name, "created_program": created},
        )
        snapshot = SnapshotWriter(workspace, import_id)
        try:
            credential = self.credentials.resolve(selected, credential_name)
            actual_fetcher = fetcher or self._fetcher_for(chosen, selected, url)
            if refresh and previous and hasattr(actual_fetcher, "prime_cache"):
                self._prime_fetcher_cache(actual_fetcher, workspace, store, previous["public_id"])
            payload = chosen.fetch(
                handle=resolved_handle, url=url, fetcher=actual_fetcher,
                snapshot=snapshot, credential=credential, from_file=from_file,
            )
            store.update_import(import_id, status=IntakeStatus.IMPORTED_DRAFT.value)
            draft = normalize_payload(
                payload, import_id=import_id, adapter_version=chosen.version,
                llm_extract=llm_extract,
            )
            if refresh:
                self._apply_existing_local_values(workspace, draft)
            draft.ambiguities = detect_ambiguities(draft)
            root, engagement = write_draft_bundle(workspace, draft)
            snapshot.finalize(adapter_version=chosen.version, parser_version=PARSER_VERSION)
            for source in draft.sources:
                store.add_source(import_id, source.model_dump(mode="json"))
            store.replace_ambiguities(
                import_id, [item.model_dump(mode="json") for item in draft.ambiguities]
            )
            source_hash = _combined_hash(source.content_hash for source in draft.sources)
            critical = sum(item.severity.value == "CRITICAL" for item in draft.ambiguities)
            store.update_import(
                import_id,
                platform_program_id=draft.metadata.platform_program_id,
                status=IntakeStatus.REVIEW_REQUIRED.value,
                completed_at=utcnow(), last_checked_at=utcnow(), source_hash=source_hash,
                draft_hash=draft.draft_hash(), scope_hash=draft.scope_hash(), roe_hash=draft.roe_hash(),
                structured_source_count=sum(source.trust_level >= 90 for source in draft.sources),
                prose_source_count=sum(source.source_type.value == "official_policy_text" for source in draft.sources),
                ambiguity_count=len(draft.ambiguities), critical_ambiguity_count=critical,
            )
            self._update_registry(program_slug, draft)
            store.audit(import_id, "draft_generated", metadata={
                "engagement_schema_valid": engagement is not None,
                "draft_hash": draft.draft_hash(),
                "llm_policy_extraction": "PROPOSAL_ONLY" if llm_extract else "NOT_CONFIGURED",
            })
            summary = review_summary(draft, store.get_import(import_id), store.list_ambiguities(import_id))
            (root / "review.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            if refresh and previous:
                summary["refresh"] = self._finish_refresh(workspace, store, previous, draft)
                summary["status"] = store.get_import(import_id)["status"]
                (root / "review.json").write_text(
                    json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
                )
            return {"program": program_slug, "import_id": import_id, "review": summary}
        except Exception as exc:
            status = IntakeStatus.FETCH_FAILED.value if not snapshot.sources else IntakeStatus.IMPORT_FAILED.value
            store.update_import(import_id, status=status, completed_at=utcnow(),
                                metadata={"error_type": type(exc).__name__, "credential_name": credential_name})
            store.audit(import_id, "import_failed", metadata={"error_type": type(exc).__name__})
            raise
        finally:
            db.close()

    def review(self, slug: str, import_id: str | None = None) -> dict:
        workspace, db, store = self._open(slug)
        try:
            row = store.get_import(import_id) if import_id else store.latest_import()
            if not row:
                raise ProgramIntakeError(f"program {slug!r} has no intake history")
            draft = self._load_draft(workspace, row["public_id"])
            return review_summary(draft, row, store.list_ambiguities(row["public_id"]))
        finally:
            db.close()

    def status(self, slug: str) -> dict:
        workspace, db, store = self._open(slug)
        try:
            latest = store.latest_import()
            if not latest:
                return {"program": slug, "source": "manual", "status": "LEGACY_MANUAL"}
            approved = store.latest_import(approved_only=True)
            approval = store.get_approval(approved["public_id"]) if approved else None
            return {
                "program": slug, "latest": latest,
                "approved_import": approved["public_id"] if approved else None,
                "approval_hash_valid": bool(approved and approval and approved["draft_hash"] == approval["draft_hash"]),
                "protective_overlay": (workspace / "intake" / "protective-overlay.yaml").is_file(),
            }
        finally:
            db.close()

    def ambiguities(self, slug: str, import_id: str | None = None) -> list[dict]:
        _, db, store = self._open(slug)
        try:
            row = store.get_import(import_id) if import_id else store.latest_import()
            if not row:
                return []
            return store.list_ambiguities(row["public_id"])
        finally:
            db.close()

    def resolve_ambiguity(self, slug: str, ambiguity_id: str, *, value: Any,
                          resolved_by: str = "human") -> dict:
        workspace, db, store = self._open(slug)
        try:
            row = store.latest_import()
            if not row or row["status"] not in {IntakeStatus.REVIEW_REQUIRED.value, IntakeStatus.CHANGE_REVIEW_REQUIRED.value}:
                raise ProgramIntakeError("latest import is not awaiting ambiguity review")
            items = store.list_ambiguities(row["public_id"])
            try:
                item = next(candidate for candidate in items if candidate["public_id"] == ambiguity_id)
            except StopIteration as exc:
                raise ProgramIntakeError(f"ambiguity {ambiguity_id!r} not found") from exc
            if item["category"] in {"MISSING_NETWORK_SCOPE", "PROGRAM_NOT_OPEN"}:
                raise ProgramIntakeError("this ambiguity requires a new official source/refresh and cannot be overridden")
            draft = self._load_draft(workspace, row["public_id"])
            self._apply_resolution(draft, item, value, resolved_by)
            store.resolve_ambiguity(row["public_id"], ambiguity_id, value=value, resolved_by=resolved_by)
            for ambiguity in draft.ambiguities:
                if ambiguity.id == ambiguity_id:
                    ambiguity.status = AmbiguityStatus.RESOLVED
                    ambiguity.resolved_value = value
                    ambiguity.resolved_by = resolved_by
                    ambiguity.resolved_at = utcnow()
            write_draft_bundle(workspace, draft)
            open_critical = sum(
                candidate["severity"] == "CRITICAL" and candidate["status"] == "OPEN"
                for candidate in store.list_ambiguities(row["public_id"])
            )
            store.update_import(row["public_id"], draft_hash=draft.draft_hash(),
                                scope_hash=draft.scope_hash(), roe_hash=draft.roe_hash(),
                                critical_ambiguity_count=open_critical)
            return self.review(slug, row["public_id"])
        finally:
            db.close()

    def approve(self, slug: str, *, approved_by: str, actor_kind: str = "human",
                notes: str = "") -> dict:
        workspace, db, store = self._open(slug)
        try:
            row = store.latest_import()
            if not row or row["status"] not in {IntakeStatus.REVIEW_REQUIRED.value, IntakeStatus.CHANGE_REVIEW_REQUIRED.value}:
                raise ProgramIntakeError("latest import is not eligible for approval")
            open_critical = [item for item in store.list_ambiguities(row["public_id"], status="OPEN") if item["severity"] == "CRITICAL"]
            if open_critical:
                raise ProgramIntakeError(f"approval blocked by {len(open_critical)} unresolved critical ambiguity/ambiguities")
            draft = self._load_draft(workspace, row["public_id"])
            state = (draft.metadata.submission_state or "").lower()
            if state in {"closed", "paused", "disabled"}:
                raise ProgramIntakeError(f"official program state {state!r} does not permit testing")
            proposed = build_engagement(draft)
            hashes = config_hashes(proposed)
            if draft.draft_hash() != row["draft_hash"]:
                raise ProgramIntakeError("draft changed after review; stored draft hash does not match")
            store.approve(
                row["public_id"], approved_by=approved_by, actor_kind=actor_kind,
                draft_hash=draft.draft_hash(), scope_hash=hashes["scope_hash"],
                roe_hash=hashes["roe_hash"], program_hash=hashes["program_hash"], notes=notes,
            )
            current = None
            try:
                current = load_engagement(workspace)
            except EngagementValidationError:
                pass
            promoted = promote_bundle(workspace, draft, current=current)
            actual_hashes = config_hashes(promoted)
            if actual_hashes != hashes:
                raise ProgramIntakeError("promoted authorization hashes differ from the approved draft")
            store.update_import(row["public_id"], status=IntakeStatus.APPROVED.value,
                                approved_at=utcnow(), approved_by=approved_by)
            # Reuse the existing engagement validation boundary.
            load_engagement(workspace)
            store.update_import(row["public_id"], status=IntakeStatus.VALIDATED.value)
            store.audit(row["public_id"], "validation_performed", actor=approved_by,
                        metadata={"result": "PASS"})
            overlay = workspace / "intake" / "protective-overlay.yaml"
            overlay.unlink(missing_ok=True)
            return {"program": slug, "import_id": row["public_id"],
                    "status": IntakeStatus.VALIDATED.value, "activation": "still_required"}
        finally:
            db.close()

    def refresh(self, slug: str, *, credential_name: str | None = None,
                adapter: PlatformAdapter | None = None, fetcher: IntakeFetcher | None = None,
                from_file: Path | None = None) -> dict:
        workspace, db, store = self._open(slug)
        try:
            approved = store.latest_import(approved_only=True)
            latest = store.latest_import()
            if not approved:
                raise ProgramIntakeError("refresh requires an approved import")
            platform = approved["platform"]
            handle = approved["platform_handle"]
            locator = approved["source_locator"]
            metadata = approved.get("metadata", {})
            selected_credential = credential_name or metadata.get("credential_name")
            source_url = locator if str(locator).startswith("https://") else None
        finally:
            db.close()
        return self.import_program(
            platform=platform, handle=handle, url=source_url,
            credential_name=selected_credential,
            from_file=from_file, slug=slug, confirm_generic_url=platform in {"generic", "custom"},
            refresh=True, adapter=adapter, fetcher=fetcher,
        )

    def provenance(self, slug: str, *, scope: str | None = None) -> dict:
        workspace, db, store = self._open(slug)
        try:
            approved = store.latest_import(approved_only=True)
            if not approved:
                raise ProgramIntakeError("program has no approved intake provenance")
            draft = self._load_draft(workspace, approved["public_id"])
            entries = draft.scope_entries
            if scope:
                entries = [item for item in entries if scope in {item.selector, item.asset_identifier}]
            return {"program": slug, "approved_through": approved["public_id"],
                    "scope": [item.model_dump(mode="json") for item in entries],
                    "roe": [item.model_dump(mode="json") for item in draft.roe_rules] if not scope else []}
        finally:
            db.close()

    def diff(self, slug: str, import_id: str | None = None) -> dict:
        workspace, db, store = self._open(slug)
        try:
            row = store.get_import(import_id) if import_id else store.latest_import()
            if not row:
                raise ProgramIntakeError("program has no intake history")
            path = workspace / "intake" / row["public_id"] / "diff.json"
            if not path.is_file():
                return {"program": slug, "import_id": row["public_id"], "result": "NO_DIFF"}
            return json.loads(path.read_text(encoding="utf-8"))
        finally:
            db.close()

    def assert_activation_ready(self, slug: str) -> None:
        workspace, db, store = self._open(slug)
        try:
            latest = store.latest_import()
            if not latest:
                return  # backward-compatible manual/legacy program
            if latest["status"] not in {IntakeStatus.VALIDATED.value, IntakeStatus.ACTIVE.value}:
                raise ProgramIntakeError(f"program intake status {latest['status']} requires human review/approval")
            if (workspace / "intake" / "protective-overlay.yaml").is_file():
                raise ProgramIntakeError("restrictive intake overlay requires review before activation")
            approved = store.latest_import(approved_only=True)
            if not approved:
                raise ProgramIntakeError("no human-approved intake revision exists")
            approval = store.get_approval(approved["public_id"])
            if not approval:
                raise ProgramIntakeError("approved import lacks an exact-hash approval record")
            draft = self._load_draft(workspace, approved["public_id"])
            if draft.draft_hash() != approval["draft_hash"] or approved["draft_hash"] != approval["draft_hash"]:
                raise ProgramIntakeError("approved draft hash mismatch (approval invalidated)")
            engagement = load_engagement(workspace)
            hashes = config_hashes(engagement)
            for key in ("program_hash", "scope_hash", "roe_hash"):
                if hashes[key] != approval[key]:
                    raise ProgramIntakeError(f"active config {key} differs from approved intake")
            critical = [item for item in store.list_ambiguities(approved["public_id"], status="OPEN") if item["severity"] == "CRITICAL"]
            if critical:
                raise ProgramIntakeError("approved import has unresolved critical ambiguities")
        finally:
            db.close()

    def mark_active(self, slug: str) -> None:
        _, db, store = self._open(slug)
        try:
            latest = store.latest_import()
            if latest:
                store.update_import(latest["public_id"], status=IntakeStatus.ACTIVE.value)
                store.audit(latest["public_id"], "program_activated", actor="human")
        finally:
            db.close()

    def runtime_blocked(self, slug: str) -> tuple[bool, str]:
        workspace, db, store = self._open(slug)
        try:
            latest = store.latest_import()
            if not latest:
                return False, "legacy_manual"
            if (workspace / "intake" / "protective-overlay.yaml").is_file():
                import yaml
                data = yaml.safe_load((workspace / "intake" / "protective-overlay.yaml").read_text(encoding="utf-8")) or {}
                if data.get("program_blocked"):
                    return True, "official_program_closed_or_paused"
            if latest["status"] in {IntakeStatus.REVIEW_REQUIRED.value, IntakeStatus.IMPORTED_DRAFT.value,
                                    IntakeStatus.FETCHING.value, IntakeStatus.STALE.value,
                                    IntakeStatus.CHANGE_REVIEW_REQUIRED.value}:
                return True, f"intake_{latest['status'].lower()}"
            return False, "effective_approved_authorization"
        finally:
            db.close()

    def ensure_current_for_hunt(self, slug: str) -> dict:
        """Refresh stale imported metadata before a newly launched hunt."""
        workspace, db, store = self._open(slug)
        try:
            latest = store.latest_import()
            if not latest:
                return {"result": "LEGACY_MANUAL"}
            checked = latest.get("last_checked_at") or latest.get("completed_at")
            if checked:
                age_hours = (datetime.now(timezone.utc) - datetime.fromisoformat(checked)).total_seconds() / 3600
                if age_hours <= self.config.intake_max_age_hours:
                    return {"result": "CURRENT", "age_hours": age_hours}
            if not self.config.intake_refresh_before_hunt:
                store.update_import(latest["public_id"], status=IntakeStatus.STALE.value)
                raise ProgramIntakeError("program intake is stale and refresh_before_hunt is disabled")
        finally:
            db.close()
        result = self.refresh(slug)
        refresh_result = result.get("review", {}).get("refresh", {}).get("result")
        if refresh_result == "CHANGE_REVIEW_REQUIRED":
            raise ProgramIntakeError("program changed during pre-hunt refresh; human review is required")
        return result

    def _finish_refresh(self, workspace: Path, store: IntakeStore,
                        previous: dict, draft: ProgramIntakeDraft) -> dict:
        old = self._load_draft(workspace, previous["public_id"])
        diff = semantic_diff(old, draft)
        save_diff(workspace, diff)
        if not diff.material:
            store.update_import(draft.import_id, status=IntakeStatus.VALIDATED.value,
                                last_checked_at=utcnow(), metadata={"no_material_change": True,
                                "equivalent_approved_import": previous["public_id"]})
            store.audit(draft.import_id, "refresh_performed", metadata={"result": "NO_CHANGE"})
            return {"result": "NO_CHANGE", "changes": []}
        overlay = write_protective_overlay(workspace, diff, old, draft)
        store.update_import(draft.import_id, status=IntakeStatus.CHANGE_REVIEW_REQUIRED.value)
        store.audit(draft.import_id, "refresh_performed", metadata={
            "restrictive": len(diff.restrictive), "permissive": len(diff.permissive)})
        if overlay:
            store.audit(draft.import_id, "restrictive_overlay_applied",
                        metadata={"count": len(diff.restrictive)})
        return {"result": "CHANGE_REVIEW_REQUIRED",
                "restrictive": [item.model_dump(mode="json") for item in diff.restrictive],
                "permissive": [item.model_dump(mode="json") for item in diff.permissive],
                "other": [item.model_dump(mode="json") for item in diff.changes
                          if item not in diff.restrictive and item not in diff.permissive]}

    def _apply_resolution(self, draft: ProgramIntakeDraft, item: dict,
                          value: Any, resolved_by: str) -> None:
        category = item["category"]
        refs = set(item.get("source_refs", []))
        if category in {"TESTING_AUTHORIZATION_UNKNOWN", "STRUCTURED_POLICY_CONFLICT"}:
            if isinstance(value, bool):
                for entry in draft.scope_entries:
                    if (not refs and entry.testing_allowed is None) or entry.source_id in refs:
                        entry.testing_allowed = value
            elif isinstance(value, dict):
                for entry in draft.scope_entries:
                    candidate = value.get(entry.source_id, value.get(entry.selector or entry.asset_identifier))
                    if isinstance(candidate, bool):
                        entry.testing_allowed = candidate
            else:
                raise ProgramIntakeError("scope ambiguity resolution must be a boolean or per-asset object")
        elif category == "REQUIRED_HEADER_VALUE_MISSING":
            if not isinstance(value, dict):
                raise ProgramIntakeError("header resolution must be a header-name/value object")
            for header in draft.required_headers:
                if header.name in value and isinstance(value[header.name], str) and value[header.name]:
                    supplied = value[header.name]
                    if supplied.startswith(("env:", "keyring:", "file:")):
                        header.value_ref, header.value = supplied, None
                    else:
                        header.value, header.value_ref = supplied, None
                    header.value_status = "FIXED"
        elif category == "NON_NUMERIC_TRAFFIC_LIMIT":
            if not isinstance(value, dict):
                raise ProgramIntakeError("traffic policy resolution must be an object")
            draft.local_safety_defaults.max_rps = float(value.get("max_rps", draft.local_safety_defaults.max_rps))
            draft.local_safety_defaults.max_concurrency = int(value.get("max_concurrency", draft.local_safety_defaults.max_concurrency))
        draft.human_overrides.append({
            "field": item["field_path"], "value": value, "reason": item["reason"],
            "human": resolved_by, "timestamp": utcnow(), "source_import": draft.import_id,
        })

    def _ensure_program(self, slug: str, platform: str, handle: str,
                        url: str | None, refresh: bool) -> tuple[Path, bool]:
        registry = ProgramRegistry(self.config)
        try:
            try:
                record = registry.get(slug)
                intake_root = Path(record.workspace_path) / "intake"
                if not refresh and intake_root.is_dir() and any(intake_root.glob("IMPORT-*")):
                    raise ProgramIntakeError(f"program {slug!r} already has intake history; use program refresh")
                return Path(record.workspace_path), False
            except ProgramNotFoundError:
                if refresh:
                    raise
                registry_platform = platform if platform in {"hackerone", "bugcrowd", "yeswehack", "intigriti"} else "custom"
                workspace = workspace_path_for(slug, self.config)
                record = registry.create(
                    slug=slug, name=handle, platform=registry_platform,
                    program_url=url, workspace_path=str(workspace), status="paused",
                    notes="Program intake pending human approval.",
                )
                try:
                    create_workspace(record, fixture=False)
                except Exception:
                    registry.delete(slug)
                    raise
                return workspace, True
        finally:
            registry.close()

    def _update_registry(self, slug: str, draft: ProgramIntakeDraft) -> None:
        registry = ProgramRegistry(self.config)
        try:
            platform = draft.metadata.platform if draft.metadata.platform in {"hackerone", "bugcrowd", "yeswehack", "intigriti"} else "custom"
            registry.update_metadata(slug, name=draft.metadata.name, platform=platform,
                                     program_url=draft.metadata.program_url,
                                     notes=f"Intake {draft.import_id} awaiting human approval.")
        finally:
            registry.close()

    @staticmethod
    def _apply_existing_local_values(workspace: Path, draft: ProgramIntakeDraft) -> None:
        """Reuse already configured local header values without copying platform data."""
        try:
            current = load_engagement(workspace)
        except EngagementValidationError:
            return
        existing = current.headers.by_name()
        for header in draft.required_headers:
            local = existing.get(header.name.lower())
            if not local:
                continue
            if local.value_ref:
                header.value_ref, header.value = local.value_ref, None
                header.value_status = "FIXED"
            elif local.value is not None:
                header.value, header.value_ref = local.value, None
                header.value_status = "FIXED"

    def _fetcher_for(self, adapter: PlatformAdapter, platform: str, url: str | None) -> IntakeFetcher:
        if platform in {"generic", "custom"} and url:
            host = urlparse(url).hostname
            if not host:
                raise ProgramIntakeError("generic source URL lacks a hostname")
            return IntakeFetcher({host}, requests_per_minute=10)
        return adapter.create_fetcher()

    @staticmethod
    def _prime_fetcher_cache(fetcher: IntakeFetcher, workspace: Path,
                             store: IntakeStore, import_id: str) -> None:
        root = workspace.resolve()
        for source in store.list_sources(import_id):
            identifier = source.get("source_identifier", "")
            if not str(identifier).startswith("https://"):
                continue
            artifact = (workspace / source["artifact_ref"]).resolve()
            try:
                artifact.relative_to(root)
            except ValueError:
                continue
            if artifact.is_file():
                fetcher.prime_cache(
                    identifier, artifact.read_bytes(), etag=source.get("etag"),
                    last_modified=source.get("last_modified"),
                )

    def _open(self, slug: str):
        registry = ProgramRegistry(self.config)
        try:
            record = registry.get(slug)
        finally:
            registry.close()
        workspace = Path(record.workspace_path)
        db = open_hunt_db(workspace, slug)
        return workspace, db, IntakeStore(db)

    @staticmethod
    def _load_draft(workspace: Path, import_id: str) -> ProgramIntakeDraft:
        path = Path(workspace) / "intake" / import_id / "normalized_draft.json"
        if not path.is_file():
            raise ProgramIntakeError(f"normalized draft artifact missing for {import_id}")
        return ProgramIntakeDraft.model_validate_json(path.read_text(encoding="utf-8"))


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not slug or not slug[0].isalpha():
        slug = "program-" + slug
    if len(slug) < 2:
        slug += "-program"
    return slug[:50].rstrip("-")


def _combined_hash(values) -> str:
    return hashlib.sha256("\n".join(sorted(values)).encode()).hexdigest()


__all__ = ["ProgramIntakeService"]
