"""Uyuni patch/repository control-plane client and synchronization."""

from __future__ import annotations

import contextlib
import logging
import xmlrpc.client
from datetime import UTC, datetime
from typing import Any
from xml.parsers.expat import ExpatError

import httpx
from sqlalchemy.orm import Session

from .. import models
from ..config import Settings, get_settings
from ..errors import IntegrationNotConfigured, IntegrationUnavailable
from .runtime_configuration_service import effective_settings

logger = logging.getLogger(__name__)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def normalize_system(item: dict) -> dict:
    channels = item.get("channelLabels") or item.get("channels") or []
    if isinstance(channels, str):
        channels = [channels]
    raw_id = item.get("id")
    return {
        "uyuni_system_id": int(raw_id) if raw_id is not None else 0,
        "host_name": item.get("name") or "",
        "status": item.get("status") or "unknown",
        "channels": channels,
        "last_sync": _parse_time(
            item.get("lastCheckin") or item.get("last_checkin")
        ),
    }


def normalize_errata(item: dict) -> dict:
    advisory = (
        item.get("advisoryName")
        or item.get("advisory")
        or item.get("id")
        or ""
    )
    return {
        "errata": str(advisory),
        "package": item.get("packageName") or item.get("package") or "system",
        "current_version": item.get("currentVersion"),
        "fixed_version": item.get("fixedVersion") or item.get("version"),
        "severity": (item.get("severity") or "unknown").lower(),
        "reboot_required": bool(
            item.get("rebootRequired") or item.get("reboot_required")
        ),
    }


class UyuniClient:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._http: httpx.Client | None = None

    @property
    def configured(self) -> bool:
        return self.settings.uyuni_configured

    def _base(self, path: str) -> str:
        return f"{self.settings.uyuni_api_url.rstrip('/')}/{path.lstrip('/')}"

    def _require(self) -> None:
        if not self.configured:
            raise IntegrationNotConfigured(
                "Uyuni is not configured; set LINSEC_UYUNI_API_URL, "
                "LINSEC_UYUNI_USERNAME and LINSEC_UYUNI_PASSWORD"
            )

    def _client(self) -> httpx.Client:
        self._require()
        if self._http is not None:
            return self._http
        client = httpx.Client(
            verify=self.settings.uyuni_verify_tls,
            timeout=self.settings.uyuni_timeout_seconds,
        )
        self._http = client
        return client

    def _call(self, method: str, *params: Any) -> Any:
        client = self._client()
        try:
            if method == "auth.login":
                call_params = (
                    self.settings.uyuni_username,
                    self.settings.uyuni_password,
                )
            else:
                call_params = (self._session_key, *params)
            body = xmlrpc.client.dumps(
                call_params,
                methodname=method,
                allow_none=True,
            )
            response = client.post(
                self.settings.uyuni_api_url.rstrip("/"),
                content=body,
                headers={"Content-Type": "text/xml"},
            )
            response.raise_for_status()
            result, _ = xmlrpc.client.loads(response.content)
            if result and len(result) == 1:
                return result[0]
        except xmlrpc.client.Fault as exc:
            raise IntegrationUnavailable(
                f"Uyuni XML-RPC error {exc.faultCode}: {exc.faultString}"
            ) from exc
        except (httpx.HTTPError, xmlrpc.client.ResponseError, ExpatError) as exc:
            raise IntegrationUnavailable(f"Uyuni API request failed: {exc}") from exc
        else:
            return result

    @property
    def _session_key(self) -> str:
        if hasattr(self, "_session"):
            return self._session
        session = self._call("auth.login")
        if not isinstance(session, str) and not isinstance(session, int):
            raise IntegrationUnavailable("Uyuni login returned an invalid session")
        self._session = str(session)
        return self._session

    def list_systems(self) -> list[dict]:
        result = self._call("system.listSystems")
        if not isinstance(result, list):
            return []
        return [normalize_system(item) for item in result if item.get("id")]

    def system_channels(self, system_id: int) -> list[str]:
        result = self._call("system.getChannels", system_id)
        if isinstance(result, list):
            return [
                item.get("label") or item.get("name")
                for item in result
                if item.get("label") or item.get("name")
            ]
        return []

    def relevant_errata(self, system_id: int) -> list[dict]:
        result = self._call("system.getRelevantErrata", system_id)
        if not isinstance(result, list):
            return []
        return [normalize_errata(item) for item in result]

    def test_connection(self) -> int:
        """Log in to Uyuni XML-RPC and confirm its systems endpoint is usable."""
        return len(self.list_systems())

    def close(self) -> None:
        if self._http is not None and hasattr(self, "_session"):
            with contextlib.suppress(IntegrationUnavailable):
                self._call("auth.logout")
        if self._http is not None:
            self._http.close()
            self._http = None


_client: UyuniClient | None = None


def get_client(settings: Settings | None = None) -> UyuniClient:
    global _client
    if settings is not None and settings is not get_settings():
        return UyuniClient(settings)
    if _client is None:
        _client = UyuniClient(settings)
    return _client


def set_client(client: UyuniClient | None) -> None:
    global _client
    _client = client


def sync_systems(db: Session, client: UyuniClient | None = None) -> dict:
    client = client or get_client(effective_settings(db))
    systems = client.list_systems()
    hosts = {host.name: host for host in db.query(models.Host).all()}
    created = updated = 0
    for system in systems:
        host = hosts.get(system["host_name"])
        record = (
            db.query(models.UyuniSystem)
            .filter(
                models.UyuniSystem.uyuni_system_id == system["uyuni_system_id"]
            )
            .one_or_none()
        )
        if record is None:
            record = models.UyuniSystem(**system)
            record.host_id = host.id if host else None
            db.add(record)
            created += 1
        else:
            record.host_id = host.id if host else record.host_id
            record.host_name = system["host_name"] or record.host_name
            record.status = system["status"]
            record.channels = system["channels"]
            record.last_sync = system.get("last_sync")
            updated += 1
    db.commit()
    return {
        "systems": len(systems),
        "matched_hosts": sum(1 for item in systems if item["host_name"] in hosts),
        "created": created,
        "updated": updated,
    }


def sync_patch_findings(db: Session, client: UyuniClient | None = None) -> dict:
    client = client or get_client(effective_settings(db))
    systems = db.query(models.UyuniSystem).all()
    created = updated = 0
    for system in systems:
        errata = client.relevant_errata(system.uyuni_system_id)
        seen: set[tuple[str, str]] = set()
        for item in errata:
            seen.add((item["package"], item["errata"]))
            record = (
                db.query(models.PatchFinding)
                .filter(
                    models.PatchFinding.host_name == system.host_name,
                    models.PatchFinding.package == item["package"],
                    models.PatchFinding.cve == "",
                    models.PatchFinding.errata == item["errata"],
                    models.PatchFinding.source == "uyuni",
                )
                .one_or_none()
            )
            if record is None:
                db.add(
                    models.PatchFinding(
                        host_id=system.host_id,
                        host_name=system.host_name,
                        package=item["package"],
                        current_version=item.get("current_version"),
                        fixed_version=item.get("fixed_version"),
                        cve="",
                        errata=item["errata"],
                        severity=item["severity"],
                        source="uyuni",
                        status="open",
                        reboot_required=item.get("reboot_required", False),
                    )
                )
                created += 1
            else:
                record.severity = item["severity"]
                record.fixed_version = item.get("fixed_version")
                record.reboot_required = item.get("reboot_required", False)
                record.status = "open"
                updated += 1
        stale = (
            db.query(models.PatchFinding)
            .filter(
                models.PatchFinding.host_name == system.host_name,
                models.PatchFinding.source == "uyuni",
                models.PatchFinding.status == "open",
            )
            .all()
        )
        for finding in stale:
            if (finding.package, finding.errata) not in seen:
                finding.status = "resolved"
    db.commit()
    return {"systems": len(systems), "created": created, "updated": updated}
