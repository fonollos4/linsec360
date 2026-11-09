"""Wazuh API / Indexer integration.

The platform never invents telemetry: when Wazuh is not configured the API
raises :class:`IntegrationNotConfigured` and KPI values remain ``unknown``.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy.orm import Session

from .. import models
from ..config import Settings, get_settings
from ..errors import IntegrationNotConfigured, IntegrationUnavailable

logger = logging.getLogger(__name__)


def _tls_verify(settings: Settings, enabled: bool) -> bool | str:
    if not enabled:
        return False
    if settings.wazuh_ca_bundle and settings.wazuh_ca_bundle.is_file():
        return str(settings.wazuh_ca_bundle)
    return True


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(str(value), fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def severity_from_level(level: int | None) -> str:
    if level is None:
        return "low"
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def normalize_agent(item: dict) -> dict:
    os_data = item.get("os") or {}
    return {
        "id": str(item.get("id") or item.get("agent_id") or ""),
        "name": item.get("name") or item.get("agent_name") or "",
        "ip": item.get("ip"),
        "status": item.get("status") or "unknown",
        "os": " ".join(
            part
            for part in (os_data.get("name"), os_data.get("version"))
            if part
        )
        or item.get("os")
        or None,
        "version": item.get("version"),
        "last_keep_alive": _parse_time(
            item.get("lastKeepAlive") or item.get("last_keep_alive")
        ),
    }


def normalize_alert(source: dict, *, alert_id: str | None = None) -> dict:
    rule = source.get("rule") or {}
    agent = source.get("agent") or {}
    mitre = (rule.get("mitre") or {}).get("ids") or []
    level = rule.get("level")
    try:
        level_value = int(level) if level is not None else None
    except (TypeError, ValueError):
        level_value = None
    timestamp = _parse_time(
        source.get("@timestamp") or source.get("timestamp")
    ) or datetime.now(UTC)
    if not alert_id:
        seed = "|".join(
            [
                timestamp.isoformat(),
                str(agent.get("id") or ""),
                str(rule.get("id") or ""),
                str(rule.get("description") or ""),
            ]
        )
        alert_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
    return {
        "alert_id": alert_id,
        "timestamp": timestamp,
        "rule_id": str(rule.get("id")) if rule.get("id") is not None else None,
        "rule_level": level_value,
        "severity": severity_from_level(level_value),
        "agent_id": str(agent.get("id")) if agent.get("id") is not None else None,
        "agent_name": agent.get("name"),
        "description": rule.get("description"),
        "location": source.get("location"),
        "mitre": list(mitre) if isinstance(mitre, list) else [],
        "raw": source,
    }


def normalize_vulnerability_status(value: Any) -> str:
    """Map Wazuh vulnerability states onto the platform's open/resolved model."""
    status = str(value or "").strip().lower()
    if status in {"active", "open", "pending", "unpatched", "vulnerable"}:
        return "open"
    if status in {"resolved", "fixed", "closed", "patched", "mitigated"}:
        return "resolved"
    return status or "open"


def normalize_vulnerability(item: dict) -> dict:
    package = item.get("package") or {}
    package_name = (
        package.get("name") if isinstance(package, dict) else str(package)
    )
    return {
        "package": package_name or "unknown",
        "current_version": (
            package.get("version") if isinstance(package, dict) else None
        )
        or item.get("version"),
        "fixed_version": item.get("fixed_version")
        or (package.get("fixed_version") if isinstance(package, dict) else None),
        "cve": item.get("cve") or "",
        "severity": (item.get("severity") or "unknown").lower(),
        "status": normalize_vulnerability_status(item.get("status")),
    }


class WazuhClient:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._token: str | None = None

    @property
    def configured(self) -> bool:
        return self.settings.wazuh_configured

    def _api(self, path: str) -> str:
        return f"{self.settings.wazuh_api_url.rstrip('/')}/{path.lstrip('/')}"

    def _indexer(self, path: str) -> str:
        return f"{self.settings.wazuh_indexer_url.rstrip('/')}/{path.lstrip('/')}"

    def _require_api(self) -> None:
        if not self.configured:
            raise IntegrationNotConfigured(
                "Wazuh is not configured; set LINSEC_WAZUH_API_URL, "
                "LINSEC_WAZUH_API_USERNAME and LINSEC_WAZUH_API_PASSWORD"
            )

    def _authenticate(self) -> str:
        self._require_api()
        try:
            with httpx.Client(
                verify=_tls_verify(self.settings, self.settings.wazuh_api_verify_tls),
                timeout=self.settings.wazuh_timeout_seconds,
            ) as client:
                response = client.post(
                    self._api("/security/user/authenticate"),
                    params={"raw": "true"},
                    auth=(
                        self.settings.wazuh_api_username,
                        self.settings.wazuh_api_password,
                    ),
                )
                response.raise_for_status()
                token = response.text.strip()
                if not token:
                    raise IntegrationUnavailable("Wazuh returned an empty token")
                self._token = token
                return token
        except httpx.HTTPError as exc:
            raise IntegrationUnavailable(f"Wazuh authentication failed: {exc}") from exc

    def _get(self, path: str, params: dict | None = None) -> dict:
        self._require_api()
        token = self._token or self._authenticate()
        try:
            with httpx.Client(
                verify=_tls_verify(self.settings, self.settings.wazuh_api_verify_tls),
                timeout=self.settings.wazuh_timeout_seconds,
            ) as client:
                response = client.get(
                    self._api(path),
                    params=params,
                    headers={"Authorization": "Bearer " + token},
                )
                if response.status_code == 401:
                    token = self._authenticate()
                    response = client.get(
                        self._api(path),
                        params=params,
                        headers={"Authorization": f"Bearer {token}"},
                    )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as exc:
            raise IntegrationUnavailable(f"Wazuh API request failed: {exc}") from exc

    def list_agents(self) -> list[dict]:
        payload = self._get(
            "/agents",
            {
                "limit": 1000,
                "select": "id,name,ip,status,os.name,os.version,version,lastKeepAlive",
            },
        )
        items = (payload.get("data") or {}).get("affected_items") or []
        return [normalize_agent(item) for item in items if item.get("id")]

    def list_vulnerabilities(self, agent_id: str) -> list[dict]:
        payload = self._get(f"/vulnerability/{agent_id}", {"limit": 1000})
        items = (payload.get("data") or {}).get("affected_items") or []
        return [normalize_vulnerability(item) for item in items]

    def list_sca(self, agent_id: str) -> list[dict]:
        payload = self._get(f"/sca/{agent_id}", {"limit": 1000})
        return (payload.get("data") or {}).get("affected_items") or []

    def search_alerts(self, *, limit: int = 500, since: datetime | None = None) -> list[dict]:
        if not (
            self.settings.wazuh_indexer_url
            and self.settings.wazuh_indexer_username
            and self.settings.wazuh_indexer_password
        ):
            raise IntegrationNotConfigured(
                "Wazuh indexer is not configured; set LINSEC_WAZUH_INDEXER_URL, "
                "LINSEC_WAZUH_INDEXER_USERNAME and LINSEC_WAZUH_INDEXER_PASSWORD"
            )
        query: dict[str, Any] = {"sort": [{"@timestamp": {"order": "desc"}}], "size": limit}
        if since is not None:
            query["query"] = {"range": {"@timestamp": {"gte": since.isoformat()}}}
        try:
            with httpx.Client(
                verify=_tls_verify(
                    self.settings,
                    self.settings.wazuh_indexer_verify_tls,
                ),
                timeout=self.settings.wazuh_timeout_seconds,
            ) as client:
                response = client.post(
                    self._indexer(f"/{self.settings.wazuh_alert_index}/_search"),
                    json=query,
                    auth=(
                        self.settings.wazuh_indexer_username,
                        self.settings.wazuh_indexer_password,
                    ),
                )
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPError as exc:
            raise IntegrationUnavailable(
                f"Wazuh indexer request failed: {exc}"
            ) from exc
        hits = (payload.get("hits") or {}).get("hits") or []
        return [
            normalize_alert(hit.get("_source") or {}, alert_id=hit.get("_id"))
            for hit in hits
        ]

    def active_response(
        self,
        *,
        agent_id: str,
        action: str,
        alert_id: str | None = None,
    ) -> dict:
        self._require_api()
        token = self._token or self._authenticate()
        payload = {
            "command": action,
            "arguments": ["-", alert_id or ""],
            "agent_id": agent_id,
        }
        try:
            with httpx.Client(
                verify=_tls_verify(self.settings, self.settings.wazuh_api_verify_tls),
                timeout=self.settings.wazuh_timeout_seconds,
            ) as client:
                response = client.put(
                    self._api("/active-response"),
                    json=payload,
                    headers={"Authorization": "Bearer " + token},
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as exc:
            raise IntegrationUnavailable(
                f"Wazuh active-response request failed: {exc}"
            ) from exc

    def test_connection(self) -> int:
        """Authenticate to the API and confirm the agents endpoint is usable."""
        return len(self.list_agents())


_client: WazuhClient | None = None


def get_client() -> WazuhClient:
    global _client
    if _client is None:
        _client = WazuhClient()
    return _client


def set_client(client: WazuhClient | None) -> None:
    """Testing/embedding hook."""
    global _client
    _client = client


def sync_agents(db: Session, client: WazuhClient | None = None) -> dict:
    client = client or get_client()
    agents = client.list_agents()
    hosts = db.query(models.Host).all()
    by_name = {host.name: host for host in hosts}
    by_agent_id = {host.agent_id: host for host in hosts if host.agent_id}
    matched = 0
    for agent in agents:
        host = by_agent_id.get(agent["id"]) or by_name.get(agent["name"])
        if host is None:
            continue
        host.agent_id = agent["id"]
        host.os = agent.get("os") or host.os
        host.last_seen = agent.get("last_keep_alive") or host.last_seen
        matched += 1
    db.commit()
    return {
        "agents": len(agents),
        "hosts": len(hosts),
        "matched": matched,
        "unmatched": max(len(agents) - matched, 0),
    }


def sync_alerts(
    db: Session, *, client: WazuhClient | None = None, limit: int = 500
) -> dict:
    client = client or get_client()
    alerts = client.search_alerts(limit=limit)
    created = updated = 0
    for alert in alerts:
        record = (
            db.query(models.Alert)
            .filter(models.Alert.alert_id == alert["alert_id"])
            .one_or_none()
        )
        if record is None:
            db.add(models.Alert(**alert))
            created += 1
        else:
            for key in (
                "timestamp",
                "rule_id",
                "rule_level",
                "severity",
                "agent_id",
                "agent_name",
                "description",
                "location",
                "mitre",
                "raw",
            ):
                setattr(record, key, alert[key])
            updated += 1
    db.commit()
    return {"fetched": len(alerts), "created": created, "updated": updated}


def sync_vulnerabilities(
    db: Session,
    *,
    client: WazuhClient | None = None,
    host_names: list[str] | None = None,
) -> dict:
    client = client or get_client()
    query = db.query(models.Host).filter(models.Host.agent_id.is_not(None))
    if host_names:
        query = query.filter(models.Host.name.in_(host_names))
    hosts = query.all()
    created = updated = 0
    for host in hosts:
        for vulnerability in client.list_vulnerabilities(str(host.agent_id)):
            record = (
                db.query(models.PatchFinding)
                .filter(
                    models.PatchFinding.host_name == host.name,
                    models.PatchFinding.package == vulnerability["package"],
                    models.PatchFinding.cve == vulnerability["cve"],
                    models.PatchFinding.errata == "",
                    models.PatchFinding.source == "wazuh",
                )
                .one_or_none()
            )
            if record is None:
                db.add(
                    models.PatchFinding(
                        host_id=host.id,
                        host_name=host.name,
                        package=vulnerability["package"],
                        current_version=vulnerability.get("current_version"),
                        fixed_version=vulnerability.get("fixed_version"),
                        cve=vulnerability["cve"],
                        severity=vulnerability["severity"],
                        source="wazuh",
                        status=vulnerability.get("status", "open"),
                    )
                )
                created += 1
            else:
                record.severity = vulnerability["severity"]
                record.current_version = vulnerability.get("current_version")
                record.fixed_version = vulnerability.get("fixed_version")
                record.status = vulnerability.get("status", "open")
                updated += 1
    db.commit()
    return {
        "hosts": len(hosts),
        "created": created,
        "updated": updated,
    }
