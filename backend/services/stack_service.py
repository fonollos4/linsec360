"""Discover configured stack endpoints and their DNS addresses."""

from __future__ import annotations

import ipaddress
import logging
import shutil
import socket
import stat
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from ..db import database_is_ready
from ..schemas import IntegrationState, StackComponentState

logger = logging.getLogger(__name__)


def resolve_addresses(hostname: str | None) -> list[str]:
    if not hostname:
        return []
    try:
        return [ipaddress.ip_address(hostname).compressed]
    except ValueError:
        pass
    try:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({result[4][0] for result in results})


def _url_details(value: str) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None, None
    if not parsed.scheme or not hostname:
        return None, None
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", "")), hostname


def _url_component(
    *,
    key: str,
    name: str,
    value: str,
    configured: bool,
    reachable: bool | None = None,
    detail: str | None = None,
) -> StackComponentState:
    endpoint, hostname = _url_details(value)
    addresses = resolve_addresses(hostname)
    if configured and hostname and not addresses:
        detail = detail or "Le nom d'hôte n'a pas pu être résolu depuis l'API."
    return StackComponentState(
        key=key,
        name=name,
        configured=configured,
        reachable=reachable,
        endpoint=endpoint,
        addresses=addresses,
        detail=detail,
    )


def _database_component(settings) -> StackComponentState:
    raw_url = getattr(settings, "database_url", "")
    try:
        parsed = make_url(raw_url)
    except (ArgumentError, TypeError, ValueError):
        return StackComponentState(
            key="database",
            name="Base de données",
            configured=False,
            reachable=False,
            detail="URL de base de données invalide.",
        )

    if parsed.get_backend_name() == "sqlite":
        endpoint = "SQLite local"
        hostname = None
    else:
        hostname = parsed.host
        endpoint = (
            f"{parsed.drivername}://{hostname}"
            if hostname
            else parsed.drivername
        )
        if parsed.port is not None:
            endpoint = f"{endpoint}:{parsed.port}"
    ready = database_is_ready()
    return StackComponentState(
        key="database",
        name="Base de données",
        configured=True,
        reachable=ready,
        endpoint=endpoint,
        addresses=resolve_addresses(hostname),
        detail=(
            "Connexion vérifiée par SELECT 1."
            if ready
            else "Base de données indisponible."
        ),
    )


def _redis_component(settings) -> StackComponentState:
    redis_url = getattr(settings, "redis_url", "")
    endpoint, hostname = _url_details(redis_url)
    if not redis_url:
        return StackComponentState(
            key="redis",
            name="Redis / file d'attente",
            configured=False,
            detail="Redis non configuré ; le mode local utilise des threads.",
        )

    from redis import Redis
    from redis.exceptions import RedisError

    client = None
    try:
        client = Redis.from_url(
            redis_url,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        reachable = bool(client.ping())
    except (OSError, RedisError, ValueError):
        reachable = False
    finally:
        if client is not None:
            try:
                client.close()
            except (OSError, RedisError):
                logger.debug("Could not close the temporary Redis status connection")
    return StackComponentState(
        key="redis",
        name="Redis / file d'attente",
        configured=True,
        reachable=reachable,
        endpoint=endpoint,
        addresses=resolve_addresses(hostname),
        detail="Connexion Redis vérifiée." if reachable else "Redis indisponible.",
    )


def components(
    settings,
    *,
    wazuh: IntegrationState,
    uyuni: IntegrationState,
    ansible: IntegrationState,
) -> list[StackComponentState]:
    api_url = getattr(settings, "wazuh_api_url", "")
    _, api_hostname = _url_details(api_url)
    configured_manager = str(
        getattr(settings, "wazuh_manager_address", "") or ""
    ).strip()
    manager_hostname = configured_manager or api_hostname
    is_internal_alias = (manager_hostname or "").lower() in {
        "localhost",
        "wazuh.manager",
        "wazuh-manager",
    }
    manager_address = getattr(settings, "effective_wazuh_manager_address", "")
    if not manager_address and manager_hostname and not is_internal_alias:
        manager_address = manager_hostname
    manager_port = getattr(settings, "wazuh_manager_agent_port", 1514)
    enrollment_port = getattr(settings, "wazuh_manager_enrollment_port", 1515)
    if is_internal_alias:
        manager_detail = (
            "Adresse détectée depuis l'API, mais nom interne Docker ; "
            "les hôtes distants ne peuvent généralement pas le résoudre."
        )
    elif configured_manager:
        manager_detail = "Adresse configurée explicitement pour les agents."
    elif manager_address:
        manager_detail = (
            "Adresse détectée automatiquement depuis l'URL de l'API Wazuh."
        )
    else:
        manager_detail = "Adresse du manager non détectée."

    manager_endpoint = (
        f"TCP {manager_hostname}:{manager_port} "
        f"(enrôlement : {enrollment_port})"
        if manager_hostname
        else None
    )
    manager_addresses = resolve_addresses(manager_hostname)
    if manager_hostname and not manager_addresses:
        manager_detail = f"{manager_detail} Le DNS n'a renvoyé aucune adresse."
    uyuni_server = getattr(settings, "effective_uyuni_server", "")
    result = [
        _database_component(settings),
        _redis_component(settings),
        StackComponentState(
            key="wazuh-manager",
            name="Wazuh Manager (agents)",
            configured=bool(manager_address),
            endpoint=manager_endpoint,
            addresses=manager_addresses,
            detail=manager_detail,
        ),
        _url_component(
            key="wazuh-api",
            name="Wazuh API",
            value=api_url,
            configured=wazuh.configured,
            reachable=wazuh.reachable,
            detail=wazuh.detail,
        ),
        _url_component(
            key="wazuh-indexer",
            name="Wazuh Indexer",
            value=getattr(settings, "wazuh_indexer_url", ""),
            configured=bool(getattr(settings, "wazuh_indexer_url", "")),
        ),
        _url_component(
            key="wazuh-dashboard",
            name="Wazuh Dashboard",
            value=getattr(settings, "wazuh_dashboard_url", ""),
            configured=bool(getattr(settings, "wazuh_dashboard_url", "")),
        ),
        _url_component(
            key="uyuni",
            name="Uyuni XML-RPC",
            value=getattr(settings, "uyuni_api_url", ""),
            configured=uyuni.configured,
            reachable=uyuni.reachable,
            detail=uyuni.detail,
        ),
        StackComponentState(
            key="uyuni-server",
            name="Uyuni server (agents)",
            configured=bool(uyuni_server),
            endpoint=uyuni_server or None,
            detail=(
                "Adresse configurée pour l'enregistrement des agents."
                if uyuni_server
                else "Adresse du serveur Uyuni non configurée pour les agents."
            ),
        ),
    ]

    binary = getattr(settings, "ansible_playbook_bin", "")
    binary_path = shutil.which(binary) if binary else None
    result.append(
        StackComponentState(
            key="ansible",
            name="Ansible",
            configured=bool(binary),
            reachable=bool(binary_path),
            endpoint=binary_path or binary or None,
            detail=ansible.detail,
        )
    )

    private_key = Path(
        str(getattr(settings, "ansible_ssh_private_key_path", ""))
    ).expanduser()
    key_available = private_key.is_file()
    if key_available:
        key_available = not (stat.S_IMODE(private_key.stat().st_mode) & 0o077)
    result.append(
        StackComponentState(
            key="ssh-key",
            name="Clé SSH Ansible",
            configured=True,
            reachable=key_available,
            endpoint=str(private_key),
            detail=(
                "Clé présente avec permissions restrictives."
                if key_available
                else "Clé absente ou permissions trop ouvertes."
            ),
        )
    )
    return result
