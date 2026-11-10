"""Background installation of the Ansible key after password verification."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from .. import models
from ..db import session_scope
from ..services import audit_service, ssh_service

logger = logging.getLogger(__name__)


def install_key_in_background(
    host_id: int,
    actor_id: int,
    password: str,
) -> None:
    with session_scope() as db:
        host = db.get(models.Host, host_id)
        if host is None:
            logger.warning(
                "SSH enrollment skipped; host id=%s no longer exists", host_id
            )
            return
        host_name = host.name
        ip = host.ip
        port = host.ansible_port
        user = host.ansible_user
        expected_fingerprint = host.ssh_fingerprint

    ssh_status = "failed"
    ssh_error = "SSH key installation did not complete."
    try:
        scanned = ssh_service.scan_host_key(
            ip,
            port,
            expected_fingerprint=expected_fingerprint,
        )
        if scanned is None:
            ssh_error = (
                "Unable to verify the SSH fingerprint; key installation aborted."
            )
        elif scanned[1] != expected_fingerprint:
            ssh_error = "SSH fingerprint changed; key installation aborted."
        elif not ssh_service.install_public_key_with_password(
            ip=ip,
            port=port,
            user=user,
            password=password,
            known_hosts_entry=scanned[0],
        ):
            ssh_error = "SSH key installation failed. Check account permissions and SSH configuration."
        else:
            reachable, _, _ = ssh_service.test_connection(
                host_name=host_name,
                ip=ip,
                ansible_user=user,
                ansible_port=port,
                known_hosts_entry=scanned[0],
            )
            if reachable:
                ssh_status = "reachable"
                ssh_error = ""
            else:
                ssh_error = (
                    "The key was installed, but Ansible could not authenticate with it."
                )
    except Exception:
        logger.exception("SSH key enrollment failed for host id=%s", host_id)
        ssh_error = "SSH key enrollment failed; check the API service logs."

    with session_scope() as db:
        host = db.get(models.Host, host_id)
        if host is None:
            logger.error(
                "SSH enrollment result lost; host id=%s no longer exists", host_id
            )
            return
        host.ssh_status = ssh_status
        host.ssh_error = ssh_error[:512] or None
        host.last_ssh_test_at = datetime.now(UTC)
        actor = db.get(models.User, actor_id)
        audit_service.record(
            db,
            actor=actor,
            action="host.ssh_enrollment_complete",
            target_type="host",
            target_id=host.id,
            data={"ssh_status": ssh_status},
        )
