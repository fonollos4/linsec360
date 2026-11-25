"""Playbooks are stored in the database and materialized for Ansible runs."""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import tempfile
from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from .. import models
from ..errors import ConflictError, NotFoundError
from ..schemas import PLAYBOOK_FILENAME

logger = logging.getLogger(__name__)

BUNDLED_DESCRIPTION = "Imported from taskengine/playbooks"


def _validate_yaml(content: str) -> None:
    if not content.strip():
        return
    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    if parsed is not None and not isinstance(parsed, list):
        raise ValueError("an Ansible playbook must be a YAML list of plays")


def validate_playbook_content(content: str) -> tuple[bool, str]:
    """Validate YAML syntax and the basic Ansible playbook list shape."""
    try:
        _validate_yaml(content)
    except ValueError as exc:
        return False, str(exc)
    if not content.strip():
        return True, "YAML valide; le document est vide et ne contient aucun play."
    return True, "YAML valide et structure de playbook (liste) reconnue."


def _checksum(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def list_playbooks(db: Session) -> list[models.Playbook]:
    return db.query(models.Playbook).order_by(models.Playbook.filename).all()


def get_by_filename(db: Session, filename: str) -> models.Playbook | None:
    return (
        db.query(models.Playbook)
        .filter(models.Playbook.filename == filename)
        .one_or_none()
    )


def get_or_raise(db: Session, filename: str) -> models.Playbook:
    playbook = get_by_filename(db, filename)
    if playbook is None:
        raise NotFoundError("playbook not found")
    return playbook


def create_playbook(
    db: Session,
    *,
    filename: str,
    content: str,
    description: str | None = None,
) -> models.Playbook:
    if not PLAYBOOK_FILENAME.fullmatch(filename):
        raise ValueError("playbook filename must end in .yml or .yaml")
    if get_by_filename(db, filename) is not None:
        raise ConflictError("playbook already exists")
    _validate_yaml(content)

    playbook = models.Playbook(
        filename=filename,
        content=content,
        description=description,
        checksum=_checksum(content),
    )
    db.add(playbook)
    db.flush()
    return playbook


def update_playbook(
    db: Session,
    playbook: models.Playbook,
    *,
    content: str,
    description: str | None = None,
) -> models.Playbook:
    _validate_yaml(content)
    playbook.content = content
    playbook.checksum = _checksum(content)
    if description is not None:
        playbook.description = description
    return playbook


def delete_playbook(db: Session, playbook: models.Playbook) -> None:
    db.delete(playbook)


def materialize(playbook: models.Playbook, directory: Path) -> Path:
    """Write the playbook to disk with private permissions."""
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / playbook.filename
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=".playbook-",
        suffix=".yml",
        dir=directory,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(playbook.content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary_path)
        raise
    return path


def seed_from_directory(db: Session, directory: Path) -> int:
    """Synchronize the DB library with the bundled taskengine playbooks.

    ``taskengine/playbooks`` is the single source of truth for bundled
    automation. Imported rows are refreshed in place and removed when their
    source file is deleted; user-created playbooks are never touched.
    """
    if not directory.is_dir():
        return 0

    bundled: dict[str, tuple[str, str]] = {}
    for path in sorted(directory.iterdir()):
        if not path.is_file() or not PLAYBOOK_FILENAME.fullmatch(path.name):
            continue
        try:
            content = path.read_text(encoding="utf-8")
            _validate_yaml(content)
        except (OSError, UnicodeDecodeError, ValueError):
            logger.warning("Skipping unreadable or invalid playbook: %s", path)
            continue
        bundled[path.name] = (content, _checksum(content))

    created = updated = removed = 0
    for filename, (content, checksum) in bundled.items():
        playbook = get_by_filename(db, filename)
        description = f"{BUNDLED_DESCRIPTION}:{checksum}"
        if playbook is None:
            db.add(
                models.Playbook(
                    filename=filename,
                    content=content,
                    checksum=checksum,
                    description=description,
                )
            )
            created += 1
        elif (playbook.description or "").startswith(BUNDLED_DESCRIPTION):
            if playbook.content != content or playbook.checksum != checksum:
                playbook.content = content
                playbook.checksum = checksum
                playbook.description = description
                updated += 1

    for playbook in db.query(models.Playbook).all():
        if (
            playbook.filename not in bundled
            and (playbook.description or "").startswith(BUNDLED_DESCRIPTION)
        ):
            db.delete(playbook)
            removed += 1

    if created or updated or removed:
        db.commit()
    return created + updated + removed
