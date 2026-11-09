"""Playbook library endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..db import get_db
from ..errors import DomainError
from ..schemas import (
    Message,
    PlaybookCreate,
    PlaybookDetail,
    PlaybookOut,
    PlaybookUpdate,
    PlaybookValidationOut,
    PlaybookValidationRequest,
)
from ..security import get_current_user, require_roles
from ..services import audit_service, playbook_service

router = APIRouter(prefix="/playbooks", tags=["playbooks"])
logger = logging.getLogger(__name__)


def _out(playbook: models.Playbook) -> PlaybookOut:
    return PlaybookOut.model_validate(playbook)


def _detail(playbook: models.Playbook) -> PlaybookDetail:
    return PlaybookDetail(
        id=playbook.id,
        filename=playbook.filename,
        description=playbook.description,
        checksum=playbook.checksum,
        is_allowlisted=playbook.is_allowlisted,
        updated_at=playbook.updated_at,
        content=playbook.content,
    )


def _materialize(playbook: models.Playbook) -> None:
    try:
        playbook_service.materialize(playbook, get_settings().playbooks_dir)
    except OSError as exc:
        logger.warning("could not materialize %s: %s", playbook.filename, exc)


@router.post("/validate", response_model=PlaybookValidationOut)
def validate_playbook(
    payload: PlaybookValidationRequest,
    user: models.User = Depends(require_roles("admin", "operator")),
) -> PlaybookValidationOut:
    valid, detail = playbook_service.validate_playbook_content(payload.content)
    return PlaybookValidationOut(valid=valid, detail=detail)


@router.get("", response_model=list[PlaybookOut])
def list_playbooks(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[PlaybookOut]:
    return [_out(playbook) for playbook in playbook_service.list_playbooks(db)]


@router.post("", response_model=PlaybookDetail, status_code=201)
def create_playbook(
    payload: PlaybookCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> PlaybookDetail:
    try:
        playbook = playbook_service.create_playbook(
            db,
            filename=payload.filename,
            content=payload.content,
            description=payload.description,
        )
        audit_service.record(
            db,
            actor=user,
            action="playbook.create",
            target_type="playbook",
            target_id=playbook.filename,
            data={"checksum": playbook.checksum},
            request=request,
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise DomainError(str(exc)) from exc
    _materialize(playbook)
    return _detail(playbook)


@router.get("/{filename}", response_model=PlaybookDetail)
def get_playbook(
    filename: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> PlaybookDetail:
    return _detail(playbook_service.get_or_raise(db, filename))


@router.put("/{filename}", response_model=PlaybookDetail)
def update_playbook(
    filename: str,
    payload: PlaybookUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> PlaybookDetail:
    playbook = playbook_service.get_or_raise(db, filename)
    try:
        playbook_service.update_playbook(
            db,
            playbook,
            content=payload.content,
            description=payload.description,
        )
    except ValueError as exc:
        db.rollback()
        raise DomainError(str(exc)) from exc
    audit_service.record(
        db,
        actor=user,
        action="playbook.update",
        target_type="playbook",
        target_id=playbook.filename,
        data={"checksum": playbook.checksum},
        request=request,
    )
    db.commit()
    _materialize(playbook)
    return _detail(playbook)


@router.delete("/{filename}", response_model=Message)
def delete_playbook(
    filename: str,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin")),
) -> Message:
    playbook = playbook_service.get_or_raise(db, filename)
    playbook_service.delete_playbook(db, playbook)
    audit_service.record(
        db,
        actor=user,
        action="playbook.delete",
        target_type="playbook",
        target_id=filename,
        request=request,
    )
    db.commit()
    return Message(message=f"playbook {filename} deleted")
