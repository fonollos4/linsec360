"""Scoped API tokens for automation clients."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..errors import NotFoundError
from ..schemas import ApiTokenCreate, ApiTokenCreated, ApiTokenOut, Message
from ..security import (
    create_api_token,
    get_current_user,
    require_roles,
    revoke_api_token,
)
from ..services import audit_service

router = APIRouter(prefix="/auth/tokens", tags=["auth"])


@router.get("", response_model=list[ApiTokenOut])
def list_tokens(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[ApiTokenOut]:
    query = db.query(models.ApiToken)
    if user.role != "admin":
        query = query.filter(models.ApiToken.created_by_id == user.id)
    tokens = query.order_by(models.ApiToken.created_at.desc()).all()
    return [ApiTokenOut.model_validate(token) for token in tokens]


@router.post("", response_model=ApiTokenCreated, status_code=201)
def create_token(
    payload: ApiTokenCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> ApiTokenCreated:
    expires_at = (
        datetime.now(UTC) + timedelta(days=payload.expires_in_days)
        if payload.expires_in_days
        else None
    )
    token, plaintext = create_api_token(
        db, user=user, name=payload.name, expires_at=expires_at
    )
    audit_service.record(
        db,
        actor=user,
        action="api_token.create",
        target_type="api_token",
        target_id=str(token.id),
        data={"name": token.name, "expires_at": expires_at},
        request=request,
    )
    db.commit()
    db.refresh(token)
    return ApiTokenCreated(
        **ApiTokenOut.model_validate(token).model_dump(),
        token=plaintext,
    )


@router.delete("/{token_id}", response_model=Message)
def delete_token(
    token_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> Message:
    token = db.get(models.ApiToken, token_id)
    if token is None:
        raise NotFoundError("api token not found")
    if user.role != "admin" and token.created_by_id != user.id:
        raise NotFoundError("api token not found")
    revoke_api_token(db, token)
    audit_service.record(
        db,
        actor=user,
        action="api_token.revoke",
        target_type="api_token",
        target_id=str(token.id),
        data={"name": token.name},
        request=request,
    )
    db.commit()
    return Message(message=f"api token {token.name} revoked")
