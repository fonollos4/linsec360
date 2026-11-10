"""Authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..ratelimit import login_rate_limiter
from ..schemas import LoginRequest, Message, PasswordChangeRequest, SessionOut, UserOut
from ..security import (
    authenticate,
    clear_auth_cookies,
    create_session,
    current_session_id,
    get_current_user,
    hash_password,
    revoke_session,
    set_auth_cookies,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _login_key(request: Request, username: str) -> str:
    client = request.client.host if request.client else "unknown"
    return f"{client}:{username.lower()}"


@router.post("/login", response_model=SessionOut)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> SessionOut:
    key = _login_key(request, payload.username)
    login_rate_limiter.check(key)
    user = authenticate(db, payload.username, payload.password)
    if user is None:
        login_rate_limiter.failure(key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid username or password",
        )

    login_rate_limiter.success(key)
    token, csrf, _ = create_session(db, user, request=request)
    set_auth_cookies(response, token, csrf)
    return SessionOut(
        authenticated=True,
        user=UserOut.model_validate(user),
        csrf_token=csrf,
    )


@router.post("/logout", response_model=Message)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> Message:
    jti = current_session_id(request)
    if jti:
        revoke_session(db, jti)
    clear_auth_cookies(response)
    return Message(message="logged out")


@router.get("/me", response_model=UserOut)
def me(user: models.User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)


@router.put("/password", response_model=Message)
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> Message:
    if not verify_password(user.password_hash, payload.current_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="current password is incorrect",
        )
    if payload.current_password == payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="new password must differ from current password",
        )

    user.password_hash = hash_password(payload.new_password)
    active_session_id = current_session_id(request)
    for session in (
        db.query(models.UserSession)
        .filter(
            models.UserSession.user_id == user.id,
            models.UserSession.revoked_at.is_(None),
        )
        .all()
    ):
        if session.id != active_session_id:
            session.revoked_at = models.utcnow()
    db.commit()
    return Message(message="password changed")
