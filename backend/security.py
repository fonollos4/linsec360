"""Password hashing, session tokens, CSRF, and RBAC dependencies."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from . import models
from .config import get_settings
from .db import get_db

_hasher = PasswordHasher()
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def encode_session_token(user: models.User, jti: str, expires_at: datetime) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": str(user.id),
            "jti": jti,
            "role": user.role,
            "iat": now,
            "exp": expires_at,
        },
        settings.secret_key,
        algorithm=ALGORITHM,
    )


def decode_session_token(token: str) -> dict | None:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None


def create_session(
    db: Session,
    user: models.User,
    *,
    request: Request | None = None,
) -> tuple[str, str, datetime]:
    """Create a revocable server-side session and return (token, csrf, expires)."""
    settings = get_settings()
    # The jti is a database primary key (VARCHAR(36)); the token itself is
    # signed, so the identifier does not need to carry secret entropy.
    jti = str(uuid4())
    csrf = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(minutes=settings.session_ttl_minutes)

    db.add(
        models.UserSession(
            id=jti,
            user_id=user.id,
            expires_at=expires_at,
            user_agent=(request.headers.get("user-agent") if request else None),
            ip_address=(request.client.host if request and request.client else None),
        )
    )
    user.last_login_at = datetime.now(UTC)
    db.commit()

    token = encode_session_token(user, jti, expires_at)
    return token, csrf, expires_at


def revoke_session(db: Session, jti: str) -> None:
    session = db.get(models.UserSession, jti)
    if session and session.revoked_at is None:
        session.revoked_at = datetime.now(UTC)
        db.commit()


def set_auth_cookies(
    response: Response,
    token: str,
    csrf_token: str,
    *,
    max_age: int | None = None,
) -> None:
    settings = get_settings()
    if max_age is None:
        max_age = settings.session_ttl_minutes * 60
    response.set_cookie(
        settings.cookie_name,
        token,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        max_age=max_age,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(settings.cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")


def _token_from_request(request: Request) -> str | None:
    settings = get_settings()
    token = request.cookies.get(settings.cookie_name)
    if token:
        return token
    header = request.headers.get("Authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value:
        return value
    return None


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> models.User:
    token = _token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
        )

    payload = decode_session_token(token)
    if not payload or not payload.get("sub") or not payload.get("jti"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid session",
        )

    session = db.get(models.UserSession, str(payload["jti"]))
    if session is None or session.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="session revoked",
        )
    expires_at = _aware(session.expires_at)
    if expires_at is None or expires_at <= datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="session expired",
        )

    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid session subject",
        ) from exc

    user = db.get(models.User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user inactive",
        )
    return user


def current_session_id(request: Request) -> str | None:
    token = _token_from_request(request)
    if not token:
        return None
    payload = decode_session_token(token)
    return str(payload["jti"]) if payload and payload.get("jti") else None


def require_roles(*allowed: str) -> Callable:
    def checker(user: models.User = Depends(get_current_user)) -> models.User:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insufficient permissions",
            )
        return user

    return checker


def authenticate(db: Session, username: str, password: str) -> models.User | None:
    user = db.query(models.User).filter(models.User.username == username).one_or_none()
    if user is None or not user.is_active:
        return None
    if not verify_password(user.password_hash, password):
        return None
    return user
