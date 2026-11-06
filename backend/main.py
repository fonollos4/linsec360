"""FastAPI application factory for LinSec360."""

from __future__ import annotations

import asyncio
import logging
import secrets
import uuid
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, models
from .api.router import api_router
from .config import get_settings
from .db import create_all, session_scope
from .errors import DomainError
from .security import hash_password
from .services import playbook_service

logger = logging.getLogger(__name__)


def _bootstrap_admin() -> None:
    settings = get_settings()
    with session_scope() as db:
        existing = db.query(models.User).count()
        if existing:
            return
        if not settings.bootstrap_admin_password:
            logger.warning(
                "No users exist. Set LINSEC_BOOTSTRAP_ADMIN_PASSWORD or run "
                "`python -m backend.cli create-admin`."
            )
            return
        db.add(
            models.User(
                username=settings.bootstrap_admin_username,
                password_hash=hash_password(settings.bootstrap_admin_password),
                role="admin",
                is_active=True,
            )
        )
        logger.warning(
            "Bootstrap admin %r created. Change the password immediately.",
            settings.bootstrap_admin_username,
        )


def _prepare_directories() -> None:
    settings = get_settings()
    for directory in (
        settings.log_dir,
        settings.playbooks_dir,
        settings.inventories_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(
        level=logging.DEBUG if settings.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    _prepare_directories()
    if settings.auto_create_tables:
        create_all()
    with session_scope() as db:
        imported = playbook_service.seed_from_directory(
            db, settings.bundled_playbooks_dir
        )
    if imported:
        logger.info("Imported %s bundled playbook(s)", imported)
    _bootstrap_admin()
    logger.info("LinSec360 API %s started", __version__)
    from .services.operations_service import scheduler_loop

    scheduler_task = asyncio.create_task(scheduler_loop())
    try:
        yield
    finally:
        scheduler_task.cancel()
        with suppress(asyncio.CancelledError):
            await scheduler_task


def _error(
    status_code: int,
    code: str,
    message: str,
    details: object | None = None,
) -> JSONResponse:
    body: dict = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=body)


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.docs_enabled else None,
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.middleware("http")
    async def request_guard(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        mutating = request.method in {"POST", "PUT", "PATCH", "DELETE"}
        is_api = request.url.path.startswith(settings.api_prefix)
        is_login = request.url.path == f"{settings.api_prefix}/auth/login"
        session_cookie = request.cookies.get(settings.cookie_name)

        if mutating and is_api and not is_login and session_cookie:
            csrf_cookie = request.cookies.get(settings.csrf_cookie_name)
            csrf_header = request.headers.get("X-CSRF-Token")
            if (
                not csrf_cookie
                or not csrf_header
                or not secrets.compare_digest(csrf_cookie, csrf_header)
            ):
                response = _error(
                    status.HTTP_403_FORBIDDEN,
                    "csrf_failed",
                    "missing or invalid CSRF token",
                )
                response.headers["X-Request-ID"] = request_id
                return response

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @app.exception_handler(DomainError)
    async def domain_error_handler(request: Request, exc: DomainError):
        return _error(exc.status_code, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        cleaned_errors = []
        for error in exc.errors():
            item = {
                key: value for key, value in error.items() if key not in {"ctx", "url"}
            }
            if error.get("ctx"):
                item["ctx"] = {key: str(value) for key, value in error["ctx"].items()}
            cleaned_errors.append(item)
        return _error(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "validation_error",
            "request validation failed",
            jsonable_encoder(cleaned_errors),
        )

    @app.exception_handler(IntegrityError)
    async def integrity_error_handler(request: Request, exc: IntegrityError):
        logger.warning("database integrity error: %s", exc)
        return _error(
            status.HTTP_409_CONFLICT,
            "conflict",
            "the request conflicts with existing data",
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException):
        return _error(
            exc.status_code,
            "http_error",
            str(exc.detail),
        )

    app.include_router(api_router, prefix=settings.api_prefix)

    @app.get("/health", tags=["health"])
    def health() -> dict:
        return {
            "status": "ok",
            "service": settings.app_name,
            "version": __version__,
        }

    @app.get("/ready", tags=["health"])
    def ready():
        from .db import database_is_ready

        if not database_is_ready():
            return _error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "not_ready",
                "database is not ready",
            )
        return {"status": "ready", "checks": {"database": "ok"}}

    @app.get("/metrics", include_in_schema=False)
    def metrics():
        from fastapi.responses import PlainTextResponse
        from sqlalchemy import func

        from .db import session_scope

        with session_scope() as db:
            host_total = db.query(func.count(models.Host.id)).scalar() or 0
            deployment_total = db.query(func.count(models.Deployment.id)).scalar() or 0
            alert_total = db.query(func.count(models.Alert.id)).scalar() or 0
        body = (
            "# HELP linsec_hosts_total Inventory host count.\n"
            "# TYPE linsec_hosts_total gauge\n"
            f"linsec_hosts_total {host_total}\n"
            "# HELP linsec_deployments_total Deployment count.\n"
            "# TYPE linsec_deployments_total gauge\n"
            f"linsec_deployments_total {deployment_total}\n"
            "# HELP linsec_alerts_total Stored alert count.\n"
            "# TYPE linsec_alerts_total gauge\n"
            f"linsec_alerts_total {alert_total}\n"
        )
        return PlainTextResponse(body, media_type="text/plain")

    @app.get("/", include_in_schema=False)
    def root() -> dict:
        return {
            "service": settings.app_name,
            "version": __version__,
            "api": settings.api_prefix,
            "docs": "/api/docs" if settings.docs_enabled else None,
        }

    return app


app = create_app()
