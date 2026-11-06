"""Small operational CLI for the FastAPI backend."""

from __future__ import annotations

import argparse
import getpass
import sys

from . import models
from .config import get_settings
from .db import create_all, session_scope
from .security import hash_password
from .services import playbook_service


def _create_admin(args: argparse.Namespace) -> int:
    password = args.password
    if not password:
        password = getpass.getpass("Password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            print("Passwords do not match", file=sys.stderr)
            return 2
    if len(password) < 12:
        print("Password must be at least 12 characters", file=sys.stderr)
        return 2

    with session_scope() as db:
        existing = (
            db.query(models.User)
            .filter(models.User.username == args.username)
            .one_or_none()
        )
        if existing is not None:
            print(f"User {args.username!r} already exists", file=sys.stderr)
            return 1
        db.add(
            models.User(
                username=args.username,
                email=args.email,
                password_hash=hash_password(password),
                role=args.role,
                is_active=True,
            )
        )
    print(f"Created {args.role} user {args.username!r}")
    return 0


def _create_tables(args: argparse.Namespace) -> int:
    create_all()
    print("Created database tables")
    return 0


def _seed_playbooks(args: argparse.Namespace) -> int:
    settings = get_settings()
    with session_scope() as db:
        count = playbook_service.seed_from_directory(db, settings.bundled_playbooks_dir)
    print(f"Imported {count} playbook(s)")
    return 0


def _reset_password(args: argparse.Namespace) -> int:
    password = args.password or getpass.getpass("New password: ")
    if len(password) < 12:
        print("Password must be at least 12 characters", file=sys.stderr)
        return 2
    with session_scope() as db:
        user = (
            db.query(models.User)
            .filter(models.User.username == args.username)
            .one_or_none()
        )
        if user is None:
            print(f"User {args.username!r} not found", file=sys.stderr)
            return 1
        user.password_hash = hash_password(password)
        db.query(models.UserSession).filter(
            models.UserSession.user_id == user.id,
            models.UserSession.revoked_at.is_(None),
        ).update({models.UserSession.revoked_at: models.utcnow()})
    print(f"Password reset for {args.username!r}; active sessions revoked")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m backend.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_admin = subparsers.add_parser("create-admin")
    create_admin.add_argument("--username", default="admin")
    create_admin.add_argument("--email")
    create_admin.add_argument("--password")
    create_admin.add_argument(
        "--role",
        default="admin",
        choices=["admin", "operator", "auditor", "viewer"],
    )
    create_admin.set_defaults(func=_create_admin)

    create_tables = subparsers.add_parser("create-tables")
    create_tables.set_defaults(func=_create_tables)

    seed = subparsers.add_parser("seed-playbooks")
    seed.set_defaults(func=_seed_playbooks)

    reset = subparsers.add_parser("reset-password")
    reset.add_argument("--username", required=True)
    reset.add_argument("--password")
    reset.set_defaults(func=_reset_password)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
