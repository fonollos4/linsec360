"""Small operational CLI for the FastAPI backend."""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import models
from .config import get_settings
from .db import create_all, session_scope
from .errors import IntegrationUnavailable
from .security import hash_password
from .services import credential_service, playbook_service


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


def _reencrypt_credentials(args: argparse.Namespace) -> int:
    """Re-encrypt stored host passwords with the current encryption key."""
    old_key = args.old_key or os.environ.get(
        "LINSEC_OLD_CREDENTIAL_ENCRYPTION_KEY"
    )
    if not old_key:
        old_key = getpass.getpass("Previous credential encryption key: ")

    migrated: list[str] = []
    already_current: list[str] = []
    unreadable: list[str] = []
    with session_scope() as db:
        hosts = (
            db.query(models.Host)
            .filter(models.Host.ansible_password_encrypted.isnot(None))
            .all()
        )
        for host in hosts:
            blob = host.ansible_password_encrypted
            assert blob is not None
            try:
                credential_service.decrypt_password(blob)
            except IntegrationUnavailable:
                pass
            else:
                already_current.append(host.name)
                continue
            try:
                plaintext = credential_service.decrypt_password_with_key(blob, old_key)
            except IntegrationUnavailable:
                unreadable.append(host.name)
                continue
            if args.apply:
                host.ansible_password_encrypted = credential_service.encrypt_password(
                    plaintext
                )
            migrated.append(host.name)

    mode = "APPLY" if args.apply else "DRY RUN"
    print(f"{mode}: {len(migrated)} credential(s) can be re-encrypted")
    if migrated:
        print("  hosts: " + ", ".join(migrated))
    if already_current:
        print(f"  already using the current key: {len(already_current)}")
    if unreadable:
        print(
            "  unreadable with the supplied key (left unchanged): "
            + ", ".join(unreadable)
        )
    if not args.apply and migrated:
        print("Re-run with --apply to persist the migration")
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

    reencrypt = subparsers.add_parser("reencrypt-credentials")
    reencrypt.add_argument(
        "--old-key",
        help="Previous Fernet key; defaults to LINSEC_OLD_CREDENTIAL_ENCRYPTION_KEY",
    )
    reencrypt.add_argument(
        "--apply",
        action="store_true",
        help="Persist the migration (otherwise only report what would change)",
    )
    reencrypt.set_defaults(func=_reencrypt_credentials)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
