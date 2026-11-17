"""``cppmmon-admin``: operator CLI (user management, key generation).

There are no default passwords: the first admin is created here.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from cppmmon.crypto import generate_key
from cppmmon.db.models import AuditLog, User
from cppmmon.db.session import session_scope

MIN_PASSWORD = 10


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass("Password: ")
        if getpass.getpass("Repeat password: ") != pw:
            raise SystemExit("error: passwords do not match")
    if len(pw) < MIN_PASSWORD:
        raise SystemExit(f"error: password must be at least {MIN_PASSWORD} characters")
    return pw


def cmd_create_user(args: argparse.Namespace) -> int:
    """Create a local user."""
    from cppmmon.web.auth import hash_password

    pw = _read_password(args.password_stdin)
    with session_scope() as s:
        if s.scalar(select(User).where(User.username == args.username)):
            print(f"error: user '{args.username}' already exists", file=sys.stderr)
            return 1
        s.add(User(username=args.username, password_hash=hash_password(pw), role=args.role))
        s.add(AuditLog(user="cli", action="user.create", target=args.username, detail={"role": args.role}))
    print(f"created user '{args.username}' (role={args.role})")
    return 0


def cmd_set_password(args: argparse.Namespace) -> int:
    """Reset a user's password."""
    from cppmmon.web.auth import hash_password

    pw = _read_password(args.password_stdin)
    with session_scope() as s:
        user = s.scalar(select(User).where(User.username == args.username))
        if user is None:
            print(f"error: no such user '{args.username}'", file=sys.stderr)
            return 1
        user.password_hash = hash_password(pw)
        s.add(AuditLog(user="cli", action="user.set_password", target=args.username, detail=None))
    print(f"password updated for '{args.username}'")
    return 0


def cmd_list_users(_args: argparse.Namespace) -> int:
    """List users (never prints hashes)."""
    with session_scope() as s:
        users = list(s.scalars(select(User).order_by(User.username)))
    if not users:
        print("(no users — run: cppmmon-admin create-user <name> --role admin)")
    for u in users:
        print(f"{u.username:<24} {u.role:<9} last_login={u.last_login or 'never'}")
    return 0


def cmd_gen_key(_args: argparse.Namespace) -> int:
    """Print a fresh Fernet key (install.sh writes it to /etc/cppmmon/secret.key)."""
    sys.stdout.write(generate_key().decode("ascii") + "\n")
    return 0


def cmd_catalog_import(args: argparse.Namespace) -> int:
    """Import a trap catalog file (YAML/CSV). ``--seed`` only adds missing OIDs."""
    from pathlib import Path

    from cppmmon.catalog import loader

    path = Path(args.file)
    try:
        pc = loader.parse(path.read_bytes(), path.name)
    except (OSError, loader.CatalogError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for e in pc.errors:
        print(f"skipped: {e}", file=sys.stderr)
    with session_scope() as s:
        d = loader.diff(s, pc)
        print(f"{path.name}: {len(d.added)} new, {len(d.changed)} changed, {len(d.unchanged)} unchanged, "
              f"{len(d.untouched)} in DB but not in file (kept)")
        if not args.apply and not args.seed:
            for c in d.changed:
                print(f"  ~ {c['name']} ({c['oid']}): {', '.join(c['fields'])}")
            print("dry run: re-run with --apply (or --seed) to write")
            return 0
        counts = loader.apply(s, pc, seed=args.seed)
        s.add(AuditLog(user="cli", action="catalog.import", target=path.name, detail={**counts, "seed": args.seed}))
    print(f"applied: {counts}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint."""
    p = argparse.ArgumentParser(prog="cppmmon-admin", description="CPPM Monitor administration")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create-user", help="create a local user")
    c.add_argument("username")
    c.add_argument("--role", choices=("admin", "operator", "viewer"), default="admin")
    c.add_argument("--password-stdin", action="store_true", help="read the password from stdin (one line)")
    c.set_defaults(fn=cmd_create_user)

    sp = sub.add_parser("set-password", help="reset a user's password")
    sp.add_argument("username")
    sp.add_argument("--password-stdin", action="store_true")
    sp.set_defaults(fn=cmd_set_password)

    sub.add_parser("list-users", help="list users").set_defaults(fn=cmd_list_users)
    sub.add_parser("gen-key", help="print a new Fernet key").set_defaults(fn=cmd_gen_key)

    ci = sub.add_parser("catalog-import", help="import a trap catalog (YAML/CSV); dry run by default")
    ci.add_argument("file")
    mode = ci.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="upsert: add new and update changed OIDs")
    mode.add_argument("--seed", action="store_true", help="add missing OIDs only, never overwrite")
    ci.set_defaults(fn=cmd_catalog_import)

    args = p.parse_args(argv)
    try:
        return int(args.fn(args))
    except SQLAlchemyError as exc:
        print(f"error: database: {exc.__class__.__name__}: {exc.orig if hasattr(exc, 'orig') else exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
