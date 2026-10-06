"""Small operator CLI for provisioning accounts without public registration."""

import argparse
from getpass import getpass

from sqlalchemy import select

from app.database import Base, SessionLocal, engine
from app.models import User
from app.security import hash_password


def create_user(email: str, display_name: str) -> None:
    Base.metadata.create_all(bind=engine)
    password = getpass("Password (12+ characters): ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    with SessionLocal() as db:
        normalized_email = email.lower()
        if db.scalar(select(User.id).where(User.email == normalized_email)):
            raise SystemExit("That email already has an account.")
        db.add(User(email=normalized_email, display_name=display_name, password_hash=hash_password(password)))
        db.commit()
    print(f"Created account for {normalized_email}.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision a Secure Web Activity Monitor account.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create-user")
    create.add_argument("email")
    create.add_argument("display_name")
    args = parser.parse_args()
    if args.command == "create-user":
        create_user(args.email, args.display_name)


if __name__ == "__main__":
    main()
