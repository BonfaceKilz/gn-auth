"""User-specific code and data structures."""
import datetime
from typing import Tuple
from uuid import UUID, uuid4
from dataclasses import dataclass

import sqlite3
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.errors import NotFoundError


@dataclass(frozen=True)
class User:
    """Class representing a user."""
    user_id: UUID
    email: str
    name: str
    created: datetime.datetime = datetime.datetime.now()
    verified: bool = False

    def get_user_id(self):
        """Get the user's ID."""
        return self.user_id

    @staticmethod
    def from_sqlite3_row(row: sqlite3.Row):
        """Generate a user from a row in an SQLite3 resultset"""
        return User(user_id=UUID(row["user_id"]),
                    email=row["email"],
                    name=row["name"],
                    created=datetime.datetime.fromtimestamp(row["created"]),
                    verified=bool(int(row["verified"])))


DUMMY_USER = User(user_id=UUID("a391cf60-e8b7-4294-bd22-ddbbda4b3530"),
                  email="gn3@dummy.user",
                  name="Dummy user to use as placeholder")

def user_by_email(conn: db.DbConnection, email: str) -> User:
    """Retrieve user from database by their email address"""
    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        row = cursor.fetchone()

    if row:
        return User.from_sqlite3_row(row)

    raise NotFoundError(f"Could not find user with email {email}")

def user_by_id(conn: db.DbConnection, user_id: UUID) -> User:
    """Retrieve user from database by their user id"""
    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM users WHERE user_id=?", (str(user_id),))
        row = cursor.fetchone()

    if row:
        return User.from_sqlite3_row(row)

    raise NotFoundError(f"Could not find user with ID {user_id}")

def same_password(password: str, hashed: str) -> bool:
    """Check that `raw_password` is hashed to `hash`"""
    try:
        return hasher().verify(hashed, password)
    except VerifyMismatchError as _vme:
        return False

def valid_login(conn: db.DbConnection, user: User, password: str) -> bool:
    """Check the validity of the provided credentials for login."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            ("SELECT * FROM users LEFT JOIN user_credentials "
             "ON users.user_id=user_credentials.user_id "
             "WHERE users.user_id=?"),
            (str(user.user_id),))
        row = cursor.fetchone()

    if row is None:
        return False

    return same_password(password, row["password"])

def save_user(
        cursor: db.DbCursor,
        email: str,
        name: str,
        created: datetime.datetime = datetime.datetime.now(),
        verified: bool = False
) -> User:
    """
    Create and persist a user.

    The user creation could be done during a transaction, therefore the function
    takes a cursor object rather than a connection.

    The newly created and persisted user is then returned.
    """
    user_id = uuid4()
    cursor.execute(
        ("INSERT INTO users(user_id, email, name, created, verified) "
         "VALUES (?, ?, ?, ?, ?)"),
        (
            str(user_id),
            email,
            name,
            int(created.timestamp()),
            (1 if verified else 0)))
    return User(user_id, email, name, created, verified)

def hasher():
    """Retrieve PasswordHasher object"""
    # TODO: Maybe tune the parameters here...
    # Tuneable Parameters:
    # - time_cost (default: 2)
    # - memory_cost (default: 102400)
    # - parallelism (default: 8)
    # - hash_len (default: 16)
    # - salt_len (default: 16)
    # - encoding (default: 'utf-8')
    # - type (default: <Type.ID: 2>)
    return PasswordHasher()

def hash_password(password):
    """Hash the password."""
    return hasher().hash(password)

def set_user_password(
        cursor: db.DbCursor, user: User, password: str) -> Tuple[User, bytes]:
    """Set the given user's password in the database."""
    hashed_password = hash_password(password)
    cursor.execute(
        ("INSERT INTO user_credentials VALUES (:user_id, :hash) "
         "ON CONFLICT (user_id) DO UPDATE SET password=:hash"),
        {"user_id": str(user.user_id), "hash": hashed_password})
    return user, hashed_password

def fetch_users(conn: db.DbConnection,
          ids: tuple[UUID, ...] = tuple()) -> tuple[User, ...]:
    """
    Fetch all users with the given `ids`. If `ids` is empty, return ALL users.
    """
    params = ", ".join(["?"] * len(ids))
    with db.cursor(conn) as cursor:
        query = "SELECT * FROM users" + (
            f" WHERE user_id IN ({params})"
            if len(ids) > 0 else "")
        cursor.execute(query, tuple(str(the_id) for the_id in ids))
        return tuple(User.from_sqlite3_row(row) for row in cursor.fetchall())
    return tuple()
