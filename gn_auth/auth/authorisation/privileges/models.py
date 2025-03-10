"""Handle privileges"""
from dataclasses import dataclass
from typing import Iterable, Optional

import sqlite3

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.authentication.users import User


@dataclass(frozen=True)
class Privilege:
    """Class representing a privilege: creates immutable objects."""
    privilege_id: str
    privilege_description: str


def db_row_to_privilege(row: sqlite3.Row) -> Privilege:
    "Convert single db row into a privilege object."
    return Privilege(privilege_id=row["privilege_id"],
                     privilege_description=row["privilege_description"])


def user_privileges(conn: db.DbConnection, user: User) -> Iterable[Privilege]:
    """Fetch the user's privileges from the database."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            ("SELECT p.privilege_id, p.privilege_description "
             "FROM user_roles AS ur "
             "INNER JOIN role_privileges AS rp ON ur.role_id=rp.role_id "
             "INNER JOIN privileges AS p ON rp.privilege_id=p.privilege_id "
             "WHERE ur.user_id=?"),
            (str(user.user_id),))
        results = cursor.fetchall()

    return (Privilege(row[0], row[1]) for row in results)

def privileges_by_ids(
        conn: db.DbConnection, privileges_ids: tuple[str, ...]) -> tuple[
            Privilege, ...]:
    """Fetch privileges by their ids."""
    if len(privileges_ids) == 0:
        return tuple()

    with db.cursor(conn) as cursor:
        clause = ", ".join(["?"] * len(privileges_ids))
        cursor.execute(
            f"SELECT * FROM privileges WHERE privilege_id IN ({clause})",
            privileges_ids)
        return tuple(
            Privilege(row["privilege_id"], row["privilege_description"])
            for row in cursor.fetchall())

def all_privileges(conn: db.DbConnection) -> tuple[Privilege, ...]:
    """Retrieve all privileges from the database."""
    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM privileges")
        results = cursor.fetchall()

    return tuple([] if not bool(results)
                 else (db_row_to_privilege(row) for row in results))

def privilege_by_id(conn: db.DbConnection, privilege_id: str) -> Optional[Privilege]:
    """Retrieve a privilege by its ID."""
    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM privileges WHERE privilege_id=?",
                       (privilege_id,))
        row = cursor.fetchone()

    return db_row_to_privilege(row) if bool(row) else None
