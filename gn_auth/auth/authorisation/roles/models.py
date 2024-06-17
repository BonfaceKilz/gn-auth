"""Handle management of roles"""
from uuid import UUID, uuid4
from functools import reduce
from dataclasses import dataclass
from typing import Sequence, Iterable, Optional

from pymonad.either import Left, Right, Either

from gn_auth.auth.errors import NotFoundError, AuthorisationError
from gn_auth.auth.authorisation.resources.base import Resource

from ...db import sqlite3 as db
from ...authentication.users import User

from ..checks import authorised_p
from ..privileges import Privilege, db_row_to_privilege


@dataclass(frozen=True)
class Role:
    """Class representing a role: creates immutable objects."""
    role_id: UUID
    role_name: str
    user_editable: bool
    privileges: tuple[Privilege, ...]


def check_user_editable(role: Role):
    """Raise an exception if `role` is not user editable."""
    if not role.user_editable:
        raise AuthorisationError(f"The role `{role.role_name}` is a default "
                                 "role and thus cannot be edited/changed.")


def db_rows_to_roles(rows) -> tuple[Role, ...]:
    """Convert a bunch of db rows into a bunch of `Role` objects."""
    def __resultset_to_roles__(roles, row):
        """Convert SQLite3 resultset into `Role` objects"""
        _role = roles.get(row["role_id"])
        return {
            **roles,
            row["role_id"]: Role(
                role_id=UUID(row["role_id"]),
                role_name=row["role_name"],
                user_editable=bool(row["user_editable"]),
                privileges=(
                    (_role.privileges if bool(_role) else tuple()) +
                    (Privilege(
                        privilege_id=row["privilege_id"],
                        privilege_description=row[
                            "privilege_description"]),)))
        }

    return tuple(reduce(__resultset_to_roles__, rows, {}).values()
                 if bool(rows) else [])

@authorised_p(
    privileges = ("resource:role:create-role",),
    error_description="Could not create role")
def create_role(
        cursor: db.DbCursor,
        role_name: str,
        privileges: Iterable[Privilege],
        user_editable: bool=True
) -> Role:
    """
    Create a new generic role.

    PARAMS:
    * cursor: A database cursor object - This function could be used as part of
              a transaction, hence the use of a cursor rather than a connection
              object.
    * role_name: The name of the role
    * privileges: A 'list' of privileges to assign the new role

    RETURNS: An immutable `gn3.auth.authorisation.roles.Role` object
    """
    role = Role(uuid4(), role_name, user_editable, tuple(privileges))

    cursor.execute(
        "INSERT INTO roles(role_id, role_name, user_editable) VALUES (?, ?, ?)",
        (str(role.role_id), role.role_name, (1 if role.user_editable else 0)))
    cursor.executemany(
        "INSERT INTO role_privileges(role_id, privilege_id) VALUES (?, ?)",
        tuple((str(role.role_id), str(priv.privilege_id))
              for priv in privileges))

    return role

def __organise_privileges__(resources, row) -> dict:
    resource_id = UUID(row["resource_id"])
    role_id = UUID(row["role_id"])
    roles = resources.get(resource_id, {}).get("roles", {})
    role = roles.get(role_id, Role(
        role_id,
        row["role_name"],
        bool(int(row["user_editable"])),
        tuple()))
    return {
        **resources,
        resource_id: {
            "resource_id": resource_id,
            "user_id": UUID(row["user_id"]),
            "roles": {
                **roles,
                role_id: Role(
                    role.role_id,
                    role.role_name,
                    role.user_editable,
                    role.privileges + (db_row_to_privilege(row),)
                )
            }
        }
    }

def user_roles(conn: db.DbConnection, user: User) -> Sequence[dict]:
    """Retrieve all roles (organised by resource) assigned to the user."""
    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM user_roles")
        cursor.execute(
            "SELECT ur.resource_id, ur.user_id, r.*, p.* "
            "FROM user_roles AS ur "
            "INNER JOIN roles AS r ON ur.role_id=r.role_id "
            "INNER JOIN role_privileges AS rp ON r.role_id=rp.role_id "
            "INNER JOIN privileges AS p ON rp.privilege_id=p.privilege_id "
            "WHERE ur.user_id=?",
            (str(user.user_id),))

        return tuple({# type: ignore[var-annotated]
            **row, "roles": tuple(row["roles"].values())
        } for row in reduce(
            __organise_privileges__, cursor.fetchall(), {}).values())
    return tuple()


def user_resource_roles(
        conn: db.DbConnection,
        user: User,
        resource: Resource
) -> tuple[Role, ...]:
    """Retrieve all roles assigned to a user for a particular resource."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            "SELECT ur.resource_id, ur.user_id, r.*, p.* "
            "FROM user_roles AS ur "
            "INNER JOIN roles AS r ON ur.role_id=r.role_id "
            "INNER JOIN role_privileges AS rp ON r.role_id=rp.role_id "
            "INNER JOIN privileges AS p ON rp.privilege_id=p.privilege_id "
            "WHERE ur.user_id=? AND ur.resource_id=?",
            (str(user.user_id), str(resource.resource_id)))

        return db_rows_to_roles(cursor.fetchall())
    return tuple()


def user_role(conn: db.DbConnection, user: User, role_id: UUID) -> Either:
    """Retrieve a specific non-resource role assigned to the user."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            "SELECT res.resource_id, ur.user_id, r.*, p.* "
            "FROM resources AS res INNER JOIN user_roles AS ur "
            "ON res.resource_id=ur.resource_id INNER JOIN roles AS r "
            "ON ur.role_id=r.role_id INNER JOIN role_privileges AS rp "
            "ON r.role_id=rp.role_id INNER JOIN privileges AS p "
            "ON rp.privilege_id=p.privilege_id "
            "WHERE ur.user_id=? AND ur.role_id=?",
            (str(user.user_id), str(role_id)))

        results = cursor.fetchall()
        if results:
            res_role_obj = tuple(# type: ignore[var-annotated]
                reduce(__organise_privileges__, results, {}).values())[0]
            resource_id = res_role_obj["resource_id"]
            role = tuple(res_role_obj["roles"].values())[0]
            return Right((role, resource_id))
        return Left(NotFoundError(
            f"Could not find role with id '{role_id}'",))

def __assign_group_creator_role__(cursor: db.DbCursor, user: User):
    cursor.execute(
        'SELECT role_id FROM roles WHERE role_name IN '
        '("group-creator")')
    role_id = cursor.fetchone()["role_id"]
    cursor.execute(
        "SELECT resource_id FROM resources AS r "
        "INNER JOIN resource_categories AS rc "
        "ON r.resource_category_id=rc.resource_category_id "
        "WHERE rc.resource_category_key='system'")
    resource_id = cursor.fetchone()["resource_id"]
    cursor.execute(
        ("INSERT INTO user_roles VALUES (:user_id, :role_id, :resource_id)"),
        {"user_id": str(user.user_id), "role_id": role_id,
         "resource_id": resource_id})

def __assign_public_view_role__(cursor: db.DbCursor, user: User):
    cursor.execute("SELECT resource_id FROM resources WHERE public=1")
    public_resources = tuple(row["resource_id"] for row in cursor.fetchall())
    cursor.execute("SELECT role_id FROM roles WHERE role_name='public-view'")
    role_id = cursor.fetchone()["role_id"]
    cursor.executemany(
        "INSERT INTO user_roles(user_id, role_id, resource_id) "
        "VALUES(:user_id, :role_id, :resource_id)",
        tuple({
            "user_id": str(user.user_id),
            "role_id": role_id,
            "resource_id": resource_id
        } for resource_id in public_resources))

def assign_default_roles(cursor: db.DbCursor, user: User):
    """Assign `user` some default roles."""
    __assign_group_creator_role__(cursor, user)
    __assign_public_view_role__(cursor, user)

def revoke_user_role_by_name(cursor: db.DbCursor, user: User, role_name: str):
    """Revoke a role from `user` by the role's name"""
    # TODO: Pass in the resource_id - this works somewhat correctly, but it's
    #       only because it is used in for revoking the "group-creator" role so
    #       far
    cursor.execute(
        "SELECT role_id FROM roles WHERE role_name=:role_name",
        {"role_name": role_name})
    role = cursor.fetchone()
    if role:
        cursor.execute(
            ("DELETE FROM user_roles "
             "WHERE user_id=:user_id AND role_id=:role_id"),
            {"user_id": str(user.user_id), "role_id": role["role_id"]})

def assign_user_role_by_name(
        cursor: db.DbCursor, user: User, resource_id: UUID, role_name: str):
    """Revoke a role from `user` by the role's name"""
    cursor.execute(
        "SELECT role_id FROM roles WHERE role_name=:role_name",
        {"role_name": role_name})
    role = cursor.fetchone()

    if role:
        cursor.execute(
            ("INSERT INTO user_roles VALUES(:user_id, :role_id, :resource_id) "
             "ON CONFLICT DO NOTHING"),
            {
                "user_id": str(user.user_id),
                "role_id": role["role_id"],
                "resource_id": str(resource_id)
            })


def role_by_id(conn: db.DbConnection, role_id: UUID) -> Optional[Role]:
    """Fetch a role from the database by its ID."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            "SELECT r.*, p.* FROM roles AS r INNER JOIN role_privileges AS rp "
            "ON r.role_id=rp.role_id INNER JOIN privileges AS p "
            "ON rp.privilege_id=p.privilege_id "
            "WHERE r.role_id=?",
            (str(role_id),))
        results = cursor.fetchall()

    if not bool(results):
        return None

    _roles = db_rows_to_roles(results)
    if len(_roles) > 1:
        raise Exception("Data corruption: Expected a single role.")

    return _roles[0]


def delete_privilege_from_resource_role(
        cursor: db.DbCursor,
        role: Role,
        privilege: Privilege
):
    """Delete a privilege from a resource role."""
    cursor.execute(
        "DELETE FROM role_privileges WHERE role_id=? AND privilege_id=?",
        (str(role.role_id), privilege.privilege_id))
