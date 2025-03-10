"""Functions for acting on users."""
import uuid
from functools import reduce

from ..roles.models import Role
from ..checks import authorised_p
from ..privileges import Privilege

from ...db import sqlite3 as db
from ...authentication.users import User

@authorised_p(
    ("system:user:list",),
    "You do not have the appropriate privileges to list users.",
    oauth2_scope="profile user")
def list_users(conn: db.DbConnection) -> tuple[User, ...]:
    """List out all users."""
    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM users")
        return tuple(User.from_sqlite3_row(row) for row in cursor.fetchall())

def __build_resource_roles__(rows):
    def __build_roles__(roles, row):
        role_id = uuid.UUID(row["role_id"])
        priv = Privilege(row["privilege_id"], row["privilege_description"])
        role = roles.get(role_id, Role(
            role_id, row["role_name"], bool(row["user_editable"]), tuple()))
        return {
            **roles,
            role_id: Role(role_id, role.role_name, role.user_editable, role.privileges + (priv,))
        }
    def __build__(acc, row):
        resource_id = uuid.UUID(row["resource_id"])
        return {
            **acc,
            resource_id: __build_roles__(acc.get(resource_id, {}), row)
        }
    return {
        resource_id: tuple(roles.values())
        for resource_id, roles in reduce(__build__, rows, {}).items()
    }

# @authorised_p(
#     ("",),
#     ("You do not have the appropriate privileges to view a user's roles on "
#      "resources."))
def user_resource_roles(conn: db.DbConnection, user: User) -> dict[uuid.UUID, tuple[Role, ...]]:
    """Fetch all the user's roles on resources."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            "SELECT res.*, rls.*, p.*"
            "FROM resources AS res INNER JOIN "
            "user_roles AS ur "
            "ON res.resource_id=ur.resource_id "
            "LEFT JOIN roles AS rls "
            "ON ur.role_id=rls.role_id "
            "LEFT JOIN role_privileges AS rp "
            "ON rls.role_id=rp.role_id "
            "LEFT JOIN privileges AS p "
            "ON rp.privilege_id=p.privilege_id "
            "WHERE ur.user_id = ?",
            (str(user.user_id),))
        return __build_resource_roles__(
            (dict(row) for row in cursor.fetchall()))
