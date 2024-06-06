"""
Move role-manipulation privileges from group to resources
"""
import sqlite3
from yoyo import step

__depends__ = {'20240529_01_ALNWj-update-schema-for-user-verification'}

def role_by_name(cursor, role_name):
    """Fetch group-admin role"""
    cursor.execute("SELECT * FROM roles WHERE role_name=?",
                   (role_name,))
    return dict(cursor.fetchone())


def move_privileges_to_resources(conn):
    """Move role-manipulation privileges from group to resource."""
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM role_privileges WHERE privilege_id IN ("
        "  'group:role:create-role',"
        "  'group:role:delete-role',"
        "  'group:role:edit-role',"
        "  'group:user:assign-role'"
        ")")
    cursor.execute(
        "DELETE FROM privileges WHERE privilege_id IN ("
        "  'group:role:create-role',"
        "  'group:role:delete-role',"
        "  'group:role:edit-role',"
        "  'group:user:assign-role'"
        ")")

    resource_owner_role = role_by_name(cursor, "resource-owner")
    privileges = (
        ("resource:role:create-role",
         "Create a new role on a specific resource"),
        ("resource:role:delete-role",
         "Delete an existing role from a specific resource"),
        ("resource:role:edit-role",
         "Edit an existing role on a specific resource"),
        ("resource:user:assign-role",
         "Assign a user to a role on a specific resource"))
    cursor.executemany(
        ("INSERT INTO privileges(privilege_id, privilege_description) "
         "VALUES (?, ?)"),
        privileges)
    cursor.executemany(
        ("INSERT INTO role_privileges(role_id, privilege_id) "
         "VALUES(?, ?)"),
        tuple((resource_owner_role["role_id"], privilege[0])
              for privilege in privileges))
    cursor.close()

def move_privileges_to_groups(conn):
    """Move role-manipulation privileges from resource to group."""
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM role_privileges WHERE privilege_id IN ("
        "  'resource:role:create-role',"
        "  'resource:role:delete-role',"
        "  'resource:role:edit-role',"
        "  'resource:user:assign-role'"
        ")")
    cursor.execute(
        "DELETE FROM privileges WHERE privilege_id IN ("
        "  'resource:role:create-role',"
        "  'resource:role:delete-role',"
        "  'resource:role:edit-role',"
        "  'resource:user:assign-role'"
        ")")

    group_leader_role = role_by_name(cursor, "group-leader")
    privileges = (
        ("group:role:create-role", "Create a new role"),
        ("group:role:delete-role", "Delete an existing role"),
        ("group:role:edit-role", "edit/update an existing role"),
        ("group:user:assign-role", "Assign a role to an existing user"))
    cursor.executemany(
        ("INSERT INTO privileges(privilege_id, privilege_description) "
         "VALUES (?, ?)"),
        privileges)
    cursor.executemany(
        ("INSERT INTO role_privileges(role_id, privilege_id) "
         "VALUES(?, ?)"),
        tuple((group_leader_role["role_id"], privilege[0])
              for privilege in privileges))
    cursor.close()

steps = [
    step(move_privileges_to_resources, move_privileges_to_groups)
]
