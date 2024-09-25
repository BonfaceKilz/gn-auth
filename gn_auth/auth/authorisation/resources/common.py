"""Utilities common to more than one resource."""
import uuid

from sqlite3 import Cursor

def assign_resource_owner_role(
        cursor: Cursor,
        resource_id: uuid.UUID,
        user_id: uuid.UUID
) -> dict:
    """Assign `user` the 'Resource Owner' role for `resource`."""
    cursor.execute("SELECT * FROM roles WHERE role_name='resource-owner'")
    role = cursor.fetchone()
    params = {
        "user_id": str(user_id),
        "role_id": role["role_id"],
        "resource_id": str(resource_id)
    }
    cursor.execute(
        "INSERT INTO user_roles "
        "VALUES (:user_id, :role_id, :resource_id) "
        "ON CONFLICT (user_id, role_id, resource_id) DO NOTHING",
        params)
    return params
