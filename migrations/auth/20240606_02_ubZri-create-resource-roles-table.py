"""
Create 'resource_roles' table.
"""

from yoyo import step

__depends__ = {'20240606_01_xQDwL-move-role-manipulation-privileges-from-group-to-resources'}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS resource_roles(
          resource_id TEXT NOT NULL,
          role_created_by TEXT NOT NULL,
          role_id TEXT NOT NULL,
          PRIMARY KEY (resource_id, role_created_by, role_id),
          FOREIGN KEY(resource_id) REFERENCES resources(resource_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
          FOREIGN KEY(role_created_by) REFERENCES users(user_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
          FOREIGN KEY(role_id) REFERENCES roles(role_id)
            ON UPDATE CASCADE ON DELETE RESTRICT
        ) WITHOUT ROWID
        """,
        "DROP TABLE IF EXISTS resource_roles"),
    step(
        """
        CREATE INDEX IF NOT EXISTS
        tbl_resource_roles_cols_resource_id_role_created_by
        ON resource_roles(resource_id, role_created_by)
        """,
        """
        DROP INDEX IF EXISTS
        tbl_resource_roles_cols_resource_id_role_created_by
        """)
]
