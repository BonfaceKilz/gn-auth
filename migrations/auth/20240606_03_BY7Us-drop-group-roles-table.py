"""
Drop 'group_roles' table.
"""
import sqlite3
from yoyo import step

__depends__ = {'20240606_02_ubZri-create-resource-roles-table'}

def restore_group_roles(conn):
    """Restore the `group_roles` table."""
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE group_roles(
          group_role_id TEXT PRIMARY KEY,
          group_id TEXT NOT NULL,
          role_id TEXT NOT NULL,
          UNIQUE (group_id, role_id),
          FOREIGN KEY(group_id) REFERENCES groups(group_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
          FOREIGN KEY(role_id) REFERENCES roles(role_id)
            ON UPDATE CASCADE ON DELETE RESTRICT
        ) WITHOUT ROWID
        """)
    cursor.execute(
        """
        CREATE INDEX idx_tbl_group_roles_cols_group_id
        ON group_roles(group_id)
        """)
    cursor.close()

steps = [
    step("DROP TABLE IF EXISTS group_roles", restore_group_roles)
]
