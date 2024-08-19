"""
Create forgot_password_tokens table

This will be used to enable users to validate/verify their password change
requests.
"""

from yoyo import step

__depends__ = {'20240606_03_BY7Us-drop-group-roles-table'}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS forgot_password_tokens(
          user_id TEXT NOT NULL,
          token TEXT NOT NULL,
          generated INTEGER NOT NULL,
          expires INTEGER NOT NULL,
          PRIMARY KEY(user_id),
          FOREIGN KEY(user_id) REFERENCES users(user_id)
            ON UPDATE CASCADE ON DELETE CASCADE
        ) WITHOUT ROWID
        """,
        "DROP TABLE IF EXISTS forgot_password_tokens")
]
