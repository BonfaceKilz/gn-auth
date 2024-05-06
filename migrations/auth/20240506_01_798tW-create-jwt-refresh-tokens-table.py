"""
Create jwt_refresh_tokens table
"""

from yoyo import step

__depends__ = {'20231011_01_CS8NZ-create-new-inbredset-group-owner-role'}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS jwt_refresh_tokens
        -- Store refresh tokens to verify refresh attempts
        (
          token TEXT NOT NULL,
          client_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          issued_with TEXT NOT NULL UNIQUE, -- JWT ID of JWT issued along with this refresh token
          issued_at INTEGER NOT NULL,
          expires INTEGER NOT NULL,
          scope TEXT NOT NULL,
          revoked INTEGER CHECK (revoked = 0 or revoked = 1),
          parent_of TEXT UNIQUE,
          PRIMARY KEY(token),
          FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
          FOREIGN KEY (user_id) REFERENCES users(user_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
          FOREIGN KEY (parent_of) REFERENCES jwt_refresh_tokens(token)
            ON UPDATE CASCADE ON DELETE RESTRICT
        ) WITHOUT ROWID
        """,
        "DROP TABLE IF EXISTS jwt_refresh_tokens")
]
