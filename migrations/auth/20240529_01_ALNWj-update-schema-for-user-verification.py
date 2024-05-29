"""
update schema for user-verification
"""

from yoyo import step

__depends__ = {'20240506_01_798tW-create-jwt-refresh-tokens-table'}

def add_verification_cols_to_users_table(conn):
    "add verification columns to users table";
    conn.execute("PRAGMA foreign_keys = OFF")

    conn.execute(
        """
        CREATE TABLE users_new(
            user_id TEXT PRIMARY KEY NOT NULL,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            created INTEGER NOT NULL DEFAULT (unixepoch()),
            verified INTEGER NOT NULL DEFAULT 0 CHECK (verified=0 or verified=1)
        ) WITHOUT ROWID
        """)
    conn.execute(
        """
        INSERT INTO users_new(user_id, email, name)
        SELECT user_id, email, name FROM users
        """)
    # the original table `users` has dependents, so we cannot simply do a
    # `ALTER TABLE … RENAME TO …` since according to
    # https://sqlite.org/lang_altertable.html#alter_table_rename
    # from versions 3.26.0 onward, the foreign key references are **ALWAYS**
    # changed. In this case, we create the new table first, do data transfers,
    # drop the original and rename the new table to the same name as the
    # original.
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("ALTER TABLE users_new RENAME TO users")

    
    print("turning foreign keys should back on.")
    conn.execute("PRAGMA foreign_key_check")
    conn.execute("PRAGMA foreign_keys = ON")

def drop_verification_cols_from_users_table(conn):
    "Drop verification columns from users table"
    conn.execute("ALTER TABLE users DROP COLUMN created")
    conn.execute("ALTER TABLE users DROP COLUMN verified")

steps = [
    step(add_verification_cols_to_users_table,
         drop_verification_cols_from_users_table),
    step(
        """
        CREATE TABLE IF NOT EXISTS user_verification_codes(
          user_id TEXT NOT NULL,
          code TEXT NOT NULL,
          generated INTEGER NOT NULL,
          expires INTEGER NOT NULL,
          PRIMARY KEY(user_id),
          FOREIGN KEY(user_id) REFERENCES users(user_id)
            ON UPDATE CASCADE ON DELETE CASCADE
        ) WITHOUT ROWID
        """,
        "DROP TABLE IF EXISTS verification_codes")
]
