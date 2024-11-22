"""Main entry point for project"""
import sys
import uuid
import json
from math import ceil
from pathlib import Path
from datetime import datetime

import click
from yoyo import get_backend, read_migrations

from gn_auth import migrations
from gn_auth import create_app

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.errors import NotFoundError
from gn_auth.auth.authentication.users import user_by_id, hash_password
from gn_auth.auth.authorisation.users.admin.models import make_sys_admin

from scripts import register_sys_admin as rsysadm# type: ignore[import]


app = create_app()

##### BEGIN: CLI Commands #####

@app.cli.command()
def apply_migrations():
    """Apply the dabasase migrations."""
    migrations.apply_migrations(
        get_backend(f'sqlite:///{app.config["AUTH_DB"]}'),
        read_migrations(app.config["AUTH_MIGRATIONS"]))

def __init_dev_users__():
    """Initialise dev users. Get's used in more than one place"""
    dev_users_query = """
    INSERT INTO users (user_id, email, name, verified)
        VALUES (:user_id, :email, :name, 1)
        ON CONFLICT(email) DO UPDATE SET
            name=excluded.name,
            verified=excluded.verified
    """
    dev_users_passwd = "INSERT OR REPLACE INTO user_credentials VALUES (:user_id, :hash)"
    dev_users = ({
        "user_id": "0ad1917c-57da-46dc-b79e-c81c91e5b928",
        "email": "test@development.user",
        "name": "Test Development User",
        "password": "testpasswd"},)

    with db.connection(app.config["AUTH_DB"]) as conn, db.cursor(conn) as cursor:
        cursor.executemany(dev_users_query, dev_users)
        cursor.executemany(dev_users_passwd, (
            {**usr, "hash": hash_password(usr["password"])}
            for usr in dev_users))

@app.cli.command()
def init_dev_users():
    """
    Initialise development users for OAuth2 sessions.

    **NOTE**: You really should not run this in production/staging
    """
    __init_dev_users__()

@app.cli.command()
@click.option('--client-uri', default= "http://localhost:5033", type=str)
def init_dev_clients(client_uri):
    """
    Initialise a development client for OAuth2 sessions.

    **NOTE**: You really should not run this in production/staging
    """
    client_uri = client_uri.lstrip("/")
    __init_dev_users__()
    dev_clients_query = """
        INSERT INTO oauth2_clients VALUES (
        :client_id, :client_secret, :client_id_issued_at,
        :client_secret_expires_at, :client_metadata, :user_id
        )
        ON CONFLICT(client_id) DO UPDATE SET
            client_secret=excluded.client_secret,
            client_secret_expires_at=excluded.client_secret_expires_at,
            client_metadata=excluded.client_metadata,
            user_id=excluded.user_id
        """
    dev_clients = ({
        "client_id": "0bbfca82-d73f-4bd4-a140-5ae7abb4a64d",
        "client_secret": "yadabadaboo",
        "client_id_issued_at": ceil(datetime.now().timestamp()),
        "client_secret_expires_at": 0,
        "client_metadata": json.dumps({
            "client_name": "GN2 Dev Server",
            "token_endpoint_auth_method": [
                "client_secret_post", "client_secret_basic"],
            "client_type": "confidential",
            "grant_types": ["password", "authorization_code", "refresh_token",
                            "urn:ietf:params:oauth:grant-type:jwt-bearer"],
            "default_redirect_uri": f"{client_uri}/oauth2/code",
            "redirect_uris": [f"{client_uri}/oauth2/code",
                              f"{client_uri}/oauth2/token"],
            "public-jwks-uri": f"{client_uri}/oauth2/public-jwks",
            "response_type": ["code", "token"],
            "scope": ["profile", "group", "role", "resource", "register-client",
                      "user", "masquerade", "migrate-data", "introspect"]
        }),
        "user_id": "0ad1917c-57da-46dc-b79e-c81c91e5b928"},)

    with db.connection(app.config["AUTH_DB"]) as conn, db.cursor(conn) as cursor:
        cursor.executemany(dev_clients_query, dev_clients)


@app.cli.command()
@click.argument("user_id", type=click.UUID)
def assign_system_admin(user_id: uuid.UUID):
    """Assign user with ID `user_id` administrator role."""
    try:
        dburi = app.config["AUTH_DB"]
        with db.connection(dburi) as conn, db.cursor(conn) as cursor:
            make_sys_admin(cursor, user_by_id(conn, user_id))
            return 0
    except NotFoundError as nfe:
        print(nfe, file=sys.stderr)
        sys.exit(1)

@app.cli.command()
def register_admin():
    """Register the administrator."""
    rsysadm.register_admin(Path(app.config["AUTH_DB"]))

##### END: CLI Commands #####

if __name__ == '__main__':
    print("Starting app...")
    app.run()
