"""
Refresh tokens for JWTs

Refresh tokens are not supported directly by JWTs. This therefore provides a
form of extension to JWTs.
"""
import uuid
import datetime
from typing import Optional
from dataclasses import dataclass

from authlib.oauth2.rfc6749 import TokenMixin, InvalidGrantError

from pymonad.either import Left, Right
from pymonad.maybe import Just, Maybe, Nothing
from pymonad.tools import monad_from_none_or_value

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.errors import ForbiddenAccess
from gn_auth.auth.authentication.users import User, user_by_id

from gn_auth.auth.authentication.oauth2.models.oauth2client import (
    OAuth2Client,
    client as fetch_client)

@dataclass(frozen=True)
class JWTRefreshToken(TokenMixin):# pylint: disable=[too-many-instance-attributes]
    """Class representing a JWT refresh token."""
    token: str
    client: OAuth2Client
    user: User
    issued_with: uuid.UUID
    issued_at: datetime.datetime
    expires: datetime.datetime
    scope: str
    revoked: bool
    parent_of: Optional[str] = None

    def is_expired(self):
        """Check whether refresh token has expired."""
        return self.expires <= datetime.datetime.now()

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return (self.expires - self.issued_at).total_seconds()

    def is_revoked(self):
        """Check whether refresh token is revoked"""
        return self.revoked

    def check_client(self, client: OAuth2Client) -> bool:
        """Check whether the token is issued to given `client`."""
        return client.client_id == self.client.client_id


def revoke_refresh_token(conn: db.DbConnection, token: JWTRefreshToken) -> None:
    """Revoke a refresh token and all its children."""
    tree_query = """
    -- CTE: See https://codedamn.com/news/sql/recursive-sql-queries-hierarchical-data-management
    WITH RECURSIVE token_tree (token, parent_of, revoked, level) AS (
        -- anchor member
        SELECT token, parent_of, revoked, 1 AS level
        FROM jwt_refresh_tokens
        WHERE token=:root
        -- merge the anchor above to the recursive member below!
        UNION ALL
        -- recursive member
        SELECT jrt.token, jrt.parent_of, jrt.revoked, tt.level + 1
        FROM jwt_refresh_tokens AS jrt
        INNER JOIN token_tree AS tt
        ON tt.parent_of=jrt.token
    ) SELECT * FROM token_tree;
    """
    with db.cursor(conn) as cursor:
        cursor.execute(tree_query, {"root": token.token})
        rows = cursor.fetchall()
        if rows:
            cursor.executemany(
                "UPDATE jwt_refresh_tokens SET revoked=1 WHERE token=?",
                tuple((row["token"],) for row in rows))


def save_refresh_token(conn: db.DbConnection, token: JWTRefreshToken) -> None:
    """Save the Refresh tokens into the database."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            ("INSERT INTO jwt_refresh_tokens"
             "(token, client_id, user_id, issued_with, issued_at, expires, "
             "scope, revoked, parent_of) "
             "VALUES"
             "(:token, :client_id, :user_id, :issued_with, :issued_at, "
             ":expires, :scope, :revoked, :parent_of) "
             "ON CONFLICT (token) DO UPDATE SET parent_of=:parent_of"),
            {
                "token": token.token,
                "client_id": str(token.client.client_id),
                "user_id": str(token.user.user_id),
                "issued_with": str(token.issued_with),
                "issued_at": token.issued_at.timestamp(),
                "expires": token.expires.timestamp(),
                "scope": token.get_scope(),
                "revoked": token.revoked,
                "parent_of": token.parent_of
            })


def load_refresh_token(conn: db.DbConnection, token: str) -> Maybe:
    """Load a refresh_token by its token string."""
    def __process_results__(results):
        _user = user_by_id(conn, uuid.UUID(results["user_id"]))
        _now = datetime.datetime.now()
        return JWTRefreshToken(
            token=results["token"],
            client=fetch_client(
                conn, uuid.UUID(results["client_id"]), user=_user).maybe(
                    OAuth2Client(uuid.uuid4(), "secret", _now, _now, {}, _user),
                    lambda _client: _client),
            user=_user,
            issued_with=uuid.UUID(results["issued_with"]),
            issued_at=datetime.datetime.fromtimestamp(results["issued_at"]),
            expires=datetime.datetime.fromtimestamp(results["expires"]),
            scope=results["scope"],
            revoked=bool(int(results["revoked"])),
            parent_of=results["parent_of"]
        )

    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM jwt_refresh_tokens WHERE token=:token",
                       {"token": token})
        return monad_from_none_or_value(Nothing, Just, cursor.fetchone()).then(
            __process_results__)


def link_child_token(conn: db.DbConnection, parenttoken: str, childtoken: str):
    """Link child token."""
    def __link_to_child__(parent):
        with db.cursor(conn) as cursor:
            cursor.execute(
                ("UPDATE jwt_refresh_tokens SET parent_of=:childtoken "
                 "WHERE token=:parenttoken"),
                {"parenttoken": parent.token, "childtoken": childtoken})

    def __check_child__(parent):#pylint: disable=[unused-variable]
        with db.cursor(conn) as cursor:
            cursor.execute(
                ("SELECT * FROM jwt_refresh_tokens WHERE token=:parenttoken"),
                {"parenttoken": parent.token})
            results = cursor.fetchone()
            if results["parent_of"] is not None:
                return Left(
                    "Refresh token has been used before. Possibly nefarious "
                    "activity detected.")
            return Right(parent)

    def __revoke_and_raise_error__(_error_msg_):#pylint: disable=[unused-variable]
        load_refresh_token(conn, parenttoken).then(
            lambda _tok: revoke_refresh_token(conn, _tok))
        raise InvalidGrantError(_error_msg_)

    def __handle_not_found__(_error_msg_):
        raise InvalidGrantError(_error_msg_)

    load_refresh_token(conn, parenttoken).maybe(
        Left("Token not found"), Right).either(
            __handle_not_found__, __link_to_child__)


def is_refresh_token_valid(token: JWTRefreshToken, client: OAuth2Client) -> bool:
    """Check whether a token is valid."""
    if not token.client.client_id == client.client_id:
        raise ForbiddenAccess("Token does not belong to client.")

    if token.is_expired():
        raise ForbiddenAccess("Token is expired.")

    if token.revoked:
        raise ForbiddenAccess("Token has previously been revoked.")

    return True
