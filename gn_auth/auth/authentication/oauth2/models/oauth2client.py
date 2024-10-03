"""OAuth2 Client model."""
import json
import logging
import datetime
from uuid import UUID
from functools import cached_property
from dataclasses import asdict, dataclass
from typing import Any, Sequence, Optional

import requests
from requests.exceptions import JSONDecodeError
from authlib.jose import KeySet, JsonWebKey
from authlib.oauth2.rfc6749 import ClientMixin
from pymonad.maybe import Just, Maybe, Nothing

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.errors import NotFoundError
from gn_auth.auth.authentication.users import (User,
                                               fetch_users,
                                               user_by_id,
                                               same_password)


@dataclass(frozen=True)
class OAuth2Client(ClientMixin):
    """
    Client to the OAuth2 Server.

    This is defined according to the mixin at
    https://docs.authlib.org/en/latest/specs/rfc6749.html#authlib.oauth2.rfc6749.ClientMixin
    """
    client_id: UUID
    client_secret: str
    client_id_issued_at: datetime.datetime
    client_secret_expires_at: datetime.datetime
    client_metadata: dict
    user: User

    def check_client_secret(self, client_secret: str) -> bool:
        """Check whether the `client_secret` matches this client."""
        return same_password(client_secret, self.client_secret)

    @cached_property
    def token_endpoint_auth_method(self) -> str:
        """Return the token endpoint authorisation method."""
        return self.client_metadata.get("token_endpoint_auth_method", ["none"])

    @cached_property
    def client_type(self) -> str:
        """
        Return the token endpoint authorisation method.

        Acceptable client types:
        * public: Unable to use registered client secrets, e.g. browsers, apps
          on mobile devices.
        * confidential: able to securely authenticate with authorisation server
          e.g. being able to keep their registered client secret safe.
        """
        return self.client_metadata.get("client_type", "public")


    def jwks(self) -> KeySet:
        """Return this client's KeySet."""
        jwksuri = self.client_metadata.get("public-jwks-uri")
        if not bool(jwksuri):
            logging.debug("No Public JWKs URI set for client!")
            return KeySet([])
        try:
            ## IMPORTANT: This can cause a deadlock if the client is working in
            ##            single-threaded mode, i.e. can only serve one request
            ##            at a time.
            return KeySet([JsonWebKey.import_key(key)
                           for key in requests.get(jwksuri).json()["jwks"]])
        except requests.ConnectionError as _connerr:
            logging.debug(
                "Could not connect to provided URI: %s", jwksuri, exc_info=True)
        except JSONDecodeError as _jsonerr:
            logging.debug(
                "Could not convert response to JSON", exc_info=True)
        except Exception as _exc:# pylint: disable=[broad-except]
            logging.debug(
                "Error retrieving the JWKs for the client.", exc_info=True)
        return KeySet([])


    def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
        """
        Check if the client supports the given method for the given endpoint.

        Acceptable methods:
        * none: Client is a public client and does not have a client secret
        * client_secret_post: Client uses the HTTP POST parameters
        * client_secret_basic: Client uses HTTP Basic
        """
        if endpoint in ("token", "revoke", "introspection"):
            return (method in self.token_endpoint_auth_method
                    and method == "client_secret_post")
        return False

    @cached_property
    def id(self):  # pylint: disable=[invalid-name]
        """Return the client_id."""
        return self.client_id

    @cached_property
    def grant_types(self) -> Sequence[str]:
        """
        Return the grant types that this client supports.

        Valid grant types:
        * authorisation_code
        * implicit
        * client_credentials
        * password
        """
        return self.client_metadata.get("grant_types", [])

    def check_grant_type(self, grant_type: str) -> bool:
        """
        Validate that client can handle the given grant types
        """
        return grant_type in self.grant_types

    @cached_property
    def redirect_uris(self) -> Sequence[str]:
        """Return the redirect_uris that this client supports."""
        return self.client_metadata.get('redirect_uris', [])

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        """
        Check whether the given `redirect_uri` is one of the expected ones.
        """
        return redirect_uri in self.redirect_uris

    @cached_property
    def response_types(self) -> Sequence[str]:
        """Return the response_types that this client supports."""
        return self.client_metadata.get("response_type", [])

    def check_response_type(self, response_type: str) -> bool:
        """Check whether this client supports `response_type`."""
        return response_type in self.response_types

    @cached_property
    def scope(self) -> Sequence[str]:
        """Return valid scopes for this client."""
        return tuple(set(self.client_metadata.get("scope", [])))

    def get_allowed_scope(self, scope: str) -> str:
        """Return list of scopes in `scope` that are supported by this
        client."""
        if not bool(scope):
            return ""
        requested = scope.split()
        return " ".join(sorted(set(
            scp for scp in requested if scp in self.scope)))

    def get_client_id(self):
        """Return this client's identifier."""
        return self.client_id

    def get_default_redirect_uri(self) -> str:
        """Return the default redirect uri"""
        return self.client_metadata.get("default_redirect_uri", "")


def client(conn: db.DbConnection, client_id: UUID,
           user: Optional[User] = None) -> Maybe:
    """Retrieve a client by its ID"""
    with db.cursor(conn) as cursor:
        cursor.execute(
            "SELECT * FROM oauth2_clients WHERE client_id=?",
            (str(client_id),))
        result = cursor.fetchone()
        _user = user
        if result:
            if not bool(_user):
                try:
                    _user = user_by_id(conn, result["user_id"])
                except NotFoundError:
                    _user = None

            return Just(
                OAuth2Client(
                    client_id=UUID(result["client_id"]),
                    client_secret=result["client_secret"],
                    client_id_issued_at=datetime.datetime.fromtimestamp(
                        result["client_id_issued_at"]
                    ),
                    client_secret_expires_at=datetime.datetime.fromtimestamp(
                        result["client_secret_expires_at"]
                    ),
                    client_metadata=json.loads(result["client_metadata"]),
                    user=_user)  # type: ignore[arg-type]
            )
    return Nothing


def client_by_id_and_secret(conn: db.DbConnection, client_id: UUID,
                            client_secret: str) -> OAuth2Client:
    """Retrieve a client by its ID and secret"""
    with db.cursor(conn) as cursor:
        cursor.execute(
            "SELECT * FROM oauth2_clients WHERE client_id=?",
            (str(client_id),))
        row = cursor.fetchone()
        if bool(row) and same_password(client_secret, row["client_secret"]):
            return OAuth2Client(
                client_id=client_id,
                client_secret=client_secret,
                client_id_issued_at=datetime.datetime.fromtimestamp(
                    row["client_id_issued_at"]
                ),
                client_secret_expires_at=datetime.datetime.fromtimestamp(
                    row["client_secret_expires_at"]
                ),
                client_metadata=json.loads(row["client_metadata"]),
                user=user_by_id(conn, UUID(row["user_id"]))
            )
        raise NotFoundError(
            "Could not find client with the given credentials."
        )


def save_client(
        conn: db.DbConnection, the_client: OAuth2Client
) -> OAuth2Client:
    """Persist the client details into the database."""
    with db.cursor(conn) as cursor:
        query = (
            "INSERT INTO oauth2_clients "
            "(client_id, client_secret, client_id_issued_at, "
            "client_secret_expires_at, client_metadata, user_id) "
            "VALUES "
            "(:client_id, :client_secret, :client_id_issued_at, "
            ":client_secret_expires_at, :client_metadata, :user_id) "
            "ON CONFLICT (client_id) DO UPDATE SET "
            "client_secret=:client_secret, "
            "client_id_issued_at=:client_id_issued_at, "
            "client_secret_expires_at=:client_secret_expires_at, "
            "client_metadata=:client_metadata, user_id=:user_id")
        cursor.execute(
            query,
            {
                "client_id": str(the_client.client_id),
                "client_secret": the_client.client_secret,
                "client_id_issued_at": (
                    the_client.client_id_issued_at.timestamp()),
                "client_secret_expires_at": (
                    the_client.client_secret_expires_at.timestamp()),
                "client_metadata": json.dumps(the_client.client_metadata),
                "user_id": str(the_client.user.user_id)
            })
        return the_client


def oauth2_clients(conn: db.DbConnection) -> tuple[OAuth2Client, ...]:
    """Fetch a list of all OAuth2 clients."""
    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM oauth2_clients")
        clients_rs = cursor.fetchall()
        the_users = {
            usr.user_id: usr for usr in fetch_users(
                conn, tuple({UUID(result["user_id"])
                             for result in clients_rs}))
        }
        return tuple(
            OAuth2Client(
                client_id=UUID(result["client_id"]),
                client_secret=result["client_secret"],
                client_id_issued_at=datetime.datetime.fromtimestamp(
                    result["client_id_issued_at"]),
                client_secret_expires_at=datetime.datetime.fromtimestamp(
                    result["client_secret_expires_at"]),
                client_metadata=json.loads(result["client_metadata"]),
                user=the_users[UUID(result["user_id"])]
            ) for result in clients_rs
        )


def delete_client(
        conn: db.DbConnection, the_client: OAuth2Client
) -> OAuth2Client:
    """Delete the given client from the database"""
    with db.cursor(conn) as cursor:
        params = (str(the_client.client_id),)
        cursor.execute("DELETE FROM authorisation_code WHERE client_id=?",
                       params)
        cursor.execute("DELETE FROM oauth2_tokens WHERE client_id=?", params)
        cursor.execute("DELETE FROM oauth2_clients WHERE client_id=?", params)
        return the_client


def update_client_attribute(
        client: OAuth2Client, attribute: str, value: Any) -> OAuth2Client:
    """Return a new OAuth2Client with the given attribute updated/changed."""
    attrs = {
        attr: type(value)
        for attr, value in asdict(client).items()
        if attr != "client_id"
    }
    assert (
        attribute in attrs.keys() and isinstance(value, attrs[attribute])), (
            "Invalid attribute/value provided!")
    return OAuth2Client(
        client_id=client.client_id,
        **{
            attr: (value if attr==attribute else getattr(client, attr))
            for attr in attrs
        })
