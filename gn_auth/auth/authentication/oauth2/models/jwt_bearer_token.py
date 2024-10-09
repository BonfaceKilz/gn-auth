"""Implement model for JWTBearerToken"""
import uuid

from authlib.oauth2.rfc7523 import JWTBearerToken as _JWTBearerToken

from gn_auth.auth.db.sqlite3 import with_db_connection
from gn_auth.auth.authentication.users import user_by_id
from gn_auth.auth.authentication.oauth2.models.oauth2client import (
    client as fetch_client)

class JWTBearerToken(_JWTBearerToken):
    """Overrides default JWTBearerToken class."""

    def __init__(self, payload, header, options=None, params=None):
        """Initialise the bearer token."""
        # TOD0: Maybe remove this init and make this a dataclass like the way
        #       OAuth2Client is a dataclass
        super().__init__(payload, header, options, params)
        self.user = with_db_connection(
            lambda conn:user_by_id(conn, uuid.UUID(payload["sub"])))
        self.client = with_db_connection(
            lambda conn: fetch_client(
                conn, uuid.UUID(payload["oauth2_client_id"])
            )
        ).maybe(None, lambda _client: _client)


    def check_client(self, client):
        """Check that the client is right."""
        return self.client.get_client_id() == client.get_client_id()
