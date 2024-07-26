"""Implement model for JWTBearerToken"""
import uuid

from authlib.oauth2.rfc7523 import JWTBearerToken as _JWTBearerToken

from gn_auth.auth.db.sqlite3 import with_db_connection
from gn_auth.auth.authentication.users import user_by_id

class JWTBearerToken(_JWTBearerToken):
    """Overrides default JWTBearerToken class."""

    def __init__(self, payload, header, options=None, params=None):
        super().__init__(payload, header, options, params)
        self.user = with_db_connection(
            lambda conn:user_by_id(conn, uuid.UUID(payload["sub"])))
