"""Protect the resources endpoints"""
from datetime import datetime, timezone, timedelta

from flask import current_app as app

from authlib.jose import KeySet
from authlib.oauth2.rfc7523 import JWTBearerTokenValidator as _JWTBearerTokenValidator
from authlib.oauth2.rfc6750 import BearerTokenValidator as _BearerTokenValidator
from authlib.integrations.flask_oauth2 import ResourceProtector

from gn_auth.auth.jwks import list_jwks, jwks_directory
from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.authentication.oauth2.models.oauth2token import token_by_access_token

class BearerTokenValidator(_BearerTokenValidator):
    """Extends `authlib.oauth2.rfc6750.BearerTokenValidator`"""
    def authenticate_token(self, token_string: str):
        with db.connection(app.config["AUTH_DB"]) as conn:
            return token_by_access_token(conn, token_string).maybe(# type: ignore[misc]
                None, lambda tok: tok)

class JWTBearerTokenValidator(_JWTBearerTokenValidator):
    """Validate a token using all the keys"""
    _local_attributes = ("jwt_refresh_frequency_hours",)

    def __init__(self, public_key, issuer=None, realm=None, **extra_attributes):
        """Initialise the validator class."""
        # https://docs.authlib.org/en/latest/jose/jwt.html#use-dynamic-keys
        # We can simply use the KeySet rather than a specific key.
        super().__init__(public_key,
                         issuer,
                         realm,
                         **{
                             key: value for key,value
                             in extra_attributes.items()
                             if key not in self._local_attributes
                         })
        self._last_jwks_update = datetime.now(tz=timezone.utc)
        self._refresh_frequency = timedelta(hours=int(
            extra_attributes.get("jwt_refresh_frequency_hours", 6)))

    def __refresh_jwks__(self):
        now = datetime.now(tz=timezone.utc)
        if (now - self._last_jwks_update) >= self._refresh_frequency:
            self.public_key = KeySet(list_jwks(jwks_directory(app)))

    def authenticate_token(self, token_string: str):
        self.__refresh_jwks__()
        return super().authenticate_token(token_string)


require_oauth = ResourceProtector()
