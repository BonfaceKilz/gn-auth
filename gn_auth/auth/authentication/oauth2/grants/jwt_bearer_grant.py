"""JWT as Authorisation Grant"""
import uuid
from urllib.parse import urlparse
from datetime import datetime, timedelta

from flask import request, current_app as app

from authlib.jose import jwt

from authlib.oauth2.rfc7523.jwt_bearer import JWTBearerGrant as _JWTBearerGrant
from authlib.oauth2.rfc7523.token import (
    JWTBearerTokenGenerator as _JWTBearerTokenGenerator)

from gn_auth.auth.authentication.users import user_by_id
from gn_auth.auth.db.sqlite3 import connection, with_db_connection
from gn_auth.auth.authentication.oauth2.models.oauth2client import client


class JWTBearerTokenGenerator(_JWTBearerTokenGenerator):
    """
    A JSON Web Token formatted bearer token generator for jwt-bearer grant type.
    """

    DEFAULT_EXPIRES_IN = 300

    def get_token_data(self, grant_type, client, expires_in=300, user=None, scope=None):
        """Post process data to prevent JSON serialization problems."""
        tokendata = super().get_token_data(
            grant_type, client, expires_in, user, scope)
        return {
            **{
                key: str(value) if key.endswith("_id") else value
                for key, value in tokendata.items()
            },
            "sub": str(tokendata["sub"])}


class JWTBearerGrant(_JWTBearerGrant):
    """Implement JWT as Authorisation Grant."""

    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_post", "client_secret_jwt"]


    def resolve_issuer_client(self, issuer):
        """Fetch client via "iss" in assertion claims."""
        return with_db_connection(
            lambda conn: self.server.query_client(issuer))


    def resolve_client_key(self, client, headers, payload):
        """Resolve client key to decode assertion data."""
        return app.config["SSL_PUBLIC_KEYS"].get(headers["kid"])


    def authenticate_user(self, subject):
        """Authenticate user with the given assertion claims."""
        return with_db_connection(lambda conn: user_by_id(conn, subject))


    def has_granted_permission(self, client, user):
        """
        Check if the client has permission to access the given user's resource.
        """
        return True # TODO: Check this!!!
