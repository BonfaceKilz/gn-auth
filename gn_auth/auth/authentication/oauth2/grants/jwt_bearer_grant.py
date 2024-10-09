"""JWT as Authorisation Grant"""
import uuid

from flask import current_app as app

from authlib.common.security import generate_token
from authlib.oauth2.rfc7523.jwt_bearer import JWTBearerGrant as _JWTBearerGrant
from authlib.oauth2.rfc7523.token import (
    JWTBearerTokenGenerator as _JWTBearerTokenGenerator)

from gn_auth.auth.db.sqlite3 import with_db_connection
from gn_auth.auth.authentication.users import user_by_id


class JWTBearerTokenGenerator(_JWTBearerTokenGenerator):
    """
    A JSON Web Token formatted bearer token generator for jwt-bearer grant type.
    """

    DEFAULT_EXPIRES_IN = 300

    def get_token_data(#pylint: disable=[too-many-arguments]
            self, grant_type, client, expires_in=None, user=None, scope=None
    ):
        """Post process data to prevent JSON serialization problems."""
        tokendata = super().get_token_data(
            grant_type, client, expires_in, user, scope)
        return {
            **{
                key: str(value) if key.endswith("_id") else value
                for key, value in tokendata.items()
            },
            "sub": str(tokendata["sub"]),
            "jti": str(uuid.uuid4()),
            "oauth2_client_id": str(client.client_id)
        }


    def __call__(# pylint: disable=[too-many-arguments]
            self, grant_type, client, user=None, scope=None, expires_in=None,
            include_refresh_token=True
    ):
        # there is absolutely no refresh token in JWT format
        """
        The default generator does not provide refresh tokens with JWT. It goes
        so far as to state "there is absolutely no refresh token in JWT format".

        This shim allows us to have a refresh token. We should probably look for
        a supported way of using JWTs with refresh capability.
        """
        token = self.generate(grant_type, client, user, scope, expires_in)
        if include_refresh_token:
            return {
                **token,
                "refresh_token": generate_token(length=42)
            }
        return token


class JWTBearerGrant(_JWTBearerGrant):
    """Implement JWT as Authorisation Grant."""

    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_post", "client_secret_jwt"]
    CLAIMS_OPTIONS = {
        **_JWTBearerGrant.CLAIMS_OPTIONS,
        "jti": {"essential": True}
    }


    def resolve_issuer_client(self, issuer):
        """Fetch client via "iss" in assertion claims."""
        return with_db_connection(
            lambda conn: self.server.query_client(issuer))


    def resolve_client_key(self, client, headers, payload):
        """Resolve client key to decode assertion data."""
        return client.jwks().find_by_kid(headers["kid"])


    def authenticate_user(self, subject):
        """Authenticate user with the given assertion claims."""
        return with_db_connection(lambda conn: user_by_id(conn, subject))


    def has_granted_permission(self, client, user):
        """
        Check if the client has permission to access the given user's resource.
        """
        return True # TODO: Check this!!!

    def create_token_response(self):
        """If valid and authorized, the authorization server issues an access
        token.
        """
        token = self.generate_token(
            scope=self.request.scope,
            user=self.request.user,
            include_refresh_token=self.request.client.check_grant_type(
                "refresh_token")
        )
        app.logger.debug('Issue token %r to %r', token, self.request.client)
        self.save_token(token)
        return 200, token, self.TOKEN_RESPONSE_HEADER
