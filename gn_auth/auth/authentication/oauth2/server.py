"""Initialise the OAuth2 Server"""
import uuid
from typing import Callable
from datetime import datetime

from flask import Flask, current_app, request as flask_request
from authlib.jose import KeySet
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749.errors import InvalidClientError
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.integrations.flask_oauth2.requests import FlaskOAuth2Request

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.jwks import (
    list_jwks,
    jwks_directory,
    newest_jwk_with_rotation)

from .models.jwt_bearer_token import JWTBearerToken
from .models.oauth2client import client as fetch_client
from .models.oauth2token import OAuth2Token, save_token

from .grants.password_grant import PasswordGrant
from .grants.refresh_token_grant import RefreshTokenGrant
from .grants.authorisation_code_grant import AuthorisationCodeGrant
from .grants.jwt_bearer_grant import JWTBearerGrant, JWTBearerTokenGenerator

from .endpoints.revocation import RevocationEndpoint
from .endpoints.introspection import IntrospectionEndpoint

from .resource_server import require_oauth, JWTBearerTokenValidator

_TWO_HOURS_ = 2 * 60 * 60


def create_query_client_func() -> Callable:
    """Create the function that loads the client."""
    def __query_client__(client_id: uuid.UUID):
        # use current_app rather than passing the db_uri to avoid issues
        # when config changes, e.g. while testing.
        with db.connection(current_app.config["AUTH_DB"]) as conn:
            _client = fetch_client(conn, client_id).maybe(
                None, lambda clt: clt) # type: ignore[misc]
            if bool(_client):
                return _client
            raise InvalidClientError(
                "No client found for the given CLIENT_ID and CLIENT_SECRET.")

    return __query_client__

def create_save_token_func(token_model: type) -> Callable:
    """Create the function that saves the token."""
    def __ignore_token__(token, request):# pylint: disable=[unused-argument]
        """Ignore the token: i.e. Do not save it."""

    def __save_token__(token, request):
        with db.connection(current_app.config["AUTH_DB"]) as conn:
            save_token(
                conn,
                token_model(
                    **token,
                    token_id=uuid.uuid4(),
                    client=request.client,
                    user=request.user,
                    issued_at=datetime.now(),
                    revoked=False,
                    expires_in=_TWO_HOURS_))

    return {
        OAuth2Token: __save_token__,
        JWTBearerToken: __ignore_token__
    }[token_model]

def make_jwt_token_generator(app):
    """Make token generator function."""
    def __generator__(# pylint: disable=[too-many-arguments, too-many-positional-arguments]
            grant_type,
            client,
            user=None,
            scope=None,
            expires_in=None,# pylint: disable=[unused-argument]
            include_refresh_token=True
    ):
        return JWTBearerTokenGenerator(
            secret_key=newest_jwk_with_rotation(
                jwks_directory(app),
                int(app.config["JWKS_ROTATION_AGE_DAYS"])),
            issuer=flask_request.host_url,
            alg="RS256").__call__(
                grant_type=grant_type,
                client=client,
                user=user,
                scope=scope,
                expires_in=expires_in,
                include_refresh_token=include_refresh_token)
    return __generator__



class JsonAuthorizationServer(AuthorizationServer):
    """An authorisation server using JSON rather than FORMDATA."""

    def create_oauth2_request(self, request):
        """Create an OAuth2 Request from the flask request."""
        match flask_request.headers.get("Content-Type"):
            case "application/json":
                req = OAuth2Request(flask_request.method,
                                     flask_request.url,
                                     flask_request.get_json(),
                                     flask_request.headers)
            case _:
                req = FlaskOAuth2Request(flask_request)

        return req


def setup_oauth2_server(app: Flask) -> None:
    """Set's up the oauth2 server for the flask application."""
    server = JsonAuthorizationServer()
    server.register_grant(PasswordGrant)

    # Figure out a common `code_verifier` for GN2 and GN3 and set
    # server.register_grant(AuthorisationCodeGrant, [CodeChallenge(required=False)])
    # below
    server.register_grant(AuthorisationCodeGrant)

    server.register_grant(JWTBearerGrant)
    jwttokengenerator = make_jwt_token_generator(app)
    server.register_token_generator(
        "urn:ietf:params:oauth:grant-type:jwt-bearer", jwttokengenerator)
    server.register_token_generator("refresh_token", jwttokengenerator)
    server.register_grant(RefreshTokenGrant)

    # register endpoints
    server.register_endpoint(RevocationEndpoint)
    server.register_endpoint(IntrospectionEndpoint)

    # init server
    server.init_app(
        app,
        query_client=create_query_client_func(),
        save_token=create_save_token_func(JWTBearerToken))
    app.config["OAUTH2_SERVER"] = server

    ## Set up the token validators
    require_oauth.register_token_validator(
        JWTBearerTokenValidator(KeySet(list_jwks(jwks_directory(app)))))
