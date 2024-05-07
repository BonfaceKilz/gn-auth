"""Initialise the OAuth2 Server"""
import uuid
import datetime
from typing import Callable

from flask import Flask, current_app
from authlib.jose import jwk, jwt
from authlib.oauth2.rfc7523 import JWTBearerTokenValidator
from authlib.oauth2.rfc6749.errors import InvalidClientError
from authlib.integrations.flask_oauth2 import AuthorizationServer

from gn_auth.auth.db import sqlite3 as db

from .models.oauth2client import client
from .models.oauth2token import OAuth2Token, save_token

from .grants.password_grant import PasswordGrant
from .grants.authorisation_code_grant import AuthorisationCodeGrant
from .grants.jwt_bearer_grant import JWTBearerGrant, JWTBearerTokenGenerator

from .endpoints.revocation import RevocationEndpoint
from .endpoints.introspection import IntrospectionEndpoint

from .resource_server import require_oauth, BearerTokenValidator

def create_query_client_func() -> Callable:
    """Create the function that loads the client."""
    def __query_client__(client_id: uuid.UUID):
        # use current_app rather than passing the db_uri to avoid issues
        # when config changes, e.g. while testing.
        with db.connection(current_app.config["AUTH_DB"]) as conn:
            _client = client(conn, client_id).maybe(
                None, lambda clt: clt) # type: ignore[misc]
            if bool(_client):
                return _client
            raise InvalidClientError(
                "No client found for the given CLIENT_ID and CLIENT_SECRET.")

    return __query_client__

def create_save_token_func(token_model: type, jwtkey: jwk) -> Callable:
    """Create the function that saves the token."""
    def __save_token__(token, request):
        _jwt = jwt.decode(token["access_token"], jwtkey)
        _token = token_model(
            token_id=uuid.UUID(_jwt["jti"]),
            client=request.client,
            user=request.user,
            **{
                "refresh_token": None,
                "revoked": False,
                "issued_at": datetime.datetime.now(),
                **token
            })
        with db.connection(current_app.config["AUTH_DB"]) as conn:
            save_token(conn, _token)
                    user=request.user,
                    **{
                        "refresh_token": None, "revoked": False,
                        "issued_at": datetime.datetime.now(),
                        **token
                    }))

    return __save_token__

def setup_oauth2_server(app: Flask) -> None:
    """Set's up the oauth2 server for the flask application."""
    server = AuthorizationServer()
    server.register_grant(PasswordGrant)

    # Figure out a common `code_verifier` for GN2 and GN3 and set
    # server.register_grant(AuthorisationCodeGrant, [CodeChallenge(required=False)])
    # below
    server.register_grant(AuthorisationCodeGrant)

    server.register_grant(JWTBearerGrant)
    server.register_token_generator(
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        JWTBearerTokenGenerator(app.config["SSL_PRIVATE_KEY"]))

    # register endpoints
    server.register_endpoint(RevocationEndpoint)
    server.register_endpoint(IntrospectionEndpoint)

    # init server
    server.init_app(
        app,
        query_client=create_query_client_func(),
        save_token=create_save_token_func(
            OAuth2Token, app.config["SSL_PRIVATE_KEY"]))
    app.config["OAUTH2_SERVER"] = server

    ## Set up the token validators
    require_oauth.register_token_validator(BearerTokenValidator())
    require_oauth.register_token_validator(
        JWTBearerTokenValidator(app.config["SSL_PRIVATE_KEY"].get_public_key()))
