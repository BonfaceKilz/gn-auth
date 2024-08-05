"""Initialise the OAuth2 Server"""
import os
import uuid
from pathlib import Path
from typing import Callable
from datetime import datetime, timedelta

from pymonad.either import Left
from flask import Flask, current_app
from authlib.jose import jwt, KeySet, JsonWebKey
from authlib.oauth2.rfc6749.errors import InvalidClientError
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.integrations.flask_helpers import create_oauth_request

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.jwks import (
    list_jwks, newest_jwk, jwks_directory, generate_and_save_private_key)

from .models.oauth2client import client as fetch_client
from .models.oauth2token import OAuth2Token, save_token
from .models.jwtrefreshtoken import (
    JWTRefreshToken,
    link_child_token,
    save_refresh_token,
    load_refresh_token)

from .grants.password_grant import PasswordGrant
from .grants.refresh_token_grant import RefreshTokenGrant
from .grants.authorisation_code_grant import AuthorisationCodeGrant
from .grants.jwt_bearer_grant import JWTBearerGrant, JWTBearerTokenGenerator

from .endpoints.revocation import RevocationEndpoint
from .endpoints.introspection import IntrospectionEndpoint

from .resource_server import require_oauth, JWTBearerTokenValidator


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

def create_save_token_func(token_model: type, app: Flask) -> Callable:
    """Create the function that saves the token."""
    def __save_token__(token, request):
        _jwt = jwt.decode(
            token["access_token"],
            newest_jwk_with_rotation(
                jwks_directory(app),
                int(app.config["JWKS_ROTATION_AGE_DAYS"])))
        _token = token_model(
            token_id=uuid.UUID(_jwt["jti"]),
            client=request.client,
            user=request.user,
            **{
                "refresh_token": None,
                "revoked": False,
                "issued_at": datetime.now(),
                **token
            })
        with db.connection(current_app.config["AUTH_DB"]) as conn:
            save_token(conn, _token)
            old_refresh_token = load_refresh_token(
                conn,
                request.form.get("refresh_token", "nosuchtoken")
            )
            new_refresh_token = JWTRefreshToken(
                    token=_token.refresh_token,
                    client=request.client,
                    user=request.user,
                    issued_with=uuid.UUID(_jwt["jti"]),
                    issued_at=datetime.fromtimestamp(_jwt["iat"]),
                    expires=datetime.fromtimestamp(
                        old_refresh_token.then(
                            lambda _tok: _tok.expires.timestamp()
                        ).maybe((int(_jwt["iat"]) +
                                 RefreshTokenGrant.DEFAULT_EXPIRES_IN),
                                lambda _expires: _expires)),
                    scope=_token.get_scope(),
                    revoked=False,
                    parent_of=None)
            save_refresh_token(conn, new_refresh_token)
            old_refresh_token.then(lambda _tok: link_child_token(
                conn, _tok.token, new_refresh_token.token))

    return __save_token__

def newest_jwk_with_rotation(jwksdir: Path, keyage: int) -> JsonWebKey:
    """
    Retrieve the latests JWK, creating a new one if older than `keyage` days.
    """
    def newer_than_days(jwkey):
        filestat = os.stat(Path(
            jwksdir, f"{jwkey.as_dict()['kid']}.private.pem"))
        oldesttimeallowed = (datetime.now() - timedelta(days=keyage))
        if filestat.st_ctime < (oldesttimeallowed.timestamp()):
            return Left("JWK is too old!")
        return jwkey

    return newest_jwk(jwksdir).then(newer_than_days).either(
        lambda _errmsg: generate_and_save_private_key(jwksdir),
        lambda key: key)


def make_jwt_token_generator(app):
    """Make token generator function."""
    def __generator__(# pylint: disable=[too-many-arguments]
            grant_type,
            client,
            user=None,
            scope=None,
            expires_in=None,# pylint: disable=[unused-argument]
            include_refresh_token=True
    ):
        return JWTBearerTokenGenerator(
            newest_jwk_with_rotation(
                jwks_directory(app),
                int(app.config["JWKS_ROTATION_AGE_DAYS"]))).__call__(
                        grant_type,
                        client,
                        user,
                        scope,
                        JWTBearerTokenGenerator.DEFAULT_EXPIRES_IN,
                        include_refresh_token)
    return __generator__



class JsonAuthorizationServer(AuthorizationServer):
    """An authorisation server using JSON rather than FORMDATA."""

    def create_oauth2_request(self, request):
        """Create an OAuth2 Request from the flask request."""
        res = create_oauth_request(request, OAuth2Request, True)
        return res


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
        save_token=create_save_token_func(OAuth2Token, app))
    app.config["OAUTH2_SERVER"] = server

    ## Set up the token validators
    require_oauth.register_token_validator(
        JWTBearerTokenValidator(KeySet(list_jwks(jwks_directory(app)))))
