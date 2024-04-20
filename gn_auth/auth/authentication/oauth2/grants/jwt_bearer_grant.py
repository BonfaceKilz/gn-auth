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
from gn_auth.auth.authentication.oauth2.grants.authorisation_code_grant import AuthorisationCodeGrant


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


class JWTBearerGrant(_JWTBearerGrant, AuthorisationCodeGrant):
    """Implement JWT as Authorisation Grant."""


    def create_authorization_response(self, redirect_uri: str, grant_user):
        resp = super().create_authorization_response(redirect_uri, grant_user)
        headers = dict(resp[2])
        location = urlparse(headers["Location"])
        query = {
            key.strip(): value.strip() for key, value in
            (item.split("=") for  item in
             (param.strip() for param in location.query.split("&")))}
        parsed_redirect = urlparse(redirect_uri)
        issued = datetime.now()
        jwtkey = app.config["JWT_PRIVATE_KEY"]
        jwttoken = jwt.encode(
            {"alg": "RS256", "typ": "jwt", "kid": jwtkey.kid},
            {
                "iss": str(self.client.client_id),
                "sub": str(grant_user.user_id),
                "aud": f"{parsed_redirect.scheme}://{parsed_redirect.netloc}",
                "exp": (issued + timedelta(minutes=5)),
                "nbf": int(issued.timestamp()),
                "iat": int(issued.timestamp()),
                "jti": str(uuid.uuid4()),
                "code": query["code"]},
            jwtkey).decode("utf8")
        return (302, "", [("Location", f"{location.geturl()}&jwt={jwttoken}")])


    def resolve_issuer_client(self, issuer):
        """Fetch client via "iss" in assertion claims."""
        return with_db_connection(
            lambda conn: self.server.query_client(issuer))


    def resolve_client_key(self, client, headers, payload):
        """Resolve client key to decode assertion data."""
        return app.config["JWT_PUBLIC_KEY"]


    def authenticate_user(self, subject):
        """Authenticate user with the given assertion claims."""
        return with_db_connection(lambda conn: user_by_id(conn, subject))


    def has_granted_permission(self, client, user):
        """
        Check if the client has permission to access the given user's resource.
        """
        return True # TODO: Check this!!!
