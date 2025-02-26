"""Functions for handling masquerade."""
from functools import wraps
from datetime import datetime
from authlib.jose import jwt

from flask import current_app as app


from gn_auth.auth.errors import ForbiddenAccess

from gn_auth.auth.jwks import newest_jwk_with_rotation, jwks_directory
from gn_auth.auth.authentication.oauth2.grants.refresh_token_grant import (
    RefreshTokenGrant)
from gn_auth.auth.authentication.oauth2.models.jwtrefreshtoken import (
    JWTRefreshToken,
    save_refresh_token)

from ...roles.models import user_roles
from ....db import sqlite3 as db
from ....authentication.users import User
from ....authentication.oauth2.models.oauth2token import OAuth2Token

__FIVE_HOURS__ = 60 * 60 * 5

def can_masquerade(func):
    """Security decorator."""
    @wraps(func)
    def __checker__(*args, **kwargs):
        if len(args) == 3:
            conn, token, _masq_user = args
        elif len(args) == 2:
            conn, token = args
        elif len(args) == 1:
            conn = args[0]
            token = kwargs["original_token"]
        else:
            conn = kwargs["conn"]
            token = kwargs["original_token"]

        masq_privs = []
        for roles in user_roles(conn, token.user):
            for role in roles["roles"]:
                privileges = [p for p in role.privileges
                              if p.privilege_id == "system:user:masquerade"]
                masq_privs.extend(privileges)

        if len(masq_privs) == 0:
            raise ForbiddenAccess(
                "You do not have the ability to masquerade as another user.")
        return func(*args, **kwargs)
    return __checker__

@can_masquerade
def masquerade_as(
        conn: db.DbConnection,
        original_token: OAuth2Token,
        masqueradee: User) -> OAuth2Token:
    """Get a token that enables `masquerader` to act as `masqueradee`."""
    scope = original_token.get_scope().replace(
        # Do not allow more than one level of masquerading
        "masquerade", "").strip()
    new_token = app.config["OAUTH2_SERVER"].generate_token(
        client=original_token.client,
        grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer",
        user=masqueradee,
        expires_in=original_token.get_expires_in(),
        include_refresh_token=True,
        scope=scope)
    _jwt = jwt.decode(
        new_token["access_token"],
        newest_jwk_with_rotation(
            jwks_directory(app),
            int(app.config["JWKS_ROTATION_AGE_DAYS"])))
    save_refresh_token(conn, JWTRefreshToken(
        token=new_token["refresh_token"],
        client=original_token.client,
        user=masqueradee,
        issued_with=_jwt["jti"],
        issued_at=datetime.fromtimestamp(_jwt["iat"]),
        expires=datetime.fromtimestamp(
            int(_jwt["iat"]) + RefreshTokenGrant.DEFAULT_EXPIRES_IN),
        scope=scope,
        revoked=False,
        parent_of=None))
    return new_token
