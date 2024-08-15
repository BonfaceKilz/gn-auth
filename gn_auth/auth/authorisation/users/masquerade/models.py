"""Functions for handling masquerade."""
import uuid
from functools import wraps
from datetime import datetime
from authlib.jose import jwt

from flask import current_app as app


from gn_auth.auth.errors import ForbiddenAccess

from gn_auth.auth.jwks import newest_jwk_with_rotation, jwks_directory

from ...roles.models import user_roles
from ....db import sqlite3 as db
from ....authentication.users import User
from ....authentication.oauth2.models.oauth2token import (
    OAuth2Token, save_token)

__FIVE_HOURS__ = (60 * 60 * 5)

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
                privileges = [p for p in role.privileges if p.privilege_id == "system:user:masquerade"]
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
    token_details = app.config["OAUTH2_SERVER"].generate_token(
        client=original_token.client,
        grant_type="authorization_code",
        user=masqueradee,
        expires_in=__FIVE_HOURS__,
        include_refresh_token=True)

    _jwt = jwt.decode(
        original_token.access_token,
        newest_jwk_with_rotation(
            jwks_directory(app),
            int(app.config["JWKS_ROTATION_AGE_DAYS"])))
    new_token = OAuth2Token(
        token_id=uuid.UUID(_jwt["jti"]),
        client=original_token.client,
        token_type=token_details["token_type"],
        access_token=token_details["access_token"],
        refresh_token=token_details.get("refresh_token"),
        scope=original_token.scope,
        revoked=False,
        issued_at=datetime.now(),
        expires_in=token_details["expires_in"],
        user=masqueradee)
    save_token(conn, new_token)
    return new_token
