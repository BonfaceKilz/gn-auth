"""RefreshTokenGrant: Useful for refreshing the tokens."""
from pymonad.maybe import Nothing
from flask import current_app as app
from authlib.oauth2.rfc6749 import grants

from gn_auth.auth.errors import NotFoundError
from gn_auth.auth.db.sqlite3 import connection
from gn_auth.auth.authentication.users import user_by_id
from gn_auth.auth.authentication.oauth2.models.jwtrefreshtoken import (
    load_refresh_token,
    revoke_refresh_token,
    is_refresh_token_valid)


class RefreshTokenGrant(grants.RefreshTokenGrant):
    """Useful for refreshing tokens"""
    INCLUDE_NEW_REFRESH_TOKEN = True
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']
    DEFAULT_EXPIRES_IN = 432000 # 5 days

    def authenticate_refresh_token(self, refresh_token):
        """
        Check that the refresh token is good.

        Maybe also check that token has not been used before: if it has, revoke
        any new tokens and refresh tokens issued from that.
        """
        with connection(app.config["AUTH_DB"]) as conn:
            return load_refresh_token(
                conn, refresh_token
            ).then(
                lambda _tok: (
                    _tok if is_refresh_token_valid(_tok, self.request.client)
                    else Nothing)
            ).maybe(None, lambda _tok: _tok)

    def authenticate_user(self, credential):
        """Check that user is valid for given token."""
        with connection(app.config["AUTH_DB"]) as conn:
            try:
                return user_by_id(conn, credential.user.user_id)
            except NotFoundError as _nfe:
                return None

        return None

    def revoke_old_credential(self, credential):
        """Revoke any old refresh token after issuing new refresh token."""
        with connection(app.config["AUTH_DB"]) as conn:
            if credential.parent_of is not None:
                revoke_refresh_token(conn, credential)
