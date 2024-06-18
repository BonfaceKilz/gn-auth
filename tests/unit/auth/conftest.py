"""Module for fixtures and test utilities"""
import uuid
import datetime
from contextlib import contextmanager

from gn_auth.auth.authentication.oauth2.models.oauth2token import OAuth2Token
from gn_auth.auth.authentication.oauth2.grants.jwt_bearer_grant import JWTBearerTokenGenerator

from .fixtures import * # pylint: disable=[wildcard-import,unused-wildcard-import]

SECRET_KEY = "this is the test secret key"
SCOPE = "profile group role resource register-client"

def _tokengenerator(user, client):
    """Generate a JWT token for tests"""
    _generator = JWTBearerTokenGenerator(
        secret_key=SECRET_KEY,
        alg="HS256")
    return _generator(
        grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer",
        client=client,
        user=user,
        scope=SCOPE,
        expires_in=3600,
        include_refresh_token=False)

def get_tokeniser(user, client):
    """Get contextmanager for mocking token acquisition."""
    @contextmanager
    def __token__(*args, **kwargs):# pylint: disable=[unused-argument]
        yield {
            usr.user_id: OAuth2Token(
                token_id=uuid.UUID("d32611e3-07fc-4564-b56c-786c6db6de2b"),
                client=client,
                token_type="Bearer",
                access_token=_tokengenerator(user, client),
                refresh_token=None,
                revoked=False,
                expires_in=864000,
                user=usr,
                issued_at=int(datetime.datetime.now().timestamp()),
                scope="profile group role resource register-client")
        for usr in TEST_USERS
        }[user.user_id]

    return __token__

def uuid_fn():
    """Return a specific UUID for testing."""
    return uuid.UUID("d32611e3-07fc-4564-b56c-786c6db6de2b")
