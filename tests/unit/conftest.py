"""Fixtures for unit tests."""
import os
from pathlib import Path
from datetime import datetime
from tempfile import TemporaryDirectory

import pytest

from gn_auth import create_app

def setup_secrets(rootdir: Path) -> Path:
    """Setup secrets directory and file."""
    secretsfile = Path(rootdir).joinpath("secrets/secrets.py")
    secretsfile.parent.mkdir(exist_ok=True)
    with open(secretsfile, "w", encoding="utf8") as outfile:
        outfile.write(
            'SECRET_KEY="qQIrgiK29kXZU6v8D09y4uw_sk8I4cqgNZniYUrRoUk"')

    return secretsfile


@pytest.fixture(scope="session")
def fxtr_app():
    """Fixture: setup the test app"""
    # Do some setup
    testsroot = os.path.dirname(__file__)

    with TemporaryDirectory() as testdir:
        testdb = Path(testdir).joinpath(
            f'testdb_{datetime.now().strftime("%Y%m%dT%H%M%S")}')
        testuploadsdir = Path(testdir).joinpath("uploads")
        testuploadsdir.mkdir()
        app = create_app({
            "TESTING": True,
            "AUTH_DB": testdb,
            "GN_AUTH_SECRETS": str(setup_secrets(testdir)),
            "OAUTH2_ACCESS_TOKEN_GENERATOR": "tests.unit.auth.test_token.gen_token",
            "UPLOADS_DIR": testuploadsdir,
            "SSL_PRIVATE_KEY": f"{testsroot}/test-ssl-private-key.pem",
            "CLIENTS_SSL_PUBLIC_KEYS_DIR": f"{testsroot}/test-public-keys-dir"
        })
        app.testing = True
        yield app
        # Clean up after ourselves
        testdb.unlink(missing_ok=True)

@pytest.fixture(scope="session")
def client(fxtr_app): # pylint: disable=redefined-outer-name
    """Create a test client fixture for tests"""
    with fxtr_app.app_context():
        yield fxtr_app.test_client()

@pytest.fixture(scope="session")
def fxtr_app_config(client): # pylint: disable=redefined-outer-name
    """Return the test application's configuration object"""
    return client.application.config
