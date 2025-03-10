"""Application initialisation module."""
import os
import sys
import logging
from pathlib import Path
from typing import Optional, Callable

from flask import Flask
from flask_cors import CORS
from authlib.jose import JsonWebKey

from gn_auth import hooks
from gn_auth.misc_views import misc
from gn_auth.auth.views import oauth2

from gn_auth.auth.authentication.oauth2.server import setup_oauth2_server

from . import settings
from .errors import register_error_handlers

class ConfigurationError(Exception):
    """Raised in case of a configuration error."""

def check_mandatory_settings(app: Flask) -> None:
    """Verify that mandatory settings are defined in the application"""
    undefined = tuple(
        setting for setting in (
            "SECRET_KEY", "SQL_URI", "AUTH_DB", "AUTH_MIGRATIONS",
            "OAUTH2_SCOPES_SUPPORTED")
        if not ((setting in app.config) and bool(app.config[setting])))
    if len(undefined) > 0:
        raise ConfigurationError(
            "You must provide (valid) values for the following settings: " +
            "\n\t* " + "\n\t* ".join(undefined))

def override_settings_with_envvars(
        app: Flask, ignore: tuple[str, ...]=tuple()) -> None:
    """Override settings in `app` with those in ENVVARS"""
    for setting in (key for key in app.config if key not in ignore):
        app.config[setting] = os.environ.get(setting) or app.config[setting]


def load_secrets_conf(app: Flask) -> None:
    """Load the secrets file."""
    secretsfile = app.config.get("GN_AUTH_SECRETS")
    if ((not secretsfile is None) and (bool(secretsfile.strip()))):
        secretsfile = Path(secretsfile.strip()).absolute()
        app.config["GN_AUTH_SECRETS"] = secretsfile
        if not secretsfile.exists():
            raise ConfigurationError(
                f"The file '{secretsfile}' does not exist. "
                "You must provide a path to an existing secrets file.")
        app.config.from_pyfile(secretsfile)


def dev_loggers(appl: Flask) -> None:
    """Setup the logging handlers."""
    stderr_handler = logging.StreamHandler(stream=sys.stderr)
    appl.logger.addHandler(stderr_handler)

    root_logger = logging.getLogger()
    root_logger.addHandler(stderr_handler)
    root_logger.setLevel(appl.config["LOGLEVEL"])


def gunicorn_loggers(appl: Flask) -> None:
    """Use gunicorn logging handlers for the application."""
    logger = logging.getLogger("gunicorn.error")
    appl.logger.handlers = logger.handlers
    appl.logger.setLevel(logger.level)


def setup_logging(appl: Flask) -> None:
    """
    Setup the loggers according to the WSGI server used to run the application.
    """
    # https://datatracker.ietf.org/doc/html/draft-coar-cgi-v11-03#section-4.1.17
    # https://wsgi.readthedocs.io/en/latest/proposals-2.0.html#making-some-keys-required
    # https://peps.python.org/pep-3333/#id4
    software, *_version_and_comments = os.environ.get(
        "SERVER_SOFTWARE", "").split('/')
    if bool(software):
        gunicorn_loggers(appl)
    dev_loggers(appl)


def create_app(config: Optional[dict] = None) -> Flask:
    """Create and return a new flask application."""
    app = Flask(__name__)

    # ====== Setup configuration ======
    app.config.from_object(settings) # Default settings
    # Override defaults with startup settings
    app.config.update(config or {})
    # Override app settings with site-local settings
    if "GN_AUTH_CONF" in os.environ:
        app.config.from_envvar("GN_AUTH_CONF")

    override_settings_with_envvars(app)

    load_secrets_conf(app)
    # ====== END: Setup configuration ======

    setup_logging(app)
    check_mandatory_settings(app)

    setup_oauth2_server(app)

    CORS(
        app,
        origins=app.config["CORS_ORIGINS"],
        allow_headers=app.config["CORS_HEADERS"],
        supports_credentials=True, intercept_exceptions=False)

    ## Blueprints
    app.register_blueprint(misc, url_prefix="/")
    app.register_blueprint(oauth2, url_prefix="/auth")

    register_error_handlers(app)
    hooks.register_hooks(app)

    return app
