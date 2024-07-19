"""UI for admin stuff"""
import uuid
import json
import random
import string
from pathlib import Path
from typing import Optional
from functools import partial
from dataclasses import asdict
from urllib.parse import urlparse
from datetime import datetime, timezone, timedelta

from authlib.jose import KeySet, JsonWebKey
from email_validator import validate_email, EmailNotValidError
from flask import (
    flash,
    request,
    url_for,
    redirect,
    Blueprint,
    render_template,
    current_app as app)


from gn_auth import session
from gn_auth.auth.errors import NotFoundError

from ....db import sqlite3 as db
from ....db.sqlite3 import with_db_connection

from ....authentication.oauth2.models.oauth2client import (
    save_client,
    OAuth2Client,
    oauth2_clients,
    client as oauth2_client,
    delete_client as _delete_client)
from ....authentication.users import (
    User,
    user_by_id,
    valid_login,
    user_by_email,
    hash_password)

from .ui import is_admin

admin = Blueprint("admin", __name__)

class RegisterClientError(Exception):
    """Error to raise in case of client registration issues"""

_FORM_GRANT_TYPES_ = ({
    "name": "Authorization Code",
    "value": "authorization_code"
}, {
    "name": "Refresh Token",
    "value": "refresh_token"
}, {
    "name": "JWT Bearer Token",
    "value": "urn:ietf:params:oauth:grant-type:jwt-bearer"
})

@admin.before_request
def update_expires():
    """Update session expiration."""
    if (session.session_info() and not session.update_expiry(
            int(app.config.get("SESSION_EXPIRY_MINUTES", 10)))):
        flash("Session has expired. Logging out...", "alert-warning")
        session.clear_session_info()
        return redirect(url_for("oauth2.admin.login"))
    return None

@admin.route("/dashboard", methods=["GET"])
@is_admin
def dashboard():
    """Admin dashboard."""
    return render_template("admin/dashboard.html")

@admin.route("/login", methods=["GET", "POST"])
def login():
    """Log in to GN3 directly without OAuth2 client."""
    if request.method == "GET":
        return render_template(
            "admin/login.html",
            next_uri=request.args.get("next", "oauth2.admin.dashboard"))

    form = request.form
    next_uri = form.get("next_uri", "oauth2.admin.dashboard")
    error_message = "Invalid email or password provided."
    login_page = redirect(url_for("oauth2.admin.login", next=next_uri))
    try:
        email = validate_email(form.get("email", "").strip(),
                               check_deliverability=False)
        password = form.get("password")
        with db.connection(app.config["AUTH_DB"]) as conn:
            user = user_by_email(conn, email["email"])
            if valid_login(conn, user, password):
                session.update_session_info(
                    user=asdict(user),
                    expires=(
                        datetime.now(tz=timezone.utc) + timedelta(minutes=int(
                            app.config.get("SESSION_EXPIRY_MINUTES", 10)))))
                return redirect(url_for(next_uri))
            raise NotFoundError(error_message)
    except NotFoundError as _nfe:
        flash(error_message, "alert-danger")
        return login_page
    except EmailNotValidError as _enve:
        flash(error_message, "alert-danger")
        return login_page

@admin.route("/logout", methods=["GET"])
def logout():
    """Log out the admin."""
    if not session.session_info():
        flash("Not logged in.", "alert-info")
        return redirect(url_for("oauth2.admin.login"))
    session.clear_session_info()
    flash("Logged out", "alert-success")
    return redirect(url_for("oauth2.admin.login"))

def random_string(length: int = 64) -> str:
    """Generate a random string."""
    return "".join(
        random.choice(string.ascii_letters + string.digits + string.punctuation)
        for _idx in range(0, length))

def __response_types__(grant_types: tuple[str, ...]) -> tuple[str, ...]:
    """Compute response types from grant types."""
    resps = {
        "password": ("token",),
        "authorization_code": ("token", "code"),
        "refresh_token": ("token",)
    }
    return tuple(set(
        resp_typ for types_list
        in (types for grant, types in resps.items() if grant in grant_types)
        for resp_typ in types_list))

def check_string(form, inputname: str, errormessage: str) -> Optional[str]:
    """Check that an input expecting a string has an actual value."""
    if not bool(form.get(inputname, "").strip()):
        return errormessage
    return None

def check_list(form, inputname: str, errormessage: str) -> Optional[str]:
    """Check that an input expecting a list has at least one value."""
    _list = [item for item in form.getlist(inputname) if bool(item.strip())]
    if not bool(_list):
        return errormessage
    return None

def uri_valid(value: str) -> bool:
    """Check that the `value` is a valid URI"""
    uri = urlparse(value)
    return (bool(uri.scheme) and bool(uri.netloc))

def check_register_client_form(form):
    """Check that all expected data is provided."""
    errors = (check_list(form,
                         "scope[]",
                         "You need to select at least one scope option."),)

    errors = errors + (check_string(
        form,
        "client_name",
        "You need to provide a name for the client being registered."),)

    errors = errors + (check_string(
        form,
        "redirect_uri",
        "You need to provide the main redirect uri."),)

    if not uri_valid(form.get("redirect_uri", "")):
        errors = errors + ("The provided redirect URI is not a valid URI.",)

    errors = errors + (check_list(
        form,
        "scope[]",
        "You need to select at least one scope option."),)

    errors = tuple(item for item in errors if item is not None)
    if bool(errors):
        raise RegisterClientError(errors)


@admin.route("/register-client", methods=["GET", "POST"])
@is_admin
def register_client():
    """Register an OAuth2 client."""
    def __list_users__(conn):
        with db.cursor(conn) as cursor:
            cursor.execute("SELECT * FROM users")
            return tuple(
                User.from_sqlite3_row(row) for row in cursor.fetchall())
    if request.method == "GET":
        return render_template(
            "admin/register-client.html",
            scope=app.config["OAUTH2_SCOPE"],
            users=with_db_connection(__list_users__),
            granttypes=_FORM_GRANT_TYPES_,
            current_user=session.session_user())

    form = request.form
    raw_client_secret = random_string()
    try:
        check_register_client_form(form)
    except RegisterClientError as _rce:
        for error_message in _rce.args:
            flash(error_message, "alert-danger")
        return redirect(url_for("oauth2.admin.register_client"))

    default_redirect_uri = form["redirect_uri"]
    grant_types = form.getlist("grants[]")
    client = OAuth2Client(
        client_id = uuid.uuid4(),
        client_secret = hash_password(raw_client_secret),
        client_id_issued_at = datetime.now(tz=timezone.utc),
        client_secret_expires_at = datetime.fromtimestamp(0),
        client_metadata = {
            "client_name": form["client_name"],
            "token_endpoint_auth_method": [
                "client_secret_post", "client_secret_basic"],
            "client_type": "confidential",
            "grant_types": grant_types,
            "default_redirect_uri": default_redirect_uri,
            "redirect_uris": [default_redirect_uri] + form.get("other_redirect_uri", "").split(),
            "response_type": __response_types__(tuple(grant_types)),
            "scope": form.getlist("scope[]")
        },
        user = with_db_connection(partial(
            user_by_id, user_id=uuid.UUID(form["user"])))
    )
    client = with_db_connection(partial(save_client, the_client=client))
    return render_template(
        "admin/registered-client.html",
        client=client,
        client_secret = raw_client_secret)


def __parse_client__(sqlite3_row) -> dict:
    """Parse the client details into python datatypes."""
    return {
        **dict(sqlite3_row),
        "client_metadata": json.loads(sqlite3_row["client_metadata"])
    }

@admin.route("/list-client", methods=["GET"])
@is_admin
def list_clients():
    """List all registered OAuth2 clients."""
    return render_template(
        "admin/list-oauth2-clients.html",
        clients=with_db_connection(oauth2_clients))

@admin.route("/view-client/<uuid:client_id>", methods=["GET"])
@is_admin
def view_client(client_id: uuid.UUID):
    """View details of OAuth2 client with given `client_id`."""
    return render_template(
        "admin/view-oauth2-client.html",
        client=with_db_connection(partial(oauth2_client, client_id=client_id)),
        scope=app.config["OAUTH2_SCOPE"],
        granttypes=_FORM_GRANT_TYPES_)

@admin.route("/register-client-public-key", methods=["POST"])
@is_admin
def register_client_public_key():
    """Register a client's SSL key"""
    form = request.form
    admin_dashboard_uri = redirect(url_for("oauth2.admin.dashboard"))
    view_client_uri = redirect(url_for("oauth2.admin.view_client",
                                       client_id=form["client_id"]))
    if not bool(form.get("client_id")):
        flash("No client selected.", "alert-danger")
        return admin_dashboard_uri

    try:
        _client = with_db_connection(partial(
            oauth2_client, client_id=uuid.UUID(form["client_id"])))
        if _client.is_nothing():
            raise ValueError("No such client.")
        _client = _client.value
    except ValueError:
        flash("Invalid client ID provided.", "alert-danger")
        return admin_dashboard_uri
    try:
        _key = JsonWebKey.import_key(form["client_ssl_key"].strip())
    except ValueError:
        flash("Invalid key provided!", "alert-danger")
        return view_client_uri

    keypath = Path(app.config["CLIENTS_SSL_PUBLIC_KEYS_DIR"]).joinpath(
        f"{_key.thumbprint()}.pem")
    if not keypath.exists():
        with open(keypath, mode="w", encoding="utf8") as _kpth:
            _kpth.write(form["client_ssl_key"])

    with_db_connection(partial(save_client, the_client=OAuth2Client(
        client_id=_client.client_id,
        client_secret=_client.client_secret,
        client_id_issued_at=_client.client_id_issued_at,
        client_secret_expires_at=_client.client_secret_expires_at,
        client_metadata={
            **_client.client_metadata,
            "public_keys": list(set(
                _client.client_metadata.get("public_keys", []) +
                [str(keypath)]))},
        user=_client.user)))
    flash("Client key successfully registered.", "alert-success")
    return view_client_uri


@admin.route("/delete-client-public-key", methods=["POST"])
@is_admin
def delete_client_public_key():
    """Delete a client's SSL key"""
    form = request.form
    admin_dashboard_uri = redirect(url_for("oauth2.admin.dashboard"))
    view_client_uri = redirect(url_for("oauth2.admin.view_client",
                                       client_id=form["client_id"]))
    if not bool(form.get("client_id")):
        flash("No client selected.", "alert-danger")
        return admin_dashboard_uri

    try:
        _client = with_db_connection(partial(
            oauth2_client, client_id=uuid.UUID(form["client_id"])))
        if _client.is_nothing():
            raise ValueError("No such client.")
        _client = _client.value
    except ValueError:
        flash("Invalid client ID provided.", "alert-danger")
        return admin_dashboard_uri

    if form.get("ssl_key", None) is None:
        flash("The key must be provided.", "alert-danger")
        return view_client_uri

    try:
        def find_by_kid(keyset: KeySet, kid: str) -> JsonWebKey:
            for key in keyset.keys:
                if key.thumbprint() == kid:
                    return key
            raise ValueError('Invalid JSON Web Key Set')
        _key = find_by_kid(_client.jwks, form.get("ssl_key"))
    except ValueError:
        flash("Could not delete: No such public key.", "alert-danger")
        return view_client_uri

    _keys = (_key for _key in _client.jwks.keys
             if _key.thumbprint() != form["ssl_key"])
    _keysdir = Path(app.config["CLIENTS_SSL_PUBLIC_KEYS_DIR"])
    with_db_connection(partial(save_client, the_client=OAuth2Client(
            client_id=_client.client_id,
            client_secret=_client.client_secret,
            client_id_issued_at=_client.client_id_issued_at,
            client_secret_expires_at=_client.client_secret_expires_at,
            client_metadata={
                **_client.client_metadata,
                "public_keys": list(set(
                    _keysdir.joinpath(f"{_key.thumbprint()}.pem")
                    for _key in _keys))},
            user=_client.user)))
    flash("Key deleted.", "alert-success")
    return view_client_uri


@admin.route("/edit-client", methods=["POST"])
@is_admin
def edit_client():
    """Edit the details of the given client."""
    form = request.form
    try:
        check_register_client_form(form)
    except RegisterClientError as _rce:
        for error_message in _rce.args:
            flash(error_message, "alert-danger")
        return redirect(url_for("oauth2.admin.view_client",
                                client_id=form["client_id"]))

    the_client = with_db_connection(partial(
        oauth2_client, client_id=uuid.UUID(form["client_id"])))
    if the_client.is_nothing():
        flash("No such client.", "alert-danger")
        return redirect(url_for("oauth2.admin.list_clients"))
    the_client = the_client.value
    client_metadata = {
        **the_client.client_metadata,
        "default_redirect_uri": form["redirect_uri"],
        "redirect_uris": list(set(
            [form["redirect_uri"]] +
            form["other_redirect_uris"].split("\r\n"))),
        "grant_types": form.getlist("grants[]"),
        "scope": form.getlist("scope[]")
    }
    with_db_connection(partial(save_client, the_client=OAuth2Client(
        the_client.client_id,
        the_client.client_secret,
        the_client.client_id_issued_at,
        the_client.client_secret_expires_at,
        client_metadata,
        the_client.user)))
    flash("Client updated.", "alert-success")
    return redirect(url_for("oauth2.admin.view_client",
                            client_id=the_client.client_id))

@admin.route("/delete-client", methods=["POST"])
@is_admin
def delete_client():
    """Delete the details of the client."""
    form = request.form
    the_client = with_db_connection(partial(
        oauth2_client, client_id=uuid.UUID(form["client_id"])))
    if the_client.is_nothing():
        flash("No such client.", "alert-danger")
        return redirect(url_for("oauth2.admin.list_clients"))
    the_client = the_client.value
    with_db_connection(partial(_delete_client, client=the_client))
    flash((f"Client '{the_client.client_metadata.client_name}' was deleted "
           "successfully."),
          "alert-success")
    return redirect(url_for("oauth2.admin.list_clients"))
