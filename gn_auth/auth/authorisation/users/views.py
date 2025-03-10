"""User authorisation endpoints."""
import uuid
import sqlite3
import secrets
import traceback
from typing import Any
from functools import partial
from dataclasses import asdict
from urllib.parse import urljoin
from datetime import datetime, timedelta
from email.headerregistry import Address
from email_validator import validate_email, EmailNotValidError
from flask import (
    flash,
    request,
    jsonify,
    url_for,
    redirect,
    Response,
    Blueprint,
    current_app,
    render_template)

from gn_auth.smtp import send_message, build_email_message

from gn_auth.auth.requests import request_json

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.db.sqlite3 import with_db_connection

from gn_auth.auth.authorisation.resources.models import (
    user_resources as _user_resources)
from gn_auth.auth.authorisation.roles.models import (
    assign_default_roles, user_roles as _user_roles)
from gn_auth.auth.authorisation.resources.groups.models import (
    user_group as _user_group)

from gn_auth.auth.errors import (
    NotFoundError,
    UsernameError,
    PasswordError,
    UserRegistrationError)


from gn_auth.auth.authentication.users import valid_login, user_by_email
from gn_auth.auth.authentication.oauth2.resource_server import require_oauth
from gn_auth.auth.authentication.users import User, save_user, set_user_password
from gn_auth.auth.authentication.oauth2.models.oauth2token import (
    token_by_access_token)

from .models import list_users
from .masquerade.views import masq
from .collections.views import collections

users = Blueprint("users", __name__)
users.register_blueprint(masq, url_prefix="/masquerade")
users.register_blueprint(collections, url_prefix="/collections")

@users.route("/", methods=["GET"])
@require_oauth("profile")
def user_details() -> Response:
    """Return user's details."""
    with require_oauth.acquire("profile") as the_token:
        user = the_token.user
        user_dets = {
            "user_id": user.user_id, "email": user.email, "name": user.name,
            "group": False
        }
        with db.connection(current_app.config["AUTH_DB"]) as conn:
            the_group = _user_group(conn, user).maybe(# type: ignore[misc]
                False, lambda grp: grp)# type: ignore[arg-type]
            return jsonify({
                **user_dets,
                "group": asdict(the_group) if the_group else False
            })

@users.route("/roles", methods=["GET"])
@require_oauth("role")
def user_roles() -> Response:
    """Return the non-resource roles assigned to the user."""
    with require_oauth.acquire("role") as token:
        with db.connection(current_app.config["AUTH_DB"]) as conn:
            return jsonify(tuple(
                {**role, "roles": tuple(asdict(rol) for rol in role["roles"])}
                for role in _user_roles(conn, token.user)))

def validate_password(password, confirm_password) -> str:
    """Validate the provided password."""
    if len(password) < 8:
        raise PasswordError("The password must be at least 8 characters long.")

    if password != confirm_password:
        raise PasswordError("Mismatched password values")

    return password

def validate_username(name: str) -> str:
    """Validate the provides name."""
    if name == "":
        raise UsernameError("User's name not provided.")

    return name

def __assert_not_logged_in__(conn: db.DbConnection):
    bearer = request.headers.get('Authorization')
    if bearer:
        token = token_by_access_token(conn, bearer.split(None)[1]).maybe(# type: ignore[misc]
            False, lambda tok: tok)
        if token:
            raise UserRegistrationError(
                "Cannot register user while authenticated")

def user_address(user: User) -> Address:
    """Compute the `email.headerregistry.Address` from a `User`"""
    return Address(display_name=user.name, addr_spec=user.email)

def send_verification_email(
        conn,
        user: User,
        client_id: str,
        response_type: str,
        redirect_uri: str
) -> None:
    """Send an email verification message."""
    subject="GeneNetwork: Please Verify Your Email"
    verification_code = secrets.token_urlsafe(64)
    generated = datetime.now()
    expiration_minutes = 15
    def __render__(template):
        return render_template(template,
                               subject=subject,
                               verification_code=verification_code,
                               verification_uri=urljoin(
                                   request.url,
                                   url_for("oauth2.users.verify_user",
                                           response_type=response_type,
                                           client_id=client_id,
                                           redirect_uri=redirect_uri,
                                           verificationcode=verification_code)),
                               expiration_minutes=expiration_minutes)
    with db.cursor(conn) as cursor:
        cursor.execute(
            ("INSERT INTO "
             "user_verification_codes(user_id, code, generated, expires) "
             "VALUES (:user_id, :code, :generated, :expires)"),
            {
                "user_id": str(user.user_id),
                "code": verification_code,
                "generated": int(generated.timestamp()),
                "expires": int(
                    (generated +
                     timedelta(
                         minutes=expiration_minutes)).timestamp())
            })
        send_message(smtp_user=current_app.config.get("SMTP_USER", ""),
                     smtp_passwd=current_app.config.get("SMTP_PASSWORD", ""),
                     message=build_email_message(
                         from_address=current_app.config["EMAIL_ADDRESS"],
                         to_addresses=(user_address(user),),
                         subject=subject,
                         txtmessage=__render__("emails/verify-email.txt"),
                         htmlmessage=__render__("emails/verify-email.html")),
                     host=current_app.config["SMTP_HOST"],
                     port=current_app.config["SMTP_PORT"])

@users.route("/register", methods=["POST"])
def register_user() -> Response:
    """Register a user."""
    with db.connection(current_app.config["AUTH_DB"]) as conn:
        __assert_not_logged_in__(conn)

        try:
            form = request_json()
            email = validate_email(form.get("email", "").strip(),
                                   check_deliverability=True)
            password = validate_password(
                form.get("password", "").strip(),
                form.get("confirm_password", "").strip())
            user_name = validate_username(form.get("user_name", "").strip())
            with db.cursor(conn) as cursor:
                user, _hashed_password = set_user_password(
                    cursor, save_user(
                        cursor, email["email"], user_name), password)
                assign_default_roles(cursor, user)
                send_verification_email(conn,
                                        user,
                                        client_id=form["client_id"],
                                        response_type=form["response_type"],
                                        redirect_uri=form["redirect_uri"])
                return jsonify(asdict(user))
        except sqlite3.IntegrityError as sq3ie:
            current_app.logger.error(traceback.format_exc())
            raise UserRegistrationError(
                "A user with that email already exists") from sq3ie
        except EmailNotValidError as enve:
            current_app.logger.error(traceback.format_exc())
            raise(UserRegistrationError(f"Email Error: {str(enve)}")) from enve

    raise Exception(# pylint: disable=[broad-exception-raised]
        "unknown_error", "The system experienced an unexpected error.")

def delete_verification_code(cursor, code: str):
    """Delete verification code from db."""
    cursor.execute("DELETE FROM user_verification_codes "
                   "WHERE code=:code",
                   {"code": code})

@users.route("/verify", methods=["GET", "POST"])
def verify_user():
    """Verify users are not bots."""
    form = request_json()
    loginuri = redirect(url_for(
        "oauth2.auth.authorise",
        response_type=(request.args.get("response_type")
                       or form["response_type"]),
        client_id=(request.args.get("client_id") or form["client_id"]),
        redirect_uri=(request.args.get("redirect_uri")
                      or form["redirect_uri"])))
    verificationcode = (request.args.get("verificationcode")
                        or form["verificationcode"])
    with (db.connection(current_app.config["AUTH_DB"]) as conn,
          db.cursor(conn) as cursor):
        cursor.execute("SELECT * FROM user_verification_codes "
                       "WHERE code=:code",
                       {"code": verificationcode})
        results = tuple(dict(row) for row in cursor.fetchall())

        if not bool(results):
            flash("Invalid verification code: code not found.",
                  "alert-danger")
            return loginuri

        if len(results) > 1:
            delete_verification_code(cursor, verificationcode)
            flash("Invalid verification code: code is duplicated.",
                  "alert-danger")
            return loginuri

        results = results[0]
        if (datetime.fromtimestamp(
                int(results["expires"])) < datetime.now()):
            delete_verification_code(cursor, verificationcode)
            flash("Invalid verification code: code has expired.",
                  "alert-danger")
            return loginuri

        # Code is good!
        delete_verification_code(cursor, verificationcode)
        cursor.execute("UPDATE users SET verified=1 WHERE user_id=:user_id",
                       {"user_id": results["user_id"]})
        flash("E-mail verified successfully! Please login to continue.",
              "alert-success")
        return loginuri


@users.route("/group", methods=["GET"])
@require_oauth("profile group")
def user_group() -> Response:
    """Retrieve the group in which the user is a member."""
    with require_oauth.acquire("profile group") as the_token:
        db_uri = current_app.config["AUTH_DB"]
        with db.connection(db_uri) as conn:
            group = _user_group(conn, the_token.user).maybe(# type: ignore[misc]
                False, lambda grp: grp)# type: ignore[arg-type]

        if group:
            return jsonify(asdict(group))
        raise NotFoundError("User is not a member of any group.")

@users.route("/resources", methods=["GET"])
@require_oauth("profile resource")
def user_resources() -> Response:
    """Retrieve the resources a user has access to."""
    with require_oauth.acquire("profile resource") as the_token:
        db_uri = current_app.config["AUTH_DB"]
        with db.connection(db_uri) as conn:
            return jsonify([
                asdict(resource) for resource in
                _user_resources(conn, the_token.user)])

@users.route("group/join-request", methods=["GET"])
@require_oauth("profile group")
def user_join_request_exists():
    """Check whether a user has an active group join request."""
    def __request_exists__(conn: db.DbConnection, user: User) -> dict[str, Any]:
        with db.cursor(conn) as cursor:
            cursor.execute(
                "SELECT * FROM group_join_requests WHERE requester_id=? AND "
                "status = 'PENDING'",
                (str(user.user_id),))
            res = cursor.fetchone()
            if res:
                return {
                    "request_id": res["request_id"],
                    "exists": True
                }
        return{
            "status": "Not found",
            "exists": False
        }
    with require_oauth.acquire("profile group") as the_token:
        return jsonify(with_db_connection(partial(
            __request_exists__, user=the_token.user)))

@users.route("/list", methods=["GET"])
@require_oauth("profile user")
def list_all_users() -> Response:
    """List all the users."""
    with require_oauth.acquire("profile group") as _the_token:
        return jsonify(tuple(
            asdict(user) for user in with_db_connection(list_users)))

@users.route("/handle-unverified", methods=["POST"])
def handle_unverified():
    """Handle case where user tries to login but is unverified"""
    email = request.args["email"]
    # TODO: Maybe have a GN2_URI setting here?
    #       or pass the client_id here?
    with (db.connection(current_app.config["AUTH_DB"]) as conn,
          db.cursor(conn) as cursor):
        cursor.execute(
            "DELETE FROM user_verification_codes WHERE expires <= ?",
            (int(datetime.now().timestamp()),))
        cursor.execute(
            "SELECT u.user_id, u.email, uvc.* FROM users AS u "
            "INNER JOIN user_verification_codes AS uvc "
            "ON u.user_id=uvc.user_id "
            "WHERE u.email=?",
            (email,))
        token_found = bool(cursor.fetchone())

    return render_template(
        "users/unverified-user.html",
        email=email,
        response_type=request.args["response_type"],
        client_id=request.args["client_id"],
        redirect_uri=request.args["redirect_uri"],
        token_found=token_found)

@users.route("/send-verification", methods=["POST"])
def send_verification_code():
    """Send verification code email."""
    form = request_json()
    with (db.connection(current_app.config["AUTH_DB"]) as conn,
          db.cursor(conn) as cursor):
        user = user_by_email(conn, form["user_email"])
        if valid_login(conn, user, form.get("user_password", "")):
            cursor.execute(
                "DELETE FROM user_verification_codes WHERE user_id=:user_id",
                {"user_id": str(user.user_id)})
            send_verification_email(conn,
                                    user,
                                    client_id=form["client_id"],
                                    response_type=form["response_type"],
                                    redirect_uri=form["redirect_uri"])
            flash(("Sent a verification code to your email. "
                   "Please login to continue."),
                  "alert-success")
            return redirect(url_for("oauth2.auth.authorise",
                                    response_type=form["response_type"],
                                    client_id=form["client_id"],
                                    redirect_uri=form["redirect_uri"]))

    resp = jsonify({
        "error": "InvalidLogin",
        "error-description": "Invalid email or password."
    })
    resp.code = 400
    return resp


def send_forgot_password_email(
        conn,
        user: User,
        client_id: uuid.UUID,
        redirect_uri: str,
        response_type: str
):
    """Send the 'forgot-password' email."""
    subject="GeneNetwork: Change Your Password"
    token = secrets.token_urlsafe(64)
    generated = datetime.now()
    expiration_minutes = 15
    def __render__(template):
        return render_template(template,
                               subject=subject,
                               forgot_password_uri=urljoin(
                                   request.url,
                                   url_for("oauth2.users.change_password",
                                           forgot_password_token=token,
                                           client_id=client_id,
                                           redirect_uri=redirect_uri,
                                           response_type=response_type)),
                               expiration_minutes=expiration_minutes)

    with db.cursor(conn) as cursor:
        cursor.execute(
            ("INSERT OR REPLACE INTO "
             "forgot_password_tokens(user_id, token, generated, expires) "
             "VALUES (:user_id, :token, :generated, :expires)"),
            {
                "user_id": str(user.user_id),
                "token": token,
                "generated": int(generated.timestamp()),
                "expires": int(
                    (generated +
                     timedelta(
                         minutes=expiration_minutes)).timestamp())
            })

    send_message(smtp_user=current_app.config["SMTP_USER"],
                 smtp_passwd=current_app.config["SMTP_PASSWORD"],
                 message=build_email_message(
                     from_address=current_app.config["EMAIL_ADDRESS"],
                     to_addresses=(user_address(user),),
                     subject=subject,
                     txtmessage=__render__("emails/forgot-password.txt"),
                     htmlmessage=__render__("emails/forgot-password.html")),
                 host=current_app.config["SMTP_HOST"],
                 port=current_app.config["SMTP_PORT"])


@users.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Enable user to request password change."""
    if request.method == "GET":
        return render_template("users/forgot-password.html",
                               client_id=request.args["client_id"],
                               redirect_uri=request.args["redirect_uri"],
                               response_type=request.args["response_type"])

    form = request.form
    email = form.get("email", "").strip()
    if not bool(email):
        flash("You MUST provide an email.", "alert-danger")
        return redirect(url_for("oauth2.users.forgot_password"))

    with db.connection(current_app.config["AUTH_DB"]) as conn:
        user = user_by_email(conn, form["email"])
        if not bool(user):
            flash("We could not find an account with that email.",
                  "alert-danger")
            return redirect(url_for("oauth2.users.forgot_password"))

        send_forgot_password_email(conn,
                                   user,
                                   request.args["client_id"],
                                   request.args["redirect_uri"],
                                   request.args["response_type"])
        return render_template("users/forgot-password-token-send-success.html",
                               email=form["email"])


@users.route("/change-password/<forgot_password_token>", methods=["GET", "POST"])
def change_password(forgot_password_token):
    """Enable user to perform password change."""
    login_page = redirect(url_for("oauth2.auth.authorise",
                                  client_id=request.args["client_id"],
                                  redirect_uri=request.args["redirect_uri"],
                                  response_type=request.args["response_type"]))
    with (db.connection(current_app.config["AUTH_DB"]) as conn,
          db.cursor(conn) as cursor):
        cursor.execute("DELETE FROM forgot_password_tokens WHERE expires<=?",
                       (int(datetime.now().timestamp()),))
        cursor.execute(
            "SELECT fpt.*, u.email FROM forgot_password_tokens AS fpt "
            "INNER JOIN users AS u ON fpt.user_id=u.user_id WHERE token=?",
            (forgot_password_token,))
        token = cursor.fetchone()
        if request.method == "GET":
            if bool(token):
                return render_template(
                    "users/change-password.html",
                    email=token["email"],
                    client_id=request.args["client_id"],
                    redirect_uri=request.args["redirect_uri"],
                    response_type=request.args["response_type"],
                    forgot_password_token=forgot_password_token)
            flash("Invalid Token: We cannot change your password!",
                  "alert-danger")
            return login_page

        password = request.form["password"]
        confirm_password = request.form["confirm-password"]
        change_password_page = redirect(url_for(
            "oauth2.users.change_password",
            client_id=request.args["client_id"],
            redirect_uri=request.args["redirect_uri"],
            response_type=request.args["response_type"],
            forgot_password_token=forgot_password_token))
        if bool(password) and bool(confirm_password):
            if password == confirm_password:
                _user, _hashed_password = set_user_password(
                    cursor, user_by_email(conn, token["email"]), password)
                cursor.execute(
                    "DELETE FROM forgot_password_tokens WHERE token=?",
                    (forgot_password_token,))
                flash("Password changed successfully!", "alert-success")
                return login_page

            flash("Passwords do not match!", "alert-danger")
            return change_password_page

        flash("Both the password and its confirmation MUST be provided!",
              "alert-danger")
        return change_password_page
