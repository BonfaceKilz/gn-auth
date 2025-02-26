"""The views/routes for the resources package"""
from uuid import UUID, uuid4
import json
import operator
import sqlite3
import time

from dataclasses import asdict
from functools import reduce

from werkzeug.exceptions import BadRequest
from authlib.jose import jwt
from authlib.integrations.flask_oauth2.errors import _HTTPException
from flask import (make_response, request, jsonify, Response,
                   Blueprint, current_app as app)

from gn_auth.auth.requests import request_json

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.db.sqlite3 import with_db_connection
from gn_auth.auth.jwks import newest_jwk, jwks_directory

from gn_auth.auth.authorisation.roles import Role
from gn_auth.auth.authorisation.roles.models import (
    create_role,
    user_resource_roles as _user_resource_roles)
from gn_auth.auth.errors import (
    InvalidData,
    InconsistencyError,
    AuthorisationError)
from gn_auth.auth.authorisation.privileges import (
    privilege_by_id,
    privileges_by_ids)
from gn_auth.auth.authorisation.roles.models import (
    role_by_id,
    db_rows_to_roles,
    delete_privilege_from_resource_role)

from gn_auth.auth.authentication.oauth2.resource_server import require_oauth
from gn_auth.auth.authentication.users import User, user_by_id, user_by_email

from .checks import authorised_for
from .inbredset.views import popbp
from .genotypes.views import genobp
from .phenotypes.views import phenobp
from .errors import MissingGroupError
from .groups.models import Group, user_group
from .models import (
    Resource, resource_data, resource_by_id, public_resources,
    resource_categories, assign_resource_user, link_data_to_resource,
    unassign_resource_user, resource_category_by_id, user_roles_on_resources,
    unlink_data_from_resource, create_resource as _create_resource,
    get_resource_id)

resources = Blueprint("resources", __name__)
resources.register_blueprint(popbp, url_prefix="/")
resources.register_blueprint(genobp, url_prefix="/")
resources.register_blueprint(phenobp, url_prefix="/")

@resources.route("/categories", methods=["GET"])
@require_oauth("profile group resource")
def list_resource_categories() -> Response:
    """Retrieve all resource categories"""
    db_uri = app.config["AUTH_DB"]
    with db.connection(db_uri) as conn:
        return jsonify(tuple(
            asdict(category) for category in resource_categories(conn)))

@resources.route("/create", methods=["POST"])
@require_oauth("profile group resource")
def create_resource() -> Response:
    """Create a new resource"""
    with require_oauth.acquire("profile group resource") as the_token:
        form = request_json()
        resource_name = form.get("resource_name")
        resource_category_id = UUID(form.get("resource_category"))
        db_uri = app.config["AUTH_DB"]
        with (db.connection(db_uri) as conn,
              db.cursor(conn) as cursor):
            try:
                group = user_group(conn, the_token.user).maybe(
                    False, lambda grp: grp)# type: ignore[misc, arg-type]
                if not group:
                    raise MissingGroupError(# Not all resources require an owner group
                        "User with no group cannot create a resource.")
                resource = _create_resource(
                    cursor,
                    resource_name,
                    resource_category_by_id(conn, resource_category_id),
                    the_token.user,
                    group,
                    (form.get("public") == "on"))
                return jsonify(asdict(resource))
            except sqlite3.IntegrityError as sql3ie:
                if sql3ie.args[0] == ("UNIQUE constraint failed: "
                                      "resources.resource_name"):
                    raise InconsistencyError(
                        "You cannot have duplicate resource names.") from sql3ie
                app.logger.debug(
                    f"{type(sql3ie)=}: {sql3ie=}")
                raise

@resources.route("/view/<uuid:resource_id>")
@require_oauth("profile group resource")
def view_resource(resource_id: UUID) -> Response:
    """View a particular resource's details."""
    with require_oauth.acquire("profile group resource") as the_token:
        db_uri = app.config["AUTH_DB"]
        with db.connection(db_uri) as conn:
            return jsonify(
                asdict(
                    resource_by_id(conn, the_token.user, resource_id)
                )
            )

def __safe_get_requests_page__(key: str = "page") -> int:
    """Get the results page if it exists or default to the first page."""
    try:
        return abs(int(request.args.get(key, "1"), base=10))
    except ValueError as _valerr:
        return 1

def __safe_get_requests_count__(key: str = "count_per_page") -> int:
    """Get the results page if it exists or default to the first page."""
    try:
        count = request.args.get(key, "0")
        if count != 0:
            return abs(int(count, base=10))
        return 0
    except ValueError as _valerr:
        return 0

@resources.route("/view/<uuid:resource_id>/data")
@require_oauth("profile group resource")
def view_resource_data(resource_id: UUID) -> Response:
    """Retrieve a particular resource's data."""
    with require_oauth.acquire("profile group resource") as the_token:
        db_uri = app.config["AUTH_DB"]
        count_per_page = __safe_get_requests_count__("count_per_page")
        offset = __safe_get_requests_page__("page") - 1
        with db.connection(db_uri) as conn:
            resource = resource_by_id(conn, the_token.user, resource_id)
            return jsonify(resource_data(
                conn,
                resource,
                ((offset * count_per_page) if bool(count_per_page) else offset),
                count_per_page))

@resources.route("/data/link", methods=["POST"])
@require_oauth("profile group resource")
def link_data():
    """Link group data to a specific resource."""
    try:
        form = request_json()
        assert "resource_id" in form, "Resource ID not provided."
        assert "data_link_id" in form, "Data Link ID not provided."
        assert "dataset_type" in form, "Dataset type not specified"
        assert form["dataset_type"].lower() in (
            "mrna", "genotype", "phenotype"), "Invalid dataset type provided."

        with require_oauth.acquire("profile group resource") as the_token:
            def __link__(conn: db.DbConnection):
                return link_data_to_resource(
                    conn, the_token.user, UUID(form["resource_id"]),
                    form["dataset_type"], UUID(form["data_link_id"]))

            return jsonify(with_db_connection(__link__))
    except AssertionError as aserr:
        raise InvalidData(aserr.args[0]) from aserr



@resources.route("/data/unlink", methods=["POST"])
@require_oauth("profile group resource")
def unlink_data():
    """Unlink data bound to a specific resource."""
    try:
        form = request_json()
        assert "resource_id" in form, "Resource ID not provided."
        assert "data_link_id" in form, "Data Link ID not provided."

        with require_oauth.acquire("profile group resource") as the_token:
            def __unlink__(conn: db.DbConnection):
                return unlink_data_from_resource(
                    conn, the_token.user, UUID(form["resource_id"]),
                    UUID(form["data_link_id"]))
            return jsonify(with_db_connection(__unlink__))
    except AssertionError as aserr:
        raise InvalidData(aserr.args[0]) from aserr

@resources.route("<uuid:resource_id>/user/list", methods=["GET"])
@require_oauth("profile group resource")
def resource_users(resource_id: UUID):
    """Retrieve all users with access to the given resource."""
    with require_oauth.acquire("profile group resource") as the_token:
        def __the_users__(conn: db.DbConnection):
            ########## BEGIN: HACK ##########
            # This hack gets the UI to work, but needs replacing.
            # It resolves (albeit, temporarily) the bug introduced after a
            # refactor that made the system itself, and the groups into
            # resources.
            grouplevelauth = authorised_for(
                conn,
                the_token.user,
                ("group:resource:view-resource",),
                (resource_id,))
            systemlevelauth = authorised_for(
                conn,
                the_token.user,
                ("system:user:list",),
                (resource_id,))
            authorised = {
                key: (grouplevelauth.get(key, False)
                      or systemlevelauth.get(key, False))
                for key in grouplevelauth.keys() | systemlevelauth.keys()
            }
            ########## END: HACK ##########
            if authorised.get(resource_id, False):
                with db.cursor(conn) as cursor:
                    def __organise_users_n_roles__(users_n_roles, row):
                        user_id = UUID(row["user_id"])
                        user = users_n_roles.get(user_id, {}).get(
                            "user", User.from_sqlite3_row(row))
                        role = Role(
                            UUID(row["role_id"]), row["role_name"],
                            bool(int(row["user_editable"])), tuple())
                        return {
                            **users_n_roles,
                            user_id: {
                                "user": user,
                                "user_group": Group(
                                    UUID(row["group_id"]), row["group_name"],
                                    json.loads(row["group_metadata"])),
                                "roles": users_n_roles.get(
                                    user_id, {}).get("roles", tuple()) + (role,)
                            }
                        }
                    cursor.execute(
                        "SELECT g.*, u.*, r.* "
                        "FROM groups AS g INNER JOIN group_users AS gu "
                        "ON g.group_id=gu.group_id INNER JOIN users AS u "
                        "ON gu.user_id=u.user_id INNER JOIN user_roles AS ur "
                        "ON u.user_id=ur.user_id INNER JOIN roles AS r "
                        "ON ur.role_id=r.role_id "
                        "WHERE ur.resource_id=?",
                        (str(resource_id),))
                    return reduce(__organise_users_n_roles__, cursor.fetchall(), {})
            raise AuthorisationError(
                "You do not have sufficient privileges to view the resource "
                "users.")
        results = (
            {
                "user": asdict(row["user"]),
                "user_group": asdict(row["user_group"]),
                "roles": tuple(asdict(role) for role in row["roles"])
            } for row in (
                user_row for user_id, user_row
                in with_db_connection(__the_users__).items()))
        return jsonify(tuple(results))

@resources.route("<uuid:resource_id>/user/assign", methods=["POST"])
@require_oauth("profile group resource role")
def assign_role_to_user(resource_id: UUID) -> Response:
    """Assign a role on the specified resource to a user."""
    with require_oauth.acquire("profile group resource role") as _token:
        try:
            form = request_json()
            role_id = form.get("role_id", "")
            user_email = form.get("user_email", "")
            assert bool(role_id), "The role must be provided."
            assert bool(user_email), "The user email must be provided."

            def __assign__(conn: db.DbConnection) -> dict:
                authorised_for(
                    conn,
                    _token.user,
                    ("resource:role:assign-role",),
                    (resource_id,))
                resource = resource_by_id(conn, _token.user, resource_id)
                user = user_by_email(conn, user_email)
                return assign_resource_user(
                    conn, resource, user,
                    role_by_id(conn, UUID(role_id)))# type: ignore[arg-type]
        except AssertionError as aserr:
            raise AuthorisationError(aserr.args[0]) from aserr

        return jsonify(with_db_connection(__assign__))

@resources.route("<uuid:resource_id>/user/unassign", methods=["POST"])
@require_oauth("profile group resource role")
def unassign_role_to_user(resource_id: UUID) -> Response:
    """Unassign a role on the specified resource from a user."""
    with require_oauth.acquire("profile group resource role") as _token:
        try:
            form = request_json()
            role_id = form.get("role_id", "")
            user_id = form.get("user_id", "")
            assert bool(role_id), "The role must be provided."
            assert bool(user_id), "The user id must be provided."

            def __assign__(conn: db.DbConnection) -> dict:
                authorised_for(
                    conn,
                    _token.user,
                    ("resource:role:assign-role",),
                    (resource_id,))
                resource = resource_by_id(conn, _token.user, resource_id)
                return unassign_resource_user(
                    conn, resource, user_by_id(conn, UUID(user_id)),
                    role_by_id(conn, UUID(role_id)))# type: ignore[arg-type]
        except AssertionError as aserr:
            raise AuthorisationError(aserr.args[0]) from aserr

        return jsonify(with_db_connection(__assign__))

def __public_view_params__(cursor, user_id, resource_id):
    ignore = (str(user_id),)
    # sys admins
    cursor.execute(
        "SELECT ur.user_id FROM user_roles AS ur INNER JOIN roles AS r "
        "ON ur.role_id=r.role_id WHERE r.role_name='system-administrator'")
    ignore = ignore + tuple(
        row["user_id"] for row in cursor.fetchall())
    # group admins
    cursor.execute(
        "SELECT DISTINCT gu.user_id FROM resource_ownership AS ro "
        "INNER JOIN groups AS g ON ro.group_id=g.group_id "
        "INNER JOIN group_users AS gu ON g.group_id=gu.group_id "
        "INNER JOIN user_roles AS ur ON gu.user_id=ur.user_id "
        "INNER JOIN roles AS r ON ur.role_id=r.role_id "
        "WHERE ro.resource_id=? AND r.role_name='group-leader'",
        (str(resource_id),))
    ignore = tuple(set(
        ignore + tuple(row["user_id"] for row in cursor.fetchall())))

    cursor.execute(
        "SELECT user_id FROM users WHERE user_id NOT IN "
        f"({', '.join(['?'] * len(ignore))})",
        ignore)
    user_ids = tuple(row["user_id"] for row in cursor.fetchall())
    cursor.execute(
        "SELECT role_id FROM roles WHERE role_name='public-view'")
    role_id = cursor.fetchone()["role_id"]
    return tuple({
        "user_id": user_id,
        "role_id": role_id,
        "resource_id": str(resource_id)
    } for user_id in user_ids)

def __assign_revoke_public_view__(cursor, user_id, resource_id, public):
    if public:
        cursor.executemany(
            "INSERT INTO user_roles(user_id, role_id, resource_id) "
            "VALUES(:user_id, :role_id, :resource_id) "
            "ON CONFLICT (user_id, role_id, resource_id) "
            "DO NOTHING",
            __public_view_params__(cursor, user_id, resource_id))
        return
    cursor.executemany(
        "DELETE FROM user_roles WHERE user_id=:user_id "
        "AND role_id=:role_id AND resource_id=:resource_id",
        __public_view_params__(cursor, user_id, resource_id))

@resources.route("<uuid:resource_id>/toggle-public", methods=["POST"])
@require_oauth("profile group resource role")
def toggle_public(resource_id: UUID) -> Response:
    """Make a resource public if it is private, or private if public."""
    with require_oauth.acquire("profile group resource") as the_token:
        def __toggle__(conn: db.DbConnection) -> Resource:
            old_rsc = resource_by_id(conn, the_token.user, resource_id)
            public = not old_rsc.public
            new_resource = Resource(
                old_rsc.resource_id, old_rsc.resource_name,
                old_rsc.resource_category, public,
                old_rsc.resource_data)
            with db.cursor(conn) as cursor:
                cursor.execute(
                    "UPDATE resources SET public=:public "
                    "WHERE resource_id=:resource_id",
                    {
                        "public": 1 if public else 0,
                        "resource_id": str(resource_id)
                    })
                __assign_revoke_public_view__(
                    cursor, the_token.user.user_id, resource_id, public)
                return new_resource
            return new_resource

        resource = with_db_connection(__toggle__)
        return jsonify({
            "resource": asdict(resource),
            "description": (
                "Made resource public" if resource.public
                else "Made resource private")})


@resources.route("<uuid:resource_id>/roles", methods=["GET"])
@require_oauth("profile group resource role")
def resource_roles(resource_id: UUID) -> Response:
    """Return the roles the user has to act on a given resource."""
    with require_oauth.acquire("profile group resource role") as _token:


        def __roles__(conn: db.DbConnection) -> tuple[Role, ...]:
            with db.cursor(conn) as cursor:
                cursor.execute(
                    "SELECT r.*, p.* FROM resource_roles AS rr "
                    "INNER JOIN roles AS r  ON rr.role_id=r.role_id "
                    "INNER JOIN role_privileges AS rp ON r.role_id=rp.role_id "
                    "INNER JOIN privileges AS p "
                    "ON rp.privilege_id=p.privilege_id "
                    "WHERE rr.resource_id=? AND rr.role_created_by=?",
                    (str(resource_id), str(_token.user.user_id)))
                user_created = db_rows_to_roles(cursor.fetchall())

                cursor.execute(
                    "SELECT ur.user_id, ur.resource_id, r.*, p.* FROM user_roles AS ur "
                    "INNER JOIN roles AS r ON ur.role_id=r.role_id "
                    "INNER JOIN role_privileges AS rp ON r.role_id=rp.role_id "
                    "INNER JOIN privileges AS p ON rp.privilege_id=p.privilege_id "
                    "WHERE resource_id=? AND user_id=?",
                    (str(resource_id), str(_token.user.user_id)))
                assigned_to_user = db_rows_to_roles(cursor.fetchall())

            return assigned_to_user + user_created

        return jsonify(with_db_connection(__roles__))


@resources.route("/authorisation", methods=["POST"])
def resources_authorisation():
    """Get user authorisations for given resource(s):"""
    try:
        data = request_json()
        assert (data and "resource-ids" in data)
        resource_ids = tuple(UUID(resid) for resid in data["resource-ids"])
        pubres = tuple(
            res.resource_id for res in with_db_connection(public_resources)
            if res.resource_id in resource_ids)
        with require_oauth.acquire("profile resource") as the_token:
            the_resources = with_db_connection(lambda conn: user_roles_on_resources(
                conn, the_token.user, resource_ids))
            resp = jsonify({
                str(resid): {
                    "public-read": resid in pubres,
                    "roles": tuple(
                        asdict(rol) for rol in
                        the_resources.get(resid, {}).get("roles", tuple()))
                } for resid in resource_ids
            })
    except _HTTPException as _httpe:
        err_msg = json.loads(_httpe.body)
        if err_msg["error"] == "missing_authorization":
            resp = jsonify({
                str(resid): {
                    "public-read": resid in pubres
                } for resid in resource_ids
            })
    except AssertionError as _aerr:
        resp = jsonify({
            "status": "bad-request",
            "error_description": (
                "Expected a JSON object with a 'resource-ids' key.")
        })
        resp.status_code = 400
    except Exception as _exc:#pylint: disable=[broad-except]
        app.logger.debug("Generic exception.", exc_info=True)
        resp = jsonify({
            "status": "general-exception",
            "error_description": (
                "Failed to fetch the user's privileges.")
        })
        resp.status_code = 500

    return resp


@resources.route("/authorisation/<name>", methods=["GET"])
def get_user_roles_on_resource(name) -> Response:
    """Get user authorisation for a given resource given it's name"""
    resid = with_db_connection(
        lambda conn: get_resource_id(conn, name)
    )
    def _extract_privilege_id(privileges):
        return tuple(
            p_.privilege_id for p_ in privileges
        )

    with require_oauth.acquire("profile resource") as _token:
        resources_ = with_db_connection(
            lambda conn: user_roles_on_resources(
                conn, _token.user, (resid,)
            )
        )
        roles: list = reduce (operator.iconcat,
                        tuple(
                            _extract_privilege_id(role.privileges)
            for role in
                            resources_.get(
                                UUID(resid), {}
                            ).get("roles", tuple())), [])
        response = make_response({
            # Flatten this list
            "roles": roles,
            "silly": "ausah",
        })
        iat = int(time.time())
        jose_header = {
            "alg": "RS256",
            "typ": "jwt",
            "cty": "json",
        }
        payload = {
            # Registered Claims
            "iss": request.url,  # Issuer Claim
            "iat": iat,  # Issued At
            "sub": name,  # Subject Claim
            "aud": f"Edit {name}",  # Audience Claim
            "exp": iat + 300,  # Expiration Time Claim
            "jti": str(uuid4()),  # Unique Identifier for this token
            # Private Claims
            "account-name": _token.user.name,
            "email": _token.user.email,
            "roles": roles,
        }
        token = jwt.encode(
            jose_header, payload, newest_jwk(jwks_directory(app)))
        response.headers["Authorization"] = f"Bearer {token.decode('utf-8')}"
        return response


@resources.route("/<uuid:resource_id>/role/<uuid:role_id>", methods=["GET"])
@require_oauth("profile group resource")
def resource_role(resource_id: UUID, role_id: UUID):
    """Fetch details for resource."""
    with (require_oauth.acquire("profile group resource") as _token,
          db.connection(app.config["AUTH_DB"]) as conn,
          db.cursor(conn) as cursor):
        cursor.execute(
            "SELECT rr.role_created_by, r.*, p.* FROM resource_roles AS rr "
            "INNER JOIN roles AS r ON rr.role_id=r.role_id "
            "INNER JOIN role_privileges AS rp ON r.role_id=rp.role_id "
            "INNER JOIN privileges AS p ON rp.privilege_id=p.privilege_id "
            "WHERE rr.resource_id=? AND rr.role_created_by=? AND rr.role_id=?",
            (str(resource_id), str(_token.user.user_id), str(role_id)))
        results = cursor.fetchall()

    if not bool(results):
        msg = f"Could not find role with ID '{role_id}'."
        return jsonify({
            "error": "RoleNotFound",
            "error_description": msg,
            "error_message": msg,
            "message": msg
        }), 404

    _roles = db_rows_to_roles(results)
    if len(_roles) > 1:
        msg = "There is data corruption in the database."
        return jsonify({
            "error": "RoleNotFound",
            "error_description": msg,
            "error_message": msg,
            "message": msg
        }), 500

    return asdict(_roles[0])


@resources.route("/<uuid:resource_id>/role/<uuid:role_id>/unassign-privilege",
                 methods=["POST"])
@require_oauth("profile group resource")
def unassign_resource_role_privilege(resource_id: UUID, role_id: UUID):
    """Unassign a privilege from a resource role."""
    with (require_oauth.acquire("profile group resource") as _token,
          db.connection(app.config["AUTH_DB"]) as conn,
          db.cursor(conn) as cursor):
        _role = role_by_id(conn, role_id)

        _authorised = authorised_for(
            conn,
            _token.user,
            privileges=("resource:role:edit-role",),
            resource_ids=(resource_id,)).get(resource_id)
        if not _authorised:
            raise AuthorisationError(
                "You are not authorised to edit/update this role.")

        # Actually unassign the privilege from the role
        privilege_id = request_json().get("privilege_id")
        if not privilege_id:
            raise AuthorisationError(
                "You need to provide a privilege to unassign")

        delete_privilege_from_resource_role(
            cursor,
            _role,# type: ignore[arg-type]
            privilege_by_id(conn, privilege_id))# type: ignore[arg-type]

        return jsonify({
            "status": "Success",
            "message": "Privilege was unassigned."
        }), 200


@resources.route("/<uuid:resource_id>/role/<uuid:role_id>/users",
                 methods=["GET"])
@require_oauth("profile group resource")
def resource_role_users(resource_id: UUID, role_id: UUID):
    """Retrieve users assigned role on resource."""
    with (require_oauth.acquire("profile group resource") as _token,
          db.connection(app.config["AUTH_DB"]) as conn,
          db.cursor(conn) as cursor):
        # MAYBE: check user has something like resource:role:view-users
        cursor.execute(
            "SELECT u.* FROM user_roles AS ur INNER JOIN users AS u "
            "ON ur.user_id=u.user_id WHERE ur.resource_id=? AND ur.role_id=?",
            (str(resource_id), str(role_id)))
        results = cursor.fetchall() or []

    return jsonify(tuple(User.from_sqlite3_row(row) for row in results)), 200


@resources.route("/<uuid:resource_id>/roles/create", methods=["POST"])
@require_oauth("profile group resource")
def create_resource_role(resource_id: UUID):
    """Create a role to act upon a specific resource."""
    role_name = request_json().get("role_name", "").strip()
    if not bool(role_name):
        raise BadRequest("You must provide the name for the new role.")

    with (require_oauth.acquire("profile group resource") as _token,
          db.connection(app.config["AUTH_DB"]) as conn,
          db.cursor(conn) as cursor):
        resource = resource_by_id(conn, _token.user, resource_id)
        if not bool(resource):
            raise BadRequest("No resource with that ID exists.")

        privileges = privileges_by_ids(conn, request_json().get("privileges", []))
        if len(privileges) == 0:
            raise BadRequest(
                "You must provide at least one privilege for the new role.")
        role = create_role(cursor,
                           f"{resource.resource_name}::{role_name}",
                           privileges)
        cursor.execute(
            "INSERT INTO resource_roles(resource_id, role_created_by, role_id) "
            "VALUES (:resource_id, :user_id, :role_id)",
            {
                "resource_id": str(resource_id),
                "user_id": str(_token.user.user_id),
                "role_id": str(role.role_id)
            })

    return jsonify(asdict(role))

@resources.route("/<uuid:resource_id>/users/<uuid:user_id>/roles", methods=["GET"])
@require_oauth("profile group resource role")
def user_resource_roles(resource_id: UUID, user_id: UUID):
    """Get a specific user's roles on a particular resource."""
    with (require_oauth.acquire("profile group resource") as _token,
          db.connection(app.config["AUTH_DB"]) as conn):
        if _token.user.user_id != user_id:
            raise AuthorisationError(
                "You are not authorised to view the roles this user has.")

        _resource = resource_by_id(conn, _token.user, resource_id)
        if not bool(_resource):
            raise BadRequest("No resource was found with the given ID.")

        return jsonify([asdict(role) for role in
                        _user_resource_roles(conn, _token.user, _resource)])
