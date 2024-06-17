"""Routes for privileges."""
from werkzeug.exceptions import NotFound
from flask import jsonify, Blueprint, current_app as app

from gn_auth.auth.db import sqlite3 as db

from .models import all_privileges, privilege_by_id

privileges = Blueprint("privileges", __name__)

@privileges.route("/", methods=["GET"])
@privileges.route("/list", methods=["GET"])
def list_privileges():
    """List all the available privileges."""
    with db.connection(app.config["AUTH_DB"]) as conn:
        _privileges = all_privileges(conn)

    return jsonify(_privileges if bool(_privileges) else []), 200

@privileges.route("/<privilege_id>/", methods=["GET"])
@privileges.route("/<privilege_id>/view", methods=["GET"])
def view_privilege(privilege_id: str):
    """View details of a single privilege"""
    with db.connection(app.config["AUTH_DB"]) as conn:
        _privilege = privilege_by_id(conn, privilege_id)

    if bool(_privilege):
        return jsonify(_privilege)

    raise NotFound(f"No privilege exists with ID '{privilege_id}'")
