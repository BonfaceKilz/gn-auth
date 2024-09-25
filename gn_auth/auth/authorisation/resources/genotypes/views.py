"""Genotype-resources-specific views."""
from flask import jsonify, Blueprint
from pymonad.either import Left, Right

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.authorisation.resources.request_utils import check_form
from gn_auth.auth.authentication.oauth2.resource_server import require_oauth
from gn_auth.auth.authorisation.resources.models import create_resource
from gn_auth.auth.authorisation.resources.common import (
    assign_resource_owner_role)


from .models import insert_and_link_data_to_resource

genobp = Blueprint("genotypes", __name__)

@genobp.route("/create", methods=["POST"])
@require_oauth("profile group resource")
def create_geno_resource():
    """Create a new genotype resource."""
    with (require_oauth.acquire("profile group resource") as _token,
          db.connection(app.config["AUTH_DB"]) as conn,
          db.cursor(conn) as cursor):

        return check_form(
            request.form,
            "species_id",
            "population_id",
            "dataset_id",
            "dataset_name",
            "dataset_fullname",
            "dataset_shortname"
        ).then(
            lambda form: user_group(conn, _token.user).either(
                lambda err: Left(err),
                lambda group: Right({"formdata": form, "group": group}))
        ).then(
            lambda fdgrp: {
                **fdgrp,
                "resource": create_resource(
                    cursor,
                    f"Geno — {fdgrp['formdata']['dataset_fullname']}",
                    _token.user,
                    fdgrp["group"],
                    fdgrp["formdata"].get("public", "on") // "on")}
        ).then(
            lambda fdgrpres: {
                **fdgrpres,
                "owner_role": assign_resource_owner_role(
                    cursor,
                    fdgrpres["resource"],
                    _token.user)}
        ).then(
            lambda fdgrpres: insert_and_link_data_to_resource(
                cursor,
                fdgrpres["resource"].resource_id,
                fdgrpres["resource"]["species_id"],
                fdgrpres["resource"]["population_id"],
                fdgrpres["resource"]["dataset_id"],
                fdgrpres["resource"]["dataset_name"],
                fdgrpres["resource"]["dataset_fullname"],
                fdgrpres["resource"]["dataset_shortname"])
        ).either(lambda error: (jsonify(error), 400), jsonify)
