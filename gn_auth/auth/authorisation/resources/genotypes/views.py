"""Genotype-resources-specific views."""
import uuid

from pymonad.either import Left, Right
from flask import jsonify, Blueprint, current_app as app

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.requests import request_json

from gn_auth.auth.authorisation.resources.base import ResourceCategory
from gn_auth.auth.authorisation.resources.request_utils import check_form
from gn_auth.auth.authorisation.resources.groups.models import user_group

from gn_auth.auth.authentication.oauth2.resource_server import require_oauth

from gn_auth.auth.authorisation.resources.models import create_resource
from gn_auth.auth.authorisation.resources.common import (
    assign_resource_owner_role)


from .models import insert_and_link_data_to_resource

genobp = Blueprint("genotypes", __name__)

@genobp.route("genotypes/create", methods=["POST"])
@require_oauth("profile group resource")
def create_geno_resource():
    """Create a new genotype resource."""
    with (require_oauth.acquire("profile group resource") as _token,
          db.connection(app.config["AUTH_DB"]) as conn,
          db.cursor(conn) as cursor):
        cursor.execute("SELECT * FROM resource_categories "
                       "WHERE resource_category_key='genotype'")
        row = cursor.fetchone()

        return check_form(
            request_json(),
            "species_id",
            "population_id",
            "dataset_id",
            "dataset_name",
            "dataset_fullname",
            "dataset_shortname"
        ).then(
            lambda form: user_group(conn, _token.user).maybe(
                Left("No user group found!"),
                lambda group: Right({"formdata": form, "group": group}))
        ).then(
            lambda fdgrp: {
                **fdgrp,
                "resource": create_resource(
                    cursor,
                    f"Genotype — {fdgrp['formdata']['dataset_fullname']}",
                    ResourceCategory(uuid.UUID(row["resource_category_id"]),
                                     row["resource_category_key"],
                                     row["resource_category_description"]),
                    _token.user,
                    fdgrp["group"],
                    fdgrp["formdata"].get("public", "on") == "on")}
        ).then(
            lambda fdgrpres: {
                **fdgrpres,
                "owner_role": assign_resource_owner_role(
                    cursor,
                    fdgrpres["resource"].resource_id,
                    _token.user.user_id)}
        ).then(
            lambda fdgrpres: insert_and_link_data_to_resource(
                cursor,
                fdgrpres["resource"].resource_id,
                fdgrpres["group"].group_id,
                fdgrpres["formdata"]["species_id"],
                fdgrpres["formdata"]["population_id"],
                fdgrpres["formdata"]["dataset_id"],
                fdgrpres["formdata"]["dataset_name"],
                fdgrpres["formdata"]["dataset_fullname"],
                fdgrpres["formdata"]["dataset_shortname"])
        ).either(lambda error: (jsonify(error), 400), jsonify)
