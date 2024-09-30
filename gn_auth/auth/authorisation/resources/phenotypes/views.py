"""Views for the phenotype resources."""
from pymonad.either import Left, Right
from flask import jsonify, Blueprint, current_app as app

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.requests import request_json
from gn_auth.auth.authorisation.resources.request_utils import check_form
from gn_auth.auth.authorisation.roles.models import user_roles_on_resource

from gn_auth.auth.authentication.oauth2.resource_server import require_oauth

from .models import all_linked_resources, individual_linked_resource

phenobp = Blueprint("phenotypes", __name__)

@phenobp.route("/phenotypes/individual/linked-resource", methods=["POST"])
def get_individual_linked_resource():
    """Get the linked resource for a particular phenotype within the dataset.

    Phenotypes are a tad tricky. Each phenotype could technically be a resource
    on its own, and thus a user could have access to only a subset of phenotypes
    within the entire dataset."""
    with (require_oauth.acquire("profile group resource") as _token,
          db.connection(app.config["AUTH_DB"]) as conn):
        return check_form(
            request_json(),
            "species_id",
            "population_id",
            "dataset_id",
            "xref_id"
        ).then(
            lambda formdata: individual_linked_resource(
                    conn,
                    int(formdata["species_id"]),
                    int(formdata["population_id"]),
                    int(formdata["dataset_id"]),
                    formdata["xref_id"]
                ).maybe(Left("No linked resource!"),
                        lambda lrsc: Right({
                            "formdata": formdata,
                            "resource": lrsc
                        }))
        ).then(
            lambda fdlrsc: {
                **fdlrsc,
                "roles": user_roles_on_resource(
                    conn, _token.user.user_id, fdlrsc["resource"].resource_id)
            }
        ).either(lambda error: (jsonify(error), 400),
                 lambda res: jsonify({
                     key: value for key, value in res.items()
                     if key != "formdata"
                 }))


@phenobp.route("/phenotypes/linked-resources", methods=["POST"])
def get_all_linked_resources():
    """Get all the linked resources for all phenotypes within a dataset.

    See `get_individual_linked_resource(…)` documentation."""
    with (require_oauth.acquire("profile group resource") as _token,
          db.connection(app.config["AUTH_DB"]) as conn):
        return check_form(
            request_json(),
            "species_id",
            "population_id",
            "dataset_id"
        ).then(
            lambda formdata: all_linked_resources(
                conn,
                int(formdata["species_id"]),
                int(formdata["population_id"]),
                int(formdata["dataset_id"])).maybe(
                    Left("No linked resource!"), Right)
        ).either(lambda error: (jsonify(error), 400), jsonify)
