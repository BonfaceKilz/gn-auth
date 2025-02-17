"""Views for InbredSet resources."""
from pymonad.either import Left, Right, Either
from flask import jsonify, Response, Blueprint, current_app as app


from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.requests import request_json
from gn_auth.auth.db.sqlite3 import with_db_connection
from gn_auth.auth.authentication.oauth2.resource_server import require_oauth
from gn_auth.auth.authorisation.resources.groups.models import user_group, admin_group

from .models import (create_resource,
                     link_data_to_resource,
                     assign_inbredset_group_owner_role)

popbp = Blueprint("populations", __name__)

@popbp.route("/populations/resource-id/<int:speciesid>/<int:inbredsetid>",
            methods=["GET"])
def resource_id_by_inbredset_id(speciesid: int, inbredsetid: int) -> Response:
    """Retrieve the resource ID for resource attached to the inbredset."""
    def __res_by_iset_id__(conn):
        with db.cursor(conn) as cursor:
            cursor.execute(
                "SELECT r.resource_id FROM linked_inbredset_groups AS lisg "
                "INNER JOIN inbredset_group_resources AS isgr "
                "ON lisg.data_link_id=isgr.data_link_id "
                "INNER JOIN resources AS r ON isgr.resource_id=r.resource_id "
                "WHERE lisg.SpeciesId=? AND lisg.InbredSetId=?",
                (speciesid, inbredsetid))
            return cursor.fetchone()

    res = with_db_connection(__res_by_iset_id__)
    if res:
        resp = jsonify({"status": "success", "resource-id": res["resource_id"]})
    else:
        resp = jsonify({
            "status": "not-found",
            "error_description": (
                "Could not find resource handling InbredSet group with ID "
                f"'{inbredsetid}' that belongs to Species with ID "
                f"'{speciesid}'")
        })
        resp.status_code = 404

    return resp


@popbp.route("/populations/create", methods=["POST"])
@require_oauth("profile group resource")
def create_population_resource():
    """Create a resource of type 'inbredset-group'."""
    with (require_oauth.acquire("profile group resource") as _token,
          db.connection(app.config["AUTH_DB"]) as conn,
          db.cursor(conn) as cursor):

        def __check_form__(form, usergroup) -> Either:
            """Check form for errors."""
            errors: tuple[str, ...] = tuple()

            species_id = form.get("species_id")
            if not bool(species_id):
                errors = errors + ("Missing `species_id` value.",)

            population_id = form.get("population_id")
            if not bool(population_id):
                errors = errors + ("Missing `population_id` value.",)

            population_name = form.get("population_name")
            if not bool(population_name):
                errors = errors + ("Missing `population_name` value.",)

            population_fullname = form.get("population_fullname")
            if not bool(population_fullname):
                errors = errors + ("Missing `population_fullname` value.",)

            if bool(errors):
                error_messages = "\n\t - ".join(errors)
                return Left({
                    "error": "Invalid Request Data!",
                    "error_description": error_messages
                })

            return Right({"formdata": form, "group": usergroup})

        def __default_group_if_none__(group) -> Either:
            if group.is_nothing():
                return admin_group(conn)
            return Right(group.value)

        return __default_group_if_none__(
            user_group(conn, _token.user)
        ).then(
            lambda group: __check_form__(request_json(), group)
        ).then(
            lambda formdata: {
                **formdata,
                "resource": create_resource(
                    cursor,
                    f"Population — {formdata['formdata']['population_name']}",
                    _token.user,
                    formdata["group"],
                    formdata["formdata"].get("public", "on") == "on")}
        ).then(
            lambda resource: {
                **resource,
                "resource": assign_inbredset_group_owner_role(
                    cursor, resource["resource"], _token.user)}
        ).then(
            lambda resource: link_data_to_resource(
                cursor,
                resource["resource"].resource_id,
                resource["formdata"]["species_id"],
                resource["formdata"]["population_id"],
                resource["formdata"]["population_name"],
                resource["formdata"]["population_fullname"])
        ).either(
            lambda error: (jsonify(error), 400),
            jsonify)
