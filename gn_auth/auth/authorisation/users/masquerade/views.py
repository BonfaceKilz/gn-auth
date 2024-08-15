"""Endpoints for user masquerade"""
from dataclasses import asdict
from uuid import UUID
from functools import partial

from flask import request, jsonify, Response, Blueprint

from gn_auth.auth.errors import InvalidData

from ...checks import require_json
from ....db.sqlite3 import with_db_connection
from ....authentication.users import user_by_id
from ....authentication.oauth2.resource_server import require_oauth

from .models import masquerade_as

masq = Blueprint("masquerade", __name__)

@masq.route("/", methods=["POST"])
@require_oauth("profile user masquerade")
@require_json
def masquerade() -> Response:
    """Masquerade as a particular user."""
    with require_oauth.acquire("profile user masquerade") as token:
        masqueradee_id = UUID(request.json["masquerade_as"])#type: ignore[index]
        if masqueradee_id == token.user.user_id:
            raise InvalidData("You are not allowed to masquerade as yourself.")

        masq_user = with_db_connection(partial(
            user_by_id, user_id=masqueradee_id))
        def __masq__(conn):
            new_token = masquerade_as(conn, original_token=token, masqueradee=masq_user)
            return new_token
        def __dump_token__(tok):
            return {
                key: value for key, value in tok.items()
                if key in ("access_token", "refresh_token", "expires_in",
                           "token_type")
            }
        return jsonify({
            "original": {
                "user": asdict(token.user),
                "token": __dump_token__(token)
            },
            "masquerade_as": {
                "user": asdict(masq_user),
                "token": __dump_token__(with_db_connection(__masq__))
            }
        })
