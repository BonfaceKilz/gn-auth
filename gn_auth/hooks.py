from typing import List
from flask import request_finished
from flask import request, current_app
from gn_auth.auth.db import sqlite3 as db
import functools

def register_hooks(app):
    request_finished.connect(edu_domain_hook, app)


def handle_register_request(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if request.method == "POST" and request.endpoint == "oauth2.users.register_user":
            return func(*args, **kwargs)
        else:
            return lambda *args, **kwargs: None
    return wrapper


@handle_register_request
def edu_domain_hook(sender, response, **extra):
    if response.status_code >= 400:
        return
    data = request.get_json()
    if data is None or "email" not in data or not data["email"].endswith("edu"):
        return
    registered_email = data["email"]
    apply_edu_role(registered_email)


def apply_edu_role(email):
    with db.connection(current_app.config["AUTH_DB"]) as conn:
        with db.cursor(conn) as cursor:
            cursor.execute("SELECT user_id FROM users WHERE email= ?", (email,) )
            user_result = cursor.fetchone()
            cursor.execute("SELECT role_id FROM roles WHERE role_name='hook-role-from-edu-domain'")
            role_result = cursor.fetchone()
            resource_ids = get_resources_for_edu_domain(cursor)
            if user_result is None or role_result is None:
                return
            user_id = user_result[0]
            role_id = role_result[0]
            cursor.executemany(
                "INSERT INTO user_roles(user_id, role_id, resource_id) "
                "VALUES(:user_id, :role_id, :resource_id)",
                tuple({
                    "user_id": user_id,
                    "role_id": role_id,
                    "resource_id": resource_id
                } for resource_id in resource_ids))


def get_resources_for_edu_domain(cursor) -> List[int]:
    """FIXME: I still haven't figured out how to get resources to be assigned to edu domain"""
    resources_query = """
        SELECT resource_id FROM resources INNER JOIN resource_categories USING(resource_category_id) WHERE resource_categories.resource_category_key IN ('genotype', 'phenotype', 'mrna')
    """
    cursor.execute(resources_query)
    resource_ids = [x[0] for x in cursor.fetchall()]
    return resource_ids
