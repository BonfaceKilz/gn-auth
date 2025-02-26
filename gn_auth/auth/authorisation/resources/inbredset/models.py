"""Functions to handle the low-level details regarding populations auth."""
from uuid import UUID, uuid4

import sqlite3

from gn_auth.auth.errors import NotFoundError
from gn_auth.auth.authentication.users import User
from gn_auth.auth.authorisation.resources.groups.models import Group
from gn_auth.auth.authorisation.resources.base import Resource, ResourceCategory
from gn_auth.auth.authorisation.resources.models import (
    create_resource as _create_resource)

def create_resource(
        cursor: sqlite3.Cursor,
        resource_name: str,
        user: User,
        group: Group,
        public: bool
) -> Resource:
    """Convenience function to create a resource of type 'inbredset-group'."""
    cursor.execute("SELECT * FROM resource_categories "
                   "WHERE resource_category_key='inbredset-group'")
    category = cursor.fetchone()
    if category:
        return _create_resource(cursor,
                                resource_name,
                                ResourceCategory(
                                    resource_category_id=UUID(
                                        category["resource_category_id"]),
                                    resource_category_key="inbredset-group",
                                    resource_category_description=category[
                                        "resource_category_description"]),
                                user,
                                group,
                                public)
    raise NotFoundError("Could not find a 'inbredset-group' resource category.")


def assign_inbredset_group_owner_role(
        cursor: sqlite3.Cursor,
        resource: Resource,
        user: User
) -> Resource:
    """
    Assign `user` as `InbredSet Group Owner` is resource category is
    'inbredset-group'.
    """
    if resource.resource_category.resource_category_key == "inbredset-group":
        cursor.execute(
            "SELECT * FROM roles WHERE role_name='inbredset-group-owner'")
        role = cursor.fetchone()
        cursor.execute(
            "INSERT INTO user_roles "
            "VALUES(:user_id, :role_id, :resource_id) "
            "ON CONFLICT (user_id, role_id, resource_id) DO NOTHING",
            {
                "user_id": str(user.user_id),
                "role_id": str(role["role_id"]),
                "resource_id": str(resource.resource_id)
            })

    return resource


def link_data_to_resource(# pylint: disable=[too-many-arguments, too-many-positional-arguments]
        cursor: sqlite3.Cursor,
        resource_id: UUID,
        species_id: int,
        population_id: int,
        population_name: str,
        population_fullname: str
) -> dict:
    """Link a species population to a resource for auth purposes."""
    params = {
        "resource_id": str(resource_id),
        "data_link_id": str(uuid4()),
        "species_id": species_id,
        "population_id": population_id,
        "population_name": population_name,
        "population_fullname": population_fullname
    }
    cursor.execute(
        "INSERT INTO linked_inbredset_groups "
        "VALUES("
        " :data_link_id,"
        " :species_id,"
        " :population_id,"
        " :population_name,"
        " :population_fullname"
        ")",
        params)
    cursor.execute(
        "INSERT INTO inbredset_group_resources "
        "VALUES (:resource_id, :data_link_id)",
        params)
    return params
