"""Handle the management of resources."""
from dataclasses import asdict
from uuid import UUID, uuid4
from functools import reduce, partial
from typing import Dict, Sequence, Optional

import sqlite3

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.authentication.users import User
from gn_auth.auth.db.sqlite3 import with_db_connection

from gn_auth.auth.authorisation.roles import Role
from gn_auth.auth.authorisation.privileges import Privilege
from gn_auth.auth.authorisation.checks import authorised_p
from gn_auth.auth.errors import NotFoundError, AuthorisationError

from .checks import authorised_for
from .base import Resource, ResourceCategory
from .groups.models import Group, is_group_leader
from .mrna import (
    resource_data as mrna_resource_data,
    attach_resources_data as mrna_attach_resources_data,
    link_data_to_resource as mrna_link_data_to_resource,
    unlink_data_from_resource as mrna_unlink_data_from_resource)
from .genotype import (
    resource_data as genotype_resource_data,
    attach_resources_data as genotype_attach_resources_data,
    link_data_to_resource as genotype_link_data_to_resource,
    unlink_data_from_resource as genotype_unlink_data_from_resource)
from .phenotype import (
    resource_data as phenotype_resource_data,
    attach_resources_data as phenotype_attach_resources_data,
    link_data_to_resource as phenotype_link_data_to_resource,
    unlink_data_from_resource as phenotype_unlink_data_from_resource)

def __assign_resource_owner_role__(cursor, resource, user):
    """Assign `user` the 'Resource Owner' role for `resource`."""
    cursor.execute("SELECT * FROM roles WHERE role_name='resource-owner'")
    role = cursor.fetchone()
    cursor.execute(
        "INSERT INTO user_roles "
        "VALUES (:user_id, :role_id, :resource_id) "
        "ON CONFLICT (user_id, role_id, resource_id) DO NOTHING",
        {
            "user_id": str(user.user_id),
            "role_id": role["role_id"],
            "resource_id": str(resource.resource_id)
        })


def resource_from_dbrow(row: sqlite3.Row):
    """Convert an SQLite3 resultset row into a resource."""
    return Resource(
        resource_id=UUID(row["resource_id"]),
        resource_name=row["resource_name"],
        resource_category=ResourceCategory(
            UUID(row["resource_category_id"]),
            row["resource_category_key"],
            row["resource_category_description"]),
        public=bool(int(row["public"])))


@authorised_p(("group:resource:create-resource",),
              error_description="Insufficient privileges to create a resource",
              oauth2_scope="profile resource")
def create_resource(# pylint: disable=[too-many-arguments]
        cursor: sqlite3.Cursor,
        resource_name: str,
        resource_category: ResourceCategory,
        user: User,
        group: Group,
        public: bool
) -> Resource:
    """Create a resource item."""
    resource = Resource(uuid4(), resource_name, resource_category, public)
    cursor.execute(
        "INSERT INTO resources VALUES (?, ?, ?, ?)",
        (str(resource.resource_id),
         resource_name,
         str(resource.resource_category.resource_category_id),
         1 if resource.public else 0))
    # TODO: @fredmanglis,@rookie101
    # 1. Move the actions below into a (the?) hooks system
    # 2. Do more checks: A resource can have varying hooks depending on type
    #    e.g. if mRNA, pheno or geno resource, assign:
    #           - "resource-owner"
    #         if inbredset-group, assign:
    #           - "resource-owner",
    #           - "inbredset-group-owner" etc.
    #         if resource is of type "group", assign:
    #           - group-leader
    cursor.execute("INSERT INTO resource_ownership (group_id, resource_id) "
                   "VALUES (?, ?)",
                   (str(group.group_id), str(resource.resource_id)))
    __assign_resource_owner_role__(cursor, resource, user)

    return resource

def resource_category_by_id(
        conn: db.DbConnection, category_id: UUID) -> ResourceCategory:
    """Retrieve a resource category by its ID."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            "SELECT * FROM resource_categories WHERE "
            "resource_category_id=?",
            (str(category_id),))
        results = cursor.fetchone()
        if results:
            return ResourceCategory(
                UUID(results["resource_category_id"]),
                results["resource_category_key"],
                results["resource_category_description"])

    raise NotFoundError(
        f"Could not find a ResourceCategory with ID '{category_id}'")

def resource_categories(conn: db.DbConnection) -> Sequence[ResourceCategory]:
    """Retrieve all available resource categories"""
    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM resource_categories")
        return tuple(
            ResourceCategory(UUID(row[0]), row[1], row[2])
            for row in cursor.fetchall())
    return tuple()

def public_resources(conn: db.DbConnection) -> Sequence[Resource]:
    """List all resources marked as public"""
    categories = {
        str(cat.resource_category_id): cat for cat in resource_categories(conn)
    }
    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM resources WHERE public=1")
        results = cursor.fetchall()
        return tuple(
            Resource(UUID(row[0]), row[1], categories[row[2]], bool(row[3]))
            for row in results)

def group_leader_resources(
        conn: db.DbConnection, user: User, group: Group,
        res_categories: Dict[UUID, ResourceCategory]) -> Sequence[Resource]:
    """Return all the resources available to the group leader"""
    if is_group_leader(conn, user, group):
        with db.cursor(conn) as cursor:
            cursor.execute(
                "SELECT r.* FROM resource_ownership AS ro "
                "INNER JOIN resources AS r "
                "ON ro.resource_id=r.resource_id "
                "WHERE ro.group_id=?",
                (str(group.group_id),))
            return tuple(
                Resource(UUID(row[0]), row[1],
                         res_categories[UUID(row[2])], bool(row[3]))
                for row in cursor.fetchall())
    return tuple()

def user_resources(conn: db.DbConnection, user: User) -> Sequence[Resource]:
    """List the resources available to the user"""
    with db.cursor(conn) as cursor:
        cursor.execute(
            ("SELECT r.*, rc.resource_category_key, "
             "rc.resource_category_description  FROM user_roles AS ur "
             "INNER JOIN resources AS r ON ur.resource_id=r.resource_id "
             "INNER JOIN resource_categories AS rc "
             "ON r.resource_category_id=rc.resource_category_id "
             "WHERE ur.user_id=?"),
            (str(user.user_id),))
        rows = cursor.fetchall() or []

    return tuple(resource_from_dbrow(row) for row in rows)


def resource_data(conn, resource, offset: int = 0, limit: Optional[int] = None) -> tuple[dict, ...]:
    """
    Retrieve the data for `resource`, optionally limiting the number of items.
    """
    resource_data_function = {
        "mrna": mrna_resource_data,
        "genotype": genotype_resource_data,
        "phenotype": phenotype_resource_data,
        "phenotype-metadata": lambda *args: tuple(),
        "genotype-metadata": lambda *args: tuple(),
        "mrna-metadata": lambda *args: tuple(),
        "system": lambda *args: tuple(),
        "group": lambda *args: tuple()
    }
    with db.cursor(conn) as cursor:
        return tuple(
            dict(data_row) for data_row in
            resource_data_function[# type: ignore[operator]
                resource.resource_category.resource_category_key](
                    cursor, resource.resource_id, offset, limit))

def attach_resource_data(cursor: db.DbCursor, resource: Resource) -> Resource:
    """Attach the linked data to the resource"""
    resource_data_function = {
        "mrna": mrna_resource_data,
        "genotype": genotype_resource_data,
        "phenotype": phenotype_resource_data
    }
    category = resource.resource_category
    data_rows = tuple(
        dict(data_row) for data_row in
        resource_data_function[category.resource_category_key](
            cursor, resource.resource_id))
    return Resource(
        resource.resource_id, resource.resource_name,
        resource.resource_category, resource.public, data_rows)

def resource_by_id(
        conn: db.DbConnection, user: User, resource_id: UUID) -> Resource:
    """Retrieve a resource by its ID."""
    if not authorised_for(
            conn, user, ("group:resource:view-resource",),
            (resource_id,))[resource_id]:
        raise AuthorisationError(
            "You are not authorised to access resource with id "
            f"'{resource_id}'.")

    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM resources WHERE resource_id=:id",
                       {"id": str(resource_id)})
        row = cursor.fetchone()
        if row:
            return Resource(
                UUID(row["resource_id"]), row["resource_name"],
                resource_category_by_id(conn, row["resource_category_id"]),
                bool(int(row["public"])))

    raise NotFoundError(f"Could not find a resource with id '{resource_id}'")

def link_data_to_resource(
        conn: db.DbConnection, user: User, resource_id: UUID, dataset_type: str,
        data_link_id: UUID) -> dict:
    """Link data to resource."""
    if not authorised_for(
            conn, user, ("group:resource:edit-resource",),
            (resource_id,))[resource_id]:
        raise AuthorisationError(
            "You are not authorised to link data to resource with id "
            f"{resource_id}")

    resource = with_db_connection(partial(
        resource_by_id, user=user, resource_id=resource_id))
    return {# type: ignore[operator]
        "mrna": mrna_link_data_to_resource,
        "genotype": genotype_link_data_to_resource,
        "phenotype": phenotype_link_data_to_resource,
    }[dataset_type.lower()](conn, resource, data_link_id)

def unlink_data_from_resource(
        conn: db.DbConnection, user: User, resource_id: UUID, data_link_id: UUID):
    """Unlink data from resource."""
    if not authorised_for(
            conn, user, ("group:resource:edit-resource",),
            (resource_id,))[resource_id]:
        raise AuthorisationError(
            "You are not authorised to link data to resource with id "
            f"{resource_id}")

    resource = with_db_connection(partial(
        resource_by_id, user=user, resource_id=resource_id))
    dataset_type = resource.resource_category.resource_category_key
    return {
        "mrna": mrna_unlink_data_from_resource,
        "genotype": genotype_unlink_data_from_resource,
        "phenotype": phenotype_unlink_data_from_resource,
    }[dataset_type.lower()](conn, resource, data_link_id)

def organise_resources_by_category(resources: Sequence[Resource]) -> dict[
        ResourceCategory, tuple[Resource]]:
    """Organise the `resources` by their categories."""
    def __organise__(accumulator, resource):
        category = resource.resource_category
        return {
            **accumulator,
            category: accumulator.get(category, tuple()) + (resource,)
        }
    return reduce(__organise__, resources, {})

def attach_resources_data(
        conn: db.DbConnection, resources: Sequence[Resource]) -> Sequence[
            Resource]:
    """Attach linked data for each resource in `resources`"""
    resource_data_function = {
        "mrna": mrna_attach_resources_data,
        "genotype": genotype_attach_resources_data,
        "phenotype": phenotype_attach_resources_data,
        "system": lambda *args: [],
        "group": lambda *args: [],
        "inbredset-group": lambda *args: []
    }
    organised = organise_resources_by_category(resources)
    with db.cursor(conn) as cursor:
        return tuple(
            resource for categories in
            (resource_data_function[category.resource_category_key](# type: ignore[operator]
                cursor, rscs)
             for category, rscs in organised.items())
            for resource in categories)


def assign_resource_user(
        conn: db.DbConnection,
        resource: Resource,
        user: User,
        role: Role
) -> dict:
    """Assign `role` to `user` for the specific `resource`."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            "INSERT INTO user_roles(user_id, role_id, resource_id)"
            "VALUES (?, ?, ?) "
            "ON CONFLICT (user_id, role_id, resource_id) "
            "DO NOTHING",
            (str(user.user_id), str(role.role_id), str(resource.resource_id)))
        return {
            "resource": asdict(resource),
            "user": asdict(user),
            "role": asdict(role),
            "description": (
                f"The user '{user.name}'({user.email}) was assigned the "
                f"'{role.role_name}' role on resource with ID "
                f"'{resource.resource_id}'.")}


def unassign_resource_user(
        conn: db.DbConnection,
        resource: Resource,
        user: User,
        role: Role
) -> dict:
    """Assign `role` to `user` for the specific `resource`."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            "DELETE FROM user_roles "
            "WHERE user_id=? AND role_id=? AND resource_id=?",
            (str(user.user_id), str(role.role_id), str(resource.resource_id)))
        return {
            "resource": asdict(resource),
            "user": asdict(user),
            "role": asdict(role),
            "description": (
                f"The user '{user.name}'({user.email}) had the "
                f"'{role.role_name}' role on resource with ID "
                f"'{resource.resource_id}' taken away.")}

def save_resource(
        conn: db.DbConnection, user: User, resource: Resource) -> Resource:
    """Update an existing resource."""
    resource_id = resource.resource_id
    authorised = authorised_for(
        conn, user, ("group:resource:edit-resource",), (resource_id,))
    if authorised[resource_id]:
        with db.cursor(conn) as cursor:
            cursor.execute(
                "UPDATE resources SET "
                "resource_name=:resource_name, "
                "public=:public "
                "WHERE resource_id=:resource_id",
                {
                    "resource_name": resource.resource_name,
                    "public": 1 if resource.public else 0,
                    "resource_id": str(resource.resource_id)
                })
            return resource

    raise AuthorisationError(
        "You do not have the appropriate privileges to edit this resource.")

def user_roles_on_resources(conn: db.DbConnection,
                            user: User,
                            resource_ids: tuple[UUID, ...] = tuple()) -> dict:
    """Get roles on resources for a particular user."""
    def __setup_roles__(old_roles, row):
        roles = {role.role_id: role for role in old_roles}
        role_id = UUID(row["role_id"])
        role = roles.get(role_id, Role(
            role_id, row["role_name"], bool(int(row["user_editable"])),
            tuple()))
        return tuple({
            **roles, role_id: Role(
                role.role_id, role.role_name, role.user_editable,
                role.privileges + (Privilege(
                    row["privilege_id"], row["privilege_description"]),))
        }.values())

    def __organise__(acc, row):
        resid = UUID(row["resource_id"])
        roles = acc.get(resid, {}).get("roles", tuple())
        return {
            **acc,
            resid: {
                "roles": __setup_roles__(roles, row)
            }
        }

    query = (
        "SELECT ur.user_id, ur.resource_id, r.*, p.* "
        "FROM user_roles AS ur "
        "INNER JOIN roles AS r ON ur.role_id=r.role_id "
        "INNER JOIN role_privileges AS rp ON r.role_id=rp.role_id "
        "INNER JOIN privileges AS p ON rp.privilege_id=p.privilege_id "
        "WHERE ur.user_id=?")
    params: tuple[str, ...] = (str(user.user_id),)

    if len(resource_ids) > 0:
        pholders = ", ".join(["?"] * len(resource_ids))
        query = f"{query} AND ur.resource_id IN ({pholders})"
        params = params + tuple(str(resid) for resid in resource_ids)

    with db.cursor(conn) as cursor:
        cursor.execute(query, params)
        return reduce(__organise__, cursor.fetchall(), {})


def get_resource_id(conn: db.DbConnection, name: str) -> Optional[str]:
    """Given a resource_name, return it's resource_id."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            "SELECT resource_id \
FROM resources as r WHERE r.resource_name=?", (name, ))
        if res := cursor.fetchone():
            return res["resource_id"]
    return None
