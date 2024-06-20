"""Fixtures and utilities for group-related tests"""
import uuid

import pytest

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.authorisation.resources.groups import Group
from gn_auth.auth.authorisation.resources import Resource, ResourceCategory

from .resource_fixtures import TEST_RESOURCES

TEST_GROUP_01 = Group(uuid.UUID("9988c21d-f02f-4d45-8966-22c968ac2fbf"),
                      "TheTestGroup", {})
TEST_GROUP_02 = Group(uuid.UUID("e37d59d7-c05e-4d67-b479-81e627d8d634"),
                      "AnotherTestGroup", {})
TEST_GROUPS = (TEST_GROUP_01, TEST_GROUP_02)

GROUP_CATEGORY = ResourceCategory(
    uuid.UUID("1e0f70ee-add5-4358-8c6c-43de77fa4cce"),
    "group",
    "A group resource.")
GROUPS_AS_RESOURCES = tuple({
    "group_id": str(group.group_id),
    "resource_id": res_id,
    "resource_name": group.group_name,
    "category_id": str(GROUP_CATEGORY.resource_category_id),
    "public": "0"
} for res_id, group in zip(
    ("38d1807d-105f-44a7-8327-7e2d973b6d8d",
     "89458ef6-e090-4b53-8c2c-59eaf2785f11"),
    TEST_GROUPS))
GROUP_RESOURCES = tuple(
    Resource(uuid.UUID(row["resource_id"]),
             row["resource_name"],
             GROUP_CATEGORY,
             False)
    for row in GROUPS_AS_RESOURCES)


TEST_RESOURCES_GROUP_01  = TEST_RESOURCES[0:3]
TEST_RESOURCES_GROUP_02  = TEST_RESOURCES[3:5]



def __gtuple__(cursor):
    return tuple(dict(row) for row in cursor.fetchall())

@pytest.fixture(scope="function")
def fxtr_group(conn_after_auth_migrations):# pylint: disable=[redefined-outer-name]
    """Fixture: setup a test group."""
    with db.cursor(conn_after_auth_migrations) as cursor:
        cursor.executemany(
            "INSERT INTO groups(group_id, group_name) VALUES (?, ?)",
            tuple(
                (str(group.group_id), group.group_name)
                for group in TEST_GROUPS))

        cursor.executemany(
            "INSERT INTO resources "
            "VALUES(:resource_id, :resource_name, :category_id, :public)",
            GROUPS_AS_RESOURCES)

        cursor.executemany(
            "INSERT INTO group_resources(resource_id, group_id) "
            "VALUES(:resource_id, :group_id)",
            GROUPS_AS_RESOURCES)

    yield (conn_after_auth_migrations, TEST_GROUPS[0])

    with db.cursor(conn_after_auth_migrations) as cursor:
        resource_id_params = tuple(
            (str(res["resource_id"]),) for res in GROUPS_AS_RESOURCES)
        cursor.executemany("DELETE FROM group_resources WHERE resource_id=?",
                           resource_id_params)
        cursor.executemany("DELETE FROM resources WHERE resource_id=?",
                           resource_id_params)
        cursor.executemany(
            "DELETE FROM groups WHERE group_id=?",
            ((str(group.group_id),) for group in TEST_GROUPS))


@pytest.fixture(scope="function")
def fxtr_resource_ownership(# pylint: disable=[redefined-outer-name]
        fxtr_resources, fxtr_group
):
    """fixture: Set up group ownership of resources."""
    _conn, resources = fxtr_resources
    conn, groups = fxtr_group
    ownership = tuple({
        "group_id": str(TEST_GROUP_01.group_id),
        "resource_id": str(res.resource_id)
    } for res in TEST_RESOURCES_GROUP_01) + tuple({
        "group_id": str(TEST_GROUP_02.group_id),
        "resource_id": str(res.resource_id)
    } for res in TEST_RESOURCES_GROUP_02)

    with db.cursor(conn) as cursor:
        cursor.executemany(
            "INSERT INTO resource_ownership(group_id, resource_id) "
            "VALUES (:group_id, :resource_id)",
            ownership)

    yield conn, resources, groups, ownership

    with db.cursor(conn) as cursor:
        cursor.executemany(
            "DELETE FROM resource_ownership "
            "WHERE group_id=:group_id AND resource_id=:resource_id",
            ownership)


@pytest.fixture(scope="function")
def fxtr_users_in_group(fxtr_group, fxtr_users):# pylint: disable=[redefined-outer-name, unused-argument]
    """Link the users to the groups."""
    conn, all_users = fxtr_users
    users = tuple(
        user for user in all_users if user.email not in ("unaff@iliated.user",))
    query_params = tuple(
        (str(TEST_GROUP_01.group_id), str(user.user_id)) for user in users)
    with db.cursor(conn) as cursor:
        cursor.executemany(
            "INSERT INTO group_users(group_id, user_id) VALUES (?, ?)",
            query_params)

    yield (conn, TEST_GROUP_01, users)

    with db.cursor(conn) as cursor:
        cursor.executemany(
            "DELETE FROM group_users WHERE group_id=? AND user_id=?",
            query_params)
