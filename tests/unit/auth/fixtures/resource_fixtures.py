"""Fixtures and utilities for resource-related tests"""
import pytest

from gn_auth.auth.db import sqlite3 as db

from .role_fixtures import RESOURCE_EDITOR_ROLE, RESOURCE_READER_ROLE
from .group_fixtures import (
    TEST_RESOURCES,
    TEST_GROUP_01,
    TEST_GROUP_02,
    TEST_RESOURCES_GROUP_01,
    TEST_RESOURCES_GROUP_02)

@pytest.fixture(scope="function")
def fxtr_resources(fxtr_group):# pylint: disable=[redefined-outer-name]
    """fixture: setup test resources in the database"""
    conn, _group = fxtr_group
    ownership = tuple({
        "group_id": str(TEST_GROUP_01.group_id),
        "resource_id": str(res.resource_id)
    } for res in TEST_RESOURCES_GROUP_01) + tuple({
        "group_id": str(TEST_GROUP_02.group_id),
        "resource_id": str(res.resource_id)
    } for res in TEST_RESOURCES_GROUP_02)

    with db.cursor(conn) as cursor:
        cursor.executemany(
            "INSERT INTO resources VALUES (?,?,?,?)",
        ((str(res.resource_id), res.resource_name,
          str(res.resource_category.resource_category_id),
          1 if res.public else 0) for res in TEST_RESOURCES))
        cursor.executemany(
            "INSERT INTO resource_ownership(group_id, resource_id) "
            "VALUES (:group_id, :resource_id)",
            ownership)

    yield (conn, TEST_RESOURCES)

    with db.cursor(conn) as cursor:
        cursor.executemany(
            "DELETE FROM resource_ownership "
            "WHERE group_id=:group_id AND resource_id=:resource_id",
            ownership)
        cursor.executemany("DELETE FROM resources WHERE resource_id=?",
                           ((str(res.resource_id),)
         for res in TEST_RESOURCES))


@pytest.fixture(scope="function")
def fxtr_resource_roles(fxtr_group, fxtr_resources, fxtr_roles):# pylint: disable=[redefined-outer-name,unused-argument]
    """Link roles to resources."""
    resource_roles = ({
        "resource_id": str(TEST_RESOURCES_GROUP_01[0].resource_id),
        "role_created_by": "ecb52977-3004-469e-9428-2a1856725c7f",
        "role_id": str(RESOURCE_EDITOR_ROLE.role_id)
    },{
        "resource_id": str(TEST_RESOURCES_GROUP_01[0].resource_id),
        "role_created_by": "ecb52977-3004-469e-9428-2a1856725c7f",
        "role_id": str(RESOURCE_READER_ROLE.role_id)
    })
    conn, groups = fxtr_group
    with db.cursor(conn) as cursor:
        cursor.executemany(
            "INSERT INTO resource_roles(resource_id, role_created_by, role_id) "
            "VALUES (:resource_id, :role_created_by, :role_id)",
            resource_roles)

    yield conn, groups, resource_roles

    with db.cursor(conn) as cursor:
        cursor.executemany(
            ("DELETE FROM resource_roles "
             "WHERE resource_id=:resource_id "
             "AND role_created_by=:role_created_by "
             "AND role_id=:role_id"),
            resource_roles)
