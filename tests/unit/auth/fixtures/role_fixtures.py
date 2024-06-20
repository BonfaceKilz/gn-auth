"""Fixtures and utilities for role-related tests"""
import uuid

import pytest

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.authorisation.roles import Role
from gn_auth.auth.authorisation.privileges import Privilege

from .user_fixtures import TEST_USERS
from .resource_fixtures import SYSTEM_RESOURCE, TEST_RESOURCES_PUBLIC
from .group_fixtures import (
    TEST_GROUP_01,
    TEST_RESOURCES_GROUP_01,
    TEST_RESOURCES_GROUP_02)

PUBLIC_VIEW_ROLE = Role(
    uuid.UUID("fd88bfed-d869-4969-87f2-67c4e8446ecb"),
    "public-view",
    False,
    (Privilege("group:resource:view-resource",
               "view a resource and use it in computations"),))

RESOURCE_READER_ROLE = Role(
    uuid.UUID("c3ca2507-ee24-4835-9b31-8c21e1c072d3"), "resource_reader",
    True,
    (Privilege("group:resource:view-resource",
               "view a resource and use it in computations"),))

RESOURCE_EDITOR_ROLE = Role(
    uuid.UUID("89819f84-6346-488b-8955-86062e9eedb7"),
    "resource_editor",
    True,
    (
        Privilege("group:resource:view-resource",
                  "view a resource and use it in computations"),
        Privilege("group:resource:edit-resource", "edit/update a resource")))

CREATE_GROUP_ROLE = Role(
    uuid.UUID("ade7e6b0-ba9c-4b51-87d0-2af7fe39a347"),
    "group-creator",
    False,
    (Privilege("system:group:create-group", "Create a group"),))

TEST_ROLES = (RESOURCE_READER_ROLE, RESOURCE_EDITOR_ROLE)

@pytest.fixture(scope="function")
def fxtr_roles(conn_after_auth_migrations):
    """Setup some example roles."""
    with db.cursor(conn_after_auth_migrations) as cursor:
        cursor.executemany(
            ("INSERT INTO roles VALUES (?, ?, ?)"),
            ((str(role.role_id), role.role_name, 1) for role in TEST_ROLES))
        cursor.executemany(
            ("INSERT INTO role_privileges VALUES (?, ?)"),
            ((str(role.role_id), str(privilege.privilege_id))
             for role in TEST_ROLES for privilege in role.privileges))

    yield conn_after_auth_migrations, TEST_ROLES

    with db.cursor(conn_after_auth_migrations) as cursor:
        cursor.executemany(
            ("DELETE FROM role_privileges WHERE role_id=? AND privilege_id=?"),
            ((str(role.role_id), str(privilege.privilege_id))
             for role in TEST_ROLES for privilege in role.privileges))
        cursor.executemany(
            ("DELETE FROM roles WHERE role_id=?"),
            ((str(role.role_id),) for role in TEST_ROLES))


@pytest.fixture(scope="function")
def fxtr_resource_roles(fxtr_resources, fxtr_roles):# pylint: disable=[redefined-outer-name,unused-argument]
    """Link roles to resources."""
    resource_roles = ({
        "resource_id": str(TEST_RESOURCES_GROUP_01[0].resource_id),
        "role_created_by": "ecb52977-3004-469e-9428-2a1856725c7f",
        "role_id": str(RESOURCE_EDITOR_ROLE.role_id)
    },{
        "resource_id": str(TEST_RESOURCES_GROUP_01[0].resource_id),
        "role_created_by": "ecb52977-3004-469e-9428-2a1856725c7f",
        "role_id": str(RESOURCE_READER_ROLE.role_id)
    }, {
        "resource_id": str(TEST_RESOURCES_GROUP_02[1].resource_id),
        "role_created_by": "ecb52977-3004-469e-9428-2a1856725c7f",
        "role_id": str(RESOURCE_EDITOR_ROLE.role_id)
    },{
        "resource_id": str(TEST_RESOURCES_GROUP_02[1].resource_id),
        "role_created_by": "ecb52977-3004-469e-9428-2a1856725c7f",
        "role_id": str(RESOURCE_READER_ROLE.role_id)
    })

    conn, resources = fxtr_resources
    with db.cursor(conn) as cursor:
        cursor.executemany(
            "INSERT INTO resource_roles(resource_id, role_created_by, role_id) "
            "VALUES (:resource_id, :role_created_by, :role_id)",
            resource_roles)

    yield conn, resources, resource_roles

    with db.cursor(conn) as cursor:
        cursor.executemany(
            ("DELETE FROM resource_roles "
             "WHERE resource_id=:resource_id "
             "AND role_created_by=:role_created_by "
             "AND role_id=:role_id"),
            resource_roles)


@pytest.fixture(scope="function")
def fxtr_setup_group_leaders(fxtr_users):
    """Define what roles users have that target resources of type 'Group'."""
    conn, users = fxtr_users
    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM group_resources")
        g01res_id = {
            row["group_id"]: row["resource_id"]
            for row in cursor.fetchall()
        }[str(TEST_GROUP_01.group_id)]
        test_user_roles = ({
            "user_id": "ecb52977-3004-469e-9428-2a1856725c7f",
            "role_id": "a0e67630-d502-4b9f-b23f-6805d0f30e30",# group-leader
            "resource_id": g01res_id
        },)
        cursor.executemany(
            "INSERT INTO user_roles(user_id, role_id, resource_id) "
            "VALUES (:user_id, :role_id, :resource_id)",
            test_user_roles)

    yield conn, users

    with db.cursor(conn) as cursor:
        cursor.executemany(
            "DELETE FROM user_roles WHERE user_id=:user_id "
            "AND role_id=:role_id AND resource_id=:resource_id",
            test_user_roles)


@pytest.fixture(scope="function")
def fxtr_system_roles(fxtr_users):
    """Define what roles users have that target resources of type 'Group'."""
    conn, users = fxtr_users
    with db.cursor(conn) as cursor:
        cursor.execute("SELECT * FROM resources WHERE resource_name='GeneNetwork System'")
        sysres_id = cursor.fetchone()["resource_id"]
        test_user_roles = tuple({
            "user_id": str(user.user_id),
            "role_id": str(PUBLIC_VIEW_ROLE.role_id),
            "resource_id": sysres_id
        } for user in TEST_USERS)
        cursor.executemany(
            "INSERT INTO user_roles(user_id, role_id, resource_id) "
            "VALUES (:user_id, :role_id, :resource_id)",
            test_user_roles)

    yield conn, users

    with db.cursor(conn) as cursor:
        cursor.executemany(
            "DELETE FROM user_roles WHERE user_id=:user_id "
            "AND role_id=:role_id AND resource_id=:resource_id",
            test_user_roles)


@pytest.fixture(scope="function")
def fxtr_resource_user_roles(# pylint: disable=[too-many-arguments, too-many-locals]
        fxtr_resources,
        fxtr_users_in_group,
        fxtr_resource_ownership,
        fxtr_resource_roles,
        fxtr_setup_group_leaders,
        fxtr_system_roles
):#pylint: disable=[redefined-outer-name,unused-argument]
    """Assign roles to users."""
    _conn, group_resources = fxtr_resources
    _conn, _resources, _groups, group_resources = fxtr_resource_ownership
    _conn, _group, group_users = fxtr_users_in_group
    conn, _groups, resource_roles = fxtr_resource_roles

    users_roles_resources = (
        # Give access to group leader to all resources in their group
        tuple((TEST_USERS[0], RESOURCE_EDITOR_ROLE, resource)
              for resource in TEST_RESOURCES_GROUP_01)
        # Set group member as resource editor
        + ((TEST_USERS[1], RESOURCE_EDITOR_ROLE, TEST_RESOURCES_GROUP_01[1]),)
        # Set group-creator role on the unaffiliated user
        + ((TEST_USERS[3], CREATE_GROUP_ROLE, SYSTEM_RESOURCE),)
        # Set roles for public resources
        + tuple(
            (user, PUBLIC_VIEW_ROLE, resource)
            for user in TEST_USERS for resource in TEST_RESOURCES_PUBLIC[1:]))
    with db.cursor(conn) as cursor:
        params = tuple({
            "user_id": str(user.user_id),
            "role_id": str(role.role_id),
            "resource_id": str(resource.resource_id)
        } for user, role, resource in users_roles_resources)
        cursor.executemany(
            ("INSERT INTO user_roles "
             "VALUES (:user_id, :role_id, :resource_id)"),
            params)

    yield conn, group_users, resource_roles, group_resources

    with db.cursor(conn) as cursor:
        cursor.executemany(
            ("DELETE FROM user_roles WHERE "
             "user_id=:user_id AND role_id=:role_id AND "
             "resource_id=:resource_id"),
            params)
