"""Tests for roles for a specific resource."""
from uuid import UUID

import pytest

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.authorisation.privileges import Privilege
from gn_auth.auth.authorisation.roles.models import Role, create_role
from gn_auth.auth.authorisation.resources.groups.models import (
    GroupRole,
    create_group_role)

from tests.unit.auth import conftest


GROUP = conftest.TEST_GROUP_01
PRIVILEGES = (
    Privilege("group:resource:view-resource",
              "view a resource and use it in computations"),
    Privilege("group:resource:edit-resource", "edit/update a resource"))


@pytest.mark.skip("Keep as placeholder until we implement test for creating "
                  "a resource role.")
@pytest.mark.unit_test
@pytest.mark.parametrize(
    "user,expected", tuple(zip(conftest.TEST_USERS[0:1], (
        GroupRole(
            UUID("d32611e3-07fc-4564-b56c-786c6db6de2b"),
            GROUP,
            Role(UUID("d32611e3-07fc-4564-b56c-786c6db6de2b"),
                 "ResourceEditor", True, PRIVILEGES)),))))
def test_create_group_role(mocker, fxtr_users_in_group, fxtr_oauth2_clients, user, expected):
    """
    GIVEN: an authenticated user
    WHEN: the user attempts to create a role, attached to a group
    THEN: verify they are only able to create the role if they have the
        appropriate privileges and that the role is attached to the given group
    """
    _conn, clients = fxtr_oauth2_clients
    mocker.patch("gn_auth.auth.authorisation.resources.groups.models.uuid4", conftest.uuid_fn)
    mocker.patch("gn_auth.auth.authorisation.roles.models.uuid4", conftest.uuid_fn)
    mocker.patch(
        "gn_auth.auth.authorisation.checks.require_oauth.acquire",
        conftest.get_tokeniser(
            user,
            tuple(client for client in clients if client.user == user)[0]))
    conn, _group, _users = fxtr_users_in_group
    with db.cursor(conn) as cursor:
        assert create_group_role(
            conn, GROUP, "ResourceEditor", PRIVILEGES) == expected
        # cleanup
        cursor.execute(
            ("DELETE FROM group_roles "
             "WHERE group_role_id=? AND group_id=? AND role_id=?"),
            (str(conftest.uuid_fn()), str(GROUP.group_id), str(conftest.uuid_fn())))


@pytest.mark.skip(
    "This needs to be replaced by tests for creation of resource roles.")
@pytest.mark.unit_test
@pytest.mark.parametrize(
    "user,expected", tuple(zip(conftest.TEST_USERS[0:1], (
        Role(UUID("d32611e3-07fc-4564-b56c-786c6db6de2b"), "a_test_role",
             True, PRIVILEGES),))))
def test_create_role(# pylint: disable=[too-many-arguments, unused-argument]
        fxtr_app,
        auth_testdb_path,
        mocker,
        fxtr_users,
        fxtr_oauth2_clients,
        user,
        expected
):
    """
    GIVEN: an authenticated user
    WHEN: the user attempts to create a role
    THEN: verify they are only able to create the role if they have the
          appropriate privileges
    """
    _conn, clients = fxtr_oauth2_clients
    mocker.patch("gn_auth.auth.authorisation.roles.models.uuid4", conftest.uuid_fn)
    mocker.patch(
        "gn_auth.auth.authorisation.checks.require_oauth.acquire",
        conftest.get_tokeniser(
            user,
            tuple(client for client in clients if client.user == user)[0]))
    with db.connection(auth_testdb_path) as conn, db.cursor(conn) as cursor:
        the_role = create_role(cursor, "a_test_role", PRIVILEGES)
        assert the_role == expected
