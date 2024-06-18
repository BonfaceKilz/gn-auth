"""Test functions dealing with group management."""
from uuid import UUID

import pytest
from pymonad.maybe import Nothing

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.errors import AuthorisationError
from gn_auth.auth.authentication.users import User
from gn_auth.auth.authorisation.roles import Role
from gn_auth.auth.authorisation.privileges import Privilege
from gn_auth.auth.authorisation.resources.groups.models import (
    Group, GroupRole, user_group, create_group, create_group_role)

from tests.unit.auth import conftest

create_group_failure = {
    "status": "error",
    "message": "Unauthorised: Failed to create group."
}

GROUP = Group(UUID("9988c21d-f02f-4d45-8966-22c968ac2fbf"), "TheTestGroup",
              {"group_description": "The test group"})
PRIVILEGES = (
    Privilege(
        "group:resource:view-resource",
        "view a resource and use it in computations"),
    Privilege("group:resource:edit-resource", "edit/update a resource"))

@pytest.mark.unit_test
@pytest.mark.parametrize(
    "user,expected", tuple(zip(conftest.TEST_USERS[0:1], (
        Group(
            UUID("d32611e3-07fc-4564-b56c-786c6db6de2b"), "a_test_group",
            {"group_description": "A test group"}),
        create_group_failure, create_group_failure, create_group_failure,
        create_group_failure))))
def test_create_group(# pylint: disable=[too-many-arguments]
        fxtr_app, auth_testdb_path, mocker, fxtr_users, fxtr_oauth2_clients, user, expected):# pylint: disable=[unused-argument]
    """
    GIVEN: an authenticated user
    WHEN: the user attempts to create a group
    THEN: verify they are only able to create the group if they have the
          appropriate privileges
    """
    _conn, clients = fxtr_oauth2_clients
    mocker.patch("gn_auth.auth.authorisation.resources.groups.models.uuid4", conftest.uuid_fn)
    mocker.patch(
        "gn_auth.auth.authorisation.checks.require_oauth.acquire",
        conftest.get_tokeniser(
            user,
            tuple(client for client in clients if client.user == user)[0]))
    with db.connection(auth_testdb_path) as conn:
        assert create_group(
            conn, "a_test_group", user, "A test group") == expected

@pytest.mark.unit_test
@pytest.mark.parametrize("user", conftest.TEST_USERS[1:])
def test_create_group_raises_exception_with_non_privileged_user(# pylint: disable=[too-many-arguments]
        fxtr_app, auth_testdb_path, mocker, fxtr_users, fxtr_oauth2_clients, user):# pylint: disable=[unused-argument]
    """
    GIVEN: an authenticated user, without appropriate privileges
    WHEN: the user attempts to create a group
    THEN: verify the system raises an exception
    """
    _conn, clients = fxtr_oauth2_clients
    mocker.patch("gn_auth.auth.authorisation.resources.groups.models.uuid4", conftest.uuid_fn)
    mocker.patch(
        "gn_auth.auth.authorisation.checks.require_oauth.acquire",
        conftest.get_tokeniser(
            user,
            tuple(client for client in clients if client.user == user)[0]))
    with db.connection(auth_testdb_path) as conn:
        with pytest.raises(AuthorisationError):
            assert create_group(conn, "a_test_group", user, "A test group")

create_role_failure = {
    "status": "error",
    "message": "Unauthorised: Could not create the group role"
}

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

@pytest.mark.unit_test
@pytest.mark.parametrize(
    "user,expected", tuple(zip(conftest.TEST_USERS[1:], (
        create_role_failure, create_role_failure, create_role_failure))))
def test_create_group_role_raises_exception_with_unauthorised_users(
        mocker, fxtr_users_in_group, fxtr_oauth2_clients, user, expected):
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
    with pytest.raises(AuthorisationError):
        assert create_group_role(
            conn, GROUP, "ResourceEditor", PRIVILEGES) == expected

@pytest.mark.unit_test
def test_create_multiple_groups(mocker, fxtr_users, fxtr_oauth2_clients):
    """
    GIVEN: An authenticated user with appropriate authorisation
    WHEN: The user attempts to create a new group, while being a member of an
      existing group
    THEN: The system should prevent that, and respond with an appropriate error
      message
    """
    _conn, clients = fxtr_oauth2_clients
    mocker.patch("gn_auth.auth.authorisation.resources.groups.models.uuid4", conftest.uuid_fn)
    user = User(
        UUID("ecb52977-3004-469e-9428-2a1856725c7f"), "group@lead.er",
        "Group Leader")
    mocker.patch(
        "gn_auth.auth.authorisation.checks.require_oauth.acquire",
        conftest.get_tokeniser(
            user,
            tuple(client for client in clients if client.user == user)[0]))
    conn, _test_users = fxtr_users
    # First time, successfully creates the group
    assert create_group(conn, "a_test_group", user) == Group(
        UUID("d32611e3-07fc-4564-b56c-786c6db6de2b"), "a_test_group",
        {})
    # subsequent attempts should fail
    with pytest.raises(AuthorisationError):
        create_group(conn, "another_test_group", user)

@pytest.mark.unit_test
@pytest.mark.parametrize(
    "user,expected",
    tuple(zip(
        conftest.TEST_USERS,
        (([Group(UUID("9988c21d-f02f-4d45-8966-22c968ac2fbf"), "TheTestGroup", {})] * 3)
         + [Nothing]))))
def test_user_group(fxtr_users_in_group, user, expected):
    """
    GIVEN: A bunch of registered users, some of whom are members of a group, and
      others are not
    WHEN: a particular user's group is requested,
    THEN: return a Maybe containing the group that the user belongs to, or
      Nothing
    """
    conn, _group, _users = fxtr_users_in_group
    assert (
        user_group(conn, user).maybe(Nothing, lambda val: val)
        == expected)
