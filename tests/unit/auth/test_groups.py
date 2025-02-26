"""Test functions dealing with group management."""
from uuid import UUID

import pytest
from pymonad.maybe import Nothing

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.errors import AuthorisationError
from gn_auth.auth.authorisation.privileges import Privilege
from gn_auth.auth.authorisation.resources.groups.models import (
    Group, user_group, create_group, create_group_role)

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
@pytest.mark.parametrize("user", tuple(conftest.TEST_USERS[0:3]))
def test_create_group_fails(# pylint: disable=[too-many-arguments too-many-positional-arguments]
        fxtr_app, auth_testdb_path, mocker, fxtr_resource_user_roles, fxtr_oauth2_clients, user):# pylint: disable=[unused-argument]
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
        with pytest.raises(AuthorisationError):
            create_group(conn, "a_test_group", user, "A test group")


def __cleanup_create_group__(conn, user, group):
    """Cleanup creating a group..."""
    # cleanup: This should probably go into a 'delete_group(…) function'
    with db.cursor(conn) as cursor:
        cursor.execute("DELETE FROM group_users WHERE group_id=? AND user_id=?",
                       (str(group.group_id), str(user.user_id)))
        cursor.execute("SELECT * FROM group_resources WHERE group_id=?",
                       (str(group.group_id),))
        grp_rsc = cursor.fetchone()
        cursor.execute(
            "DELETE FROM user_roles WHERE user_id=? AND resource_id=?",
            (str(user.user_id), str(grp_rsc["resource_id"])))
        cursor.execute("DELETE FROM group_resources WHERE group_id=?",
                       (str(group.group_id),))
        cursor.execute("DELETE FROM groups WHERE group_id=?",
                       (str(group.group_id),))


@pytest.mark.unit_test
@pytest.mark.parametrize(
    "user,expected",
    ((conftest.TEST_USERS[3], Group(
        UUID("d32611e3-07fc-4564-b56c-786c6db6de2b"), "a_test_group",
        {"group_description": "A test group"})),))
def test_create_group_succeeds(# pylint: disable=[too-many-arguments too-many-positional-arguments, unused-argument]
        fxtr_app,
        auth_testdb_path,
        mocker,
        fxtr_resource_user_roles,
        fxtr_oauth2_clients,
        user,
        expected
):
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
        created_group = create_group(
            conn, "a_test_group", user, "A test group")
        assert created_group == expected
        __cleanup_create_group__(conn, user, created_group)


@pytest.mark.unit_test
@pytest.mark.parametrize("user", conftest.TEST_USERS[1:])
def test_create_group_raises_exception_with_non_privileged_user(# pylint: disable=[too-many-arguments too-many-positional-arguments]
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
def test_create_multiple_groups(mocker, fxtr_resource_user_roles, fxtr_oauth2_clients):
    """
    GIVEN: An authenticated user with appropriate authorisation
    WHEN: The user attempts to create a new group, while being a member of an
      existing group
    THEN: The system should prevent that, and respond with an appropriate error
      message
    """
    _conn, clients = fxtr_oauth2_clients
    mocker.patch("gn_auth.auth.authorisation.resources.groups.models.uuid4", conftest.uuid_fn)
    user = conftest.TEST_USERS[3]
    mocker.patch(
        "gn_auth.auth.authorisation.checks.require_oauth.acquire",
        conftest.get_tokeniser(
            user,
            tuple(client for client in clients if client.user == user)[0]))
    conn, *_test_users = fxtr_resource_user_roles
    # First time, successfully creates the group
    created_group = create_group(conn, "a_test_group", user)
    assert created_group == Group(
        UUID("d32611e3-07fc-4564-b56c-786c6db6de2b"), "a_test_group",
        {})
    # subsequent attempts should fail
    with pytest.raises(AuthorisationError):
        create_group(conn, "another_test_group", user)

    __cleanup_create_group__(conn, user, created_group)

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
