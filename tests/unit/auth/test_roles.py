"""Test functions dealing with group management."""
import uuid

import pytest

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.errors import AuthorisationError
from gn_auth.auth.authorisation.privileges import Privilege
from gn_auth.auth.authorisation.roles.models import Role, user_roles, create_role

from tests.unit.auth import conftest
from tests.unit.auth.fixtures import TEST_USERS

create_role_failure = {
    "status": "error",
    "message": "Unauthorised: Could not create role"
}

PRIVILEGES = (
    Privilege("group:resource:view-resource",
              "view a resource and use it in computations"),
    Privilege("group:resource:edit-resource", "edit/update a resource"))

@pytest.mark.unit_test
@pytest.mark.parametrize(
    "user,expected", tuple(zip(conftest.TEST_USERS[0:1], (
        Role(uuid.UUID("d32611e3-07fc-4564-b56c-786c6db6de2b"), "a_test_role",
             True, PRIVILEGES),))))
def test_create_role(# pylint: disable=[too-many-arguments]
        fxtr_app, auth_testdb_path, mocker, fxtr_users, user, expected):# pylint: disable=[unused-argument]
    """
    GIVEN: an authenticated user
    WHEN: the user attempts to create a role
    THEN: verify they are only able to create the role if they have the
          appropriate privileges
    """
    mocker.patch("gn_auth.auth.authorisation.roles.models.uuid4", conftest.uuid_fn)
    mocker.patch("gn_auth.auth.authorisation.checks.require_oauth.acquire",
                 conftest.get_tokeniser(user))
    with db.connection(auth_testdb_path) as conn, db.cursor(conn) as cursor:
        the_role = create_role(cursor, "a_test_role", PRIVILEGES)
        assert the_role == expected

@pytest.mark.unit_test
@pytest.mark.parametrize(
    "user,expected", tuple(zip(conftest.TEST_USERS[1:], (
        create_role_failure, create_role_failure, create_role_failure))))
def test_create_role_raises_exception_for_unauthorised_users(# pylint: disable=[too-many-arguments]
        fxtr_app, auth_testdb_path, mocker, fxtr_users, user, expected):# pylint: disable=[unused-argument]
    """
    GIVEN: an authenticated user
    WHEN: the user attempts to create a role
    THEN: verify they are only able to create the role if they have the
          appropriate privileges
    """
    mocker.patch("gn_auth.auth.authorisation.roles.models.uuid4", conftest.uuid_fn)
    mocker.patch("gn_auth.auth.authorisation.checks.require_oauth.acquire",
                 conftest.get_tokeniser(user))
    with db.connection(auth_testdb_path) as conn, db.cursor(conn) as cursor:
        with pytest.raises(AuthorisationError):
            create_role(cursor, "a_test_role", PRIVILEGES)

@pytest.mark.unit_test
@pytest.mark.parametrize(
    "user,expected",
    (zip(TEST_USERS,
         (({"resource_id": uuid.UUID("38d1807d-105f-44a7-8327-7e2d973b6d8d"),
            "user_id": uuid.UUID("ecb52977-3004-469e-9428-2a1856725c7f"),
            "roles": (Role(
                role_id=uuid.UUID('a0e67630-d502-4b9f-b23f-6805d0f30e30'),
                role_name='group-leader', user_editable=False,
                privileges=(
                    Privilege(
                        privilege_id='group:resource:create-resource',
                        privilege_description='Create a resource object'),
                    Privilege(
                        privilege_id='group:resource:delete-resource',
                        privilege_description='Delete a resource'),
                    Privilege(
                        privilege_id='group:resource:edit-resource',
                        privilege_description='edit/update a resource'),
                    Privilege(
                        privilege_id='group:resource:view-resource',
                        privilege_description=(
                            'view a resource and use it in computations')),
                    Privilege(
                        privilege_id='group:role:create-role',
                        privilege_description='Create a new role'),
                    Privilege(
                        privilege_id='group:role:delete-role',
                        privilege_description='Delete an existing role'),
                    Privilege(
                        privilege_id='group:role:edit-role',
                        privilege_description='edit/update an existing role'),
                    Privilege(
                        privilege_id='group:user:add-group-member',
                        privilege_description='Add a user to a group'),
                    Privilege(
                        privilege_id='group:user:assign-role',
                        privilege_description=(
                            'Assign a role to an existing user')),
                    Privilege(
                        privilege_id='group:user:remove-group-member',
                        privilege_description='Remove a user from a group'),
                    Privilege(
                        privilege_id='system:group:delete-group',
                        privilege_description='Delete a group'),
                    Privilege(
                        privilege_id='system:group:edit-group',
                        privilege_description='Edit the details of a group'),
                    Privilege(
                        privilege_id='system:group:transfer-group-leader',
                        privilege_description=(
                            'Transfer leadership of the group to some other '
                            'member')),
                    Privilege(
                        privilege_id='system:group:view-group',
                        privilege_description='View the details of a group'),
                    Privilege(
                        privilege_id='system:user:list',
                        privilege_description='List users in the system'))),)
            },
           {
               "resource_id": uuid.UUID("0248b289-b277-4eaa-8c94-88a434d14b6e"),
               "user_id": uuid.UUID("ecb52977-3004-469e-9428-2a1856725c7f"),
               "roles": (Role(
                   role_id=uuid.UUID("ade7e6b0-ba9c-4b51-87d0-2af7fe39a347"),
                   role_name="group-creator",
                   user_editable=False,
                   privileges=(
                       Privilege(
                           privilege_id="system:group:create-group",
                           privilege_description="Create a group"),)),)}),
          ({"resource_id": uuid.UUID("2130aec0-fefd-434d-92fd-9ca342348b2d"),
            "user_id": uuid.UUID("21351b66-8aad-475b-84ac-53ce528451e3"),
            "roles": (Role(
                role_id=uuid.UUID('89819f84-6346-488b-8955-86062e9eedb7'),
                role_name='resource_editor',
                user_editable=True,
                privileges=(
                    Privilege(
                        privilege_id='group:resource:edit-resource',
                        privilege_description='edit/update a resource'),
                    Privilege(
                        privilege_id='group:resource:view-resource',
                        privilege_description='view a resource and use it in computations'))),)},),
          tuple(),
          tuple()))))
def test_user_roles(fxtr_group_user_roles, user, expected):
    """
    GIVEN: an authenticated user
    WHEN: we request the user's privileges
    THEN: return **ALL** the privileges attached to the user
    """
    conn, *_others = fxtr_group_user_roles
    assert user_roles(conn, user) == expected
