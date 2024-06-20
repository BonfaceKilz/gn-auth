"""Test resource-management functions"""
import uuid

import pytest

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.errors import AuthorisationError

from gn_auth.auth.authorisation.resources.groups import Group
from gn_auth.auth.authorisation.resources.models import (
    Resource, user_resources, create_resource, ResourceCategory,
    public_resources)

from tests.unit.auth import conftest

group = Group(uuid.UUID("9988c21d-f02f-4d45-8966-22c968ac2fbf"), "TheTestGroup",
              {})
resource_category = ResourceCategory(
    uuid.UUID("fad071a3-2fc8-40b8-992b-cdefe7dcac79"), "mrna", "mRNA Dataset")
create_resource_failure = {
    "status": "error",
    "message": "Unauthorised: Could not create resource"
}

@pytest.mark.unit_test
@pytest.mark.parametrize(
    "user,expected",
    tuple(zip(
        conftest.TEST_USERS[0:1],
        (Resource(
            uuid.UUID("d32611e3-07fc-4564-b56c-786c6db6de2b"),
            "test_resource", resource_category, False),))))
def test_create_resource(# pylint: disable=[too-many-arguments, unused-argument]
        mocker,
        fxtr_users_in_group,
        fxtr_resource_user_roles,
        fxtr_oauth2_clients,
        user,
        expected
):
    """Test that resource creation works as expected."""
    mocker.patch("gn_auth.auth.authorisation.resources.models.uuid4", conftest.uuid_fn)
    _conn, clients = fxtr_oauth2_clients
    mocker.patch(
        "gn_auth.auth.authorisation.checks.require_oauth.acquire",
        conftest.get_tokeniser(
            user,
            tuple(client for client in clients if client.user == user)[0]))
    conn, _group, _users = fxtr_users_in_group
    resource = create_resource(
        conn, "test_resource", resource_category, user, False)
    assert resource == expected

    with db.cursor(conn) as cursor:
        # Cleanup
        cursor.execute(
            "DELETE FROM user_roles WHERE resource_id=?",
            (str(resource.resource_id),))
        cursor.execute(
            "DELETE FROM resource_ownership WHERE resource_id=?",
            (str(resource.resource_id),))
        cursor.execute(
            "DELETE FROM resources WHERE resource_id=?",
            (str(resource.resource_id),))

@pytest.mark.unit_test
@pytest.mark.parametrize(
    "user,expected",
    tuple(zip(
        conftest.TEST_USERS[1:],
        (create_resource_failure, create_resource_failure,
         create_resource_failure))))
def test_create_resource_raises_for_unauthorised_users(
        mocker, fxtr_users_in_group, fxtr_oauth2_clients, user, expected):
    """Test that resource creation works as expected."""
    mocker.patch("gn_auth.auth.authorisation.resources.models.uuid4", conftest.uuid_fn)
    _conn, clients = fxtr_oauth2_clients
    mocker.patch(
        "gn_auth.auth.authorisation.checks.require_oauth.acquire",
        conftest.get_tokeniser(
            user,
            tuple(client for client in clients if client.user == user)[0]))
    conn, _group, _users = fxtr_users_in_group
    with pytest.raises(AuthorisationError):
        assert create_resource(
            conn, "test_resource", resource_category, user, False) == expected

def sort_key_resources(resource):
    """Sort-key for resources."""
    return resource.resource_id

PUBLIC_RESOURCES = sorted(
    conftest.TEST_RESOURCES_PUBLIC, key=sort_key_resources)

@pytest.mark.unit_test
def test_public_resources(fxtr_resources):
    """
    GIVEN: some resources in the database
    WHEN: public resources are requested
    THEN: only list the resources that are public
    """
    conn, _res = fxtr_resources
    assert sorted(
        public_resources(conn), key=sort_key_resources) == PUBLIC_RESOURCES

@pytest.mark.unit_test
@pytest.mark.parametrize(
    "user,expected",
    tuple(zip(
        conftest.TEST_USERS,
        (sorted(
            {res.resource_id: res for res in
             ((conftest.GROUP_RESOURCES[0],) +
              conftest.TEST_RESOURCES_GROUP_01 +
              conftest.TEST_RESOURCES_PUBLIC)}.values(),
            key=sort_key_resources),
         sorted(
             {res.resource_id: res for res in
              ((conftest.TEST_RESOURCES_GROUP_01[1],) +
               conftest.TEST_RESOURCES_PUBLIC)}.values()
             ,
             key=sort_key_resources),
         PUBLIC_RESOURCES, PUBLIC_RESOURCES))))
def test_user_resources(fxtr_resource_user_roles, user, expected):
    """
    GIVEN: some resources in the database
    WHEN: a particular user's resources are requested
    THEN: list only the resources for which the user can access
    """
    conn, *_others = fxtr_resource_user_roles
    assert sorted(
        {res.resource_id: res for res in user_resources(conn, user)
         }.values(), key=sort_key_resources) == expected
