"""Fixtures and utilities for user-related tests"""
import uuid

import pytest

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.authentication.users import User, hash_password

TEST_USERS = (
        User(uuid.UUID("ecb52977-3004-469e-9428-2a1856725c7f"), "group@lead.er",
             "Group Leader"),
        User(uuid.UUID("21351b66-8aad-475b-84ac-53ce528451e3"),
             "group@mem.ber01", "Group Member 01"),
        User(uuid.UUID("ae9c6245-0966-41a5-9a5e-20885a96bea7"),
             "group@mem.ber02", "Group Member 02"),
        User(uuid.UUID("9a0c7ce5-2f40-4e78-979e-bf3527a59579"),
             "unaff@iliated.user", "Unaffiliated User"))

@pytest.fixture(scope="function")
def fxtr_users(conn_after_auth_migrations, fxtr_group):# pylint: disable=[redefined-outer-name, unused-argument]
    """Fixture: setup test users."""
    query = "INSERT INTO users(user_id, email, name) VALUES (?, ?, ?)"
    with db.cursor(conn_after_auth_migrations) as cursor:
        cursor.executemany(query, (
            (str(user.user_id), user.email, user.name) for user in TEST_USERS))

    yield (conn_after_auth_migrations, TEST_USERS)

    with db.cursor(conn_after_auth_migrations) as cursor:
        cursor.executemany(
            "DELETE FROM user_roles WHERE user_id=?",
            (("ecb52977-3004-469e-9428-2a1856725c7f",),))
        cursor.executemany(
            "DELETE FROM users WHERE user_id=?",
            (("ecb52977-3004-469e-9428-2a1856725c7f",),
             ("21351b66-8aad-475b-84ac-53ce528451e3",),
             ("ae9c6245-0966-41a5-9a5e-20885a96bea7",),
             ("9a0c7ce5-2f40-4e78-979e-bf3527a59579",)))

@pytest.fixture(scope="function")
def fxtr_users_with_passwords(fxtr_users): # pylint: disable=[redefined-outer-name]
    """Fixture: add passwords to the users"""
    conn, users = fxtr_users
    user_passwords_params = tuple(
        (str(user.user_id), hash_password(
            f"password_for_user_{idx:03}".encode("utf8")))
        for idx, user in enumerate(users, start=1))

    with db.cursor(conn) as cursor:
        cursor.executemany(
            "INSERT INTO user_credentials VALUES (?, ?)",
            user_passwords_params)

    yield conn, users

    with db.cursor(conn) as cursor:
        cursor.executemany(
            "DELETE FROM user_credentials WHERE user_id=?",
            ((item[0],) for item in user_passwords_params))
