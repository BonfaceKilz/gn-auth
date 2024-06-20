"""Fixtures and utilities for resource-related tests"""
import uuid

import pytest

from gn_auth.auth.db import sqlite3 as db
from gn_auth.auth.authorisation.resources import Resource, ResourceCategory


SYSTEM_CATEGORY = ResourceCategory(
    uuid.UUID("aa3d787f-af6a-44fa-9b0b-c82d40e54ad2"),
    "system",
    "The overall system.")
SYSTEM_RESOURCE = Resource(
    uuid.UUID("0248b289-b277-4eaa-8c94-88a434d14b6e"),
    "GeneNetwork System",
    SYSTEM_CATEGORY,
    True)

TEST_RESOURCES = (
    Resource(uuid.UUID("26ad1668-29f5-439d-b905-84d551f85955"),
             "ResourceG01R01",
             ResourceCategory(uuid.UUID("48056f84-a2a6-41ac-8319-0e1e212cba2a"),
                              "genotype", "Genotype Dataset"),
             True),
    Resource(uuid.UUID("2130aec0-fefd-434d-92fd-9ca342348b2d"),
             "ResourceG01R02",
             ResourceCategory(uuid.UUID("548d684b-d4d1-46fb-a6d3-51a56b7da1b3"),
                              "phenotype", "Phenotype (Publish) Dataset"),
             False),
    Resource(uuid.UUID("e9a1184a-e8b4-49fb-b713-8d9cbeea5b83"),
             "ResourceG01R03",
             ResourceCategory(uuid.UUID("fad071a3-2fc8-40b8-992b-cdefe7dcac79"),
                              "mrna", "mRNA Dataset"),
             False),
    Resource(uuid.UUID("14496a1c-c234-49a2-978c-8859ea274054"),
             "ResourceG02R01",
             ResourceCategory(uuid.UUID("48056f84-a2a6-41ac-8319-0e1e212cba2a"),
                              "genotype", "Genotype Dataset"),
             False),
    Resource(uuid.UUID("04ad9e09-94ea-4390-8a02-11f92999806b"),
             "ResourceG02R02",
             ResourceCategory(uuid.UUID("fad071a3-2fc8-40b8-992b-cdefe7dcac79"),
                              "mrna", "mRNA Dataset"),
             True))

TEST_RESOURCES_PUBLIC = (SYSTEM_RESOURCE, TEST_RESOURCES[0], TEST_RESOURCES[4])


@pytest.fixture(scope="function")
def fxtr_resources(conn_after_auth_migrations):
    """fixture: setup test resources in the database"""
    conn = conn_after_auth_migrations
    with db.cursor(conn) as cursor:
        cursor.executemany(
            "INSERT INTO resources VALUES (?,?,?,?)",
            ((str(res.resource_id), res.resource_name,
              str(res.resource_category.resource_category_id),
              1 if res.public else 0) for res in TEST_RESOURCES))

    yield (conn, TEST_RESOURCES)

    with db.cursor(conn) as cursor:
        cursor.executemany("DELETE FROM resources WHERE resource_id=?",
                           ((str(res.resource_id),) for res in TEST_RESOURCES))
