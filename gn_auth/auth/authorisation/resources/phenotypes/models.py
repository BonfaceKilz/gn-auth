"""Phenotype data resources functions and utilities."""
import uuid
from functools import reduce
from typing import Optional, Sequence

import sqlite3
from pymonad.maybe import Just, Maybe, Nothing
from pymonad.tools import monad_from_none_or_value

import gn_auth.auth.db.sqlite3 as db
from gn_auth.auth.authorisation.resources.data import __attach_data__
from gn_auth.auth.authorisation.resources.base import Resource, resource_from_dbrow

def resource_data(
        cursor: db.DbCursor,
        resource_id: uuid.UUID,
        offset: int = 0,
        limit: Optional[int] = None) -> Sequence[sqlite3.Row]:
    """Fetch data linked to a Phenotype resource"""
    cursor.execute(
        ("SELECT * FROM phenotype_resources AS pr "
         "INNER JOIN linked_phenotype_data AS lpd "
         "ON pr.data_link_id=lpd.data_link_id "
         "WHERE pr.resource_id=?") + (
             f" LIMIT {limit} OFFSET {offset}" if bool(limit) else ""),
        (str(resource_id),))
    return cursor.fetchall()

def link_data_to_resource(
        conn: db.DbConnection,
        resource: Resource,
        data_link_id: uuid.UUID) -> dict:
    """Link Phenotype data with a resource."""
    with db.cursor(conn) as cursor:
        params = {
            "resource_id": str(resource.resource_id),
            "data_link_id": str(data_link_id)
        }
        cursor.execute(
            "INSERT INTO phenotype_resources VALUES"
            "(:resource_id, :data_link_id)",
            params)
        return params

def unlink_data_from_resource(
        conn: db.DbConnection,
        resource: Resource,
        data_link_id: uuid.UUID) -> dict:
    """Unlink data from Phenotype resources"""
    with db.cursor(conn) as cursor:
        cursor.execute("DELETE FROM phenotype_resources "
                       "WHERE resource_id=? AND data_link_id=?",
                       (str(resource.resource_id), str(data_link_id)))
        return {
            "resource_id": str(resource.resource_id),
            "dataset_type": resource.resource_category.resource_category_key,
            "data_link_id": str(data_link_id)
        }

def attach_resources_data(
        cursor, resources: Sequence[Resource]) -> Sequence[Resource]:
    """Attach linked data to Phenotype resources"""
    placeholders = ", ".join(["?"] * len(resources))
    cursor.execute(
        "SELECT * FROM phenotype_resources AS pr "
        "INNER JOIN linked_phenotype_data AS lpd "
        "ON pr.data_link_id=lpd.data_link_id "
        f"WHERE pr.resource_id IN ({placeholders})",
        tuple(str(resource.resource_id) for resource in resources))
    return __attach_data__(cursor.fetchall(), resources)


def individual_linked_resource(
        conn: db.DbConnection,
        species_id: int,
        population_id: int,
        dataset_id: int,
        xref_id: str) -> Maybe:
    """Given the data details, return the linked resource, if one is defined."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            "SELECT "
            "rsc.*, rc.*, lpd.SpeciesId AS species_id, "
            "lpd.InbredSetId AS population_id, lpd.PublishXRefId AS xref_id, "
            "lpd.dataset_name, lpd.dataset_fullname, lpd.dataset_shortname "
            "FROM linked_phenotype_data AS lpd "
            "INNER JOIN phenotype_resources AS pr "
            "ON lpd.data_link_id=pr.data_link_id "
            "INNER JOIN resources AS rsc ON pr.resource_id=rsc.resource_id "
            "INNER JOIN resource_categories AS rc "
            "ON rsc.resource_category_id=rc.resource_category_id "
            "WHERE "
            "(lpd.SpeciesId, lpd.InbredSetId, lpd.PublishFreezeId, lpd.PublishXRefId) = "
            "(?, ?, ?, ?)",
            (species_id, population_id, dataset_id, xref_id))
        return monad_from_none_or_value(
            Nothing, Just, cursor.fetchone()).then(resource_from_dbrow)


def all_linked_resources(
        conn: db.DbConnection,
        species_id: int,
        population_id: int,
        dataset_id: int) -> Maybe:
    """Given the data details, return the linked resource, if one is defined."""
    with db.cursor(conn) as cursor:
        cursor.execute(
            "SELECT rsc.*, rc.resource_category_key, "
            "rc.resource_category_description, lpd.SpeciesId AS species_id, "
            "lpd.InbredSetId AS population_id, lpd.PublishXRefId AS xref_id, "
            "lpd.dataset_name, lpd.dataset_fullname, lpd.dataset_shortname "
            "FROM linked_phenotype_data AS lpd "
            "INNER JOIN phenotype_resources AS pr "
            "ON lpd.data_link_id=pr.data_link_id INNER JOIN resources AS rsc "
            "ON pr.resource_id=rsc.resource_id "
            "INNER JOIN resource_categories AS rc "
            "ON rsc.resource_category_id=rc.resource_category_id "
            "WHERE "
            "(lpd.SpeciesId, lpd.InbredSetId, lpd.PublishFreezeId) = (?, ?, ?)",
            (species_id, population_id, dataset_id))

        _rscdatakeys = (
            "species_id", "population_id", "xref_id", "dataset_name",
            "dataset_fullname", "dataset_shortname")
        def __organise__(resources, row):
            _rscid = uuid.UUID(row["resource_id"])
            _resource = resources.get(_rscid, resource_from_dbrow(row))
            return {
                **resources,
                _rscid: Resource(
                    _resource.resource_id,
                    _resource.resource_name,
                    _resource.resource_category,
                    _resource.public,
                    _resource.resource_data + (
                             {key: row[key] for key in _rscdatakeys},))
            }
        results: dict[uuid.UUID, Resource] = reduce(
            __organise__, cursor.fetchall(), {})
        if len(results) == 0:
            return Nothing
        return Just(tuple(results.values()))
