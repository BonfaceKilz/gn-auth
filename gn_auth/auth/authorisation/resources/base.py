"""Base types for resources."""
from uuid import UUID
from dataclasses import dataclass
from typing import Any, Sequence

import sqlite3


@dataclass(frozen=True)
class ResourceCategory:
    """Class representing a resource category."""
    resource_category_id: UUID
    resource_category_key: str
    resource_category_description: str


@dataclass(frozen=True)
class Resource:
    """Class representing a resource."""
    resource_id: UUID
    resource_name: str
    resource_category: ResourceCategory
    public: bool
    resource_data: Sequence[dict[str, Any]] = tuple()


def resource_from_dbrow(row: sqlite3.Row):
    """Convert an SQLite3 resultset row into a resource."""
    return Resource(
        resource_id=UUID(row["resource_id"]),
        resource_name=row["resource_name"],
        resource_category=ResourceCategory(
            UUID(row["resource_category_id"]),
            row["resource_category_key"],
            row["resource_category_description"]),
        public=bool(int(row["public"])))
