"""
Similar to the 'assign_data_to_default_admin' script but without user
interaction.
"""
import sys
import logging
from pathlib import Path

import click
from gn_libs import mysqldb as biodb
from pymonad.maybe import Just, Maybe, Nothing
from pymonad.tools import monad_from_none_or_value

from gn_auth.auth.db import sqlite3 as authdb
from gn_auth.auth.authentication.users import User
from gn_auth.auth.authorisation.resources.groups.models import (
    Group, db_row_to_group)

from scripts.assign_data_to_default_admin import (
    default_resources, assign_data_to_resource)


def resources_group(conn: authdb.DbConnection) -> Maybe:
    """Retrieve resources' group"""
    with authdb.cursor(conn) as cursor:
        cursor.execute(
            "SELECT g.* FROM resources AS r "
            "INNER JOIN resource_ownership AS ro "
            "ON r.resource_id=ro.resource_id "
            "INNER JOIN groups AS g ON ro.group_id=g.group_id "
            "WHERE resource_name='mRNA-euhrin'")
        return monad_from_none_or_value(
            Nothing, Just, cursor.fetchone()).then(
                db_row_to_group)


def resource_owner(conn: authdb.DbConnection) -> Maybe:
    """Retrieve the resource owner."""
    with authdb.cursor(conn) as cursor:
        cursor.execute(
            "SELECT u.* FROM users AS u WHERE u.user_id IN "
            "(SELECT ur.user_id FROM resources AS rsc "
            "INNER JOIN user_roles AS ur ON rsc.resource_id=ur.resource_id "
            "INNER JOIN roles AS r on ur.role_id=r.role_id "
            "WHERE resource_name='mRNA-euhrin' "
            "AND r.role_name='resource-owner')")
        return monad_from_none_or_value(
            Nothing, Just, cursor.fetchone()).then(
                User.from_sqlite3_row)


def assign_data(authconn: authdb.DbConnection, bioconn, group: Group):
    """Do actual data assignments."""
    try:
        for resource in default_resources(authconn, group):
            assign_data_to_resource(authconn, bioconn, resource, group)

        return 1
    except Exception as _exc:# pylint: disable=[broad-except]
        logging.error("Failed to assign some data!", exc_info=True)
        return 1


if __name__ == "__main__":
    @click.command()
    @click.argument("authdbpath") # "Path to the Auth(entic|oris)ation database"
    @click.argument("mysqldburi") # "URI to the MySQL database with the biology data"
    @click.option("--loglevel",
                  default="WARNING",
                  show_default=True,
                  type=click.Choice([
                      "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]))
    def run(authdbpath, mysqldburi, loglevel):
        """Script entry point."""
        _logger = logging.getLogger()
        _logger.setLevel(loglevel)
        if Path(authdbpath).exists():
            with (authdb.connection(authdbpath) as authconn,
                  biodb.database_connection(mysqldburi) as bioconn):
                return resources_group(authconn).maybe(
                    1,
                    lambda group: assign_data(authconn, bioconn, group))

        logging.error("There is no such SQLite3 database file.")
        return 1

    sys.exit(run()) # pylint: disable=[no-value-for-parameter]
