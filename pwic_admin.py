# Pwic.wiki server running on Python and SQLite
# Copyright (C) 2020-2024 Alexandre Bréard
#
#   https://pwic.wiki
#   https://github.com/gitbra/pwic
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from typing import Any, Dict, List, Optional, Tuple, Union
import argparse
import sqlite3
import gzip
import datetime
import sys
import os
import ssl
from os import chmod, listdir, makedirs, mkdir, removedirs, rename, rmdir, system
from os.path import getsize, isdir, isfile, join, splitext
from shutil import copyfile, copyfileobj
from subprocess import call
from stat import S_IREAD
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlencode, urlparse
from http.client import RemoteDisconnected
import imagesize
from prettytable import PrettyTable
import pyotp

from pwic_lib import PwicConst, PwicLib
from pwic_extension import PwicExtension


class PwicAdmin():
    ''' Administration tools for Pwic.wiki '''

    # ======
    #  Main
    # ======

    def __init__(self):
        self.db = None

    def main(self) -> bool:
        # Default encoding
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except AttributeError:
            pass

        # Check root
        try:
            if os.geteuid() == 0:
                print('Error: Pwic.wiki cannot be administrated with the root account')
                return False
        except AttributeError:
            pass    # No check on Windows

        # Prepare the command line (subparsers cannot be grouped)
        parser = argparse.ArgumentParser(prog='python3 pwic_admin.py', description=f'Pwic.wiki Management Console v{PwicConst.VERSION}')

        subparsers = parser.add_subparsers(dest='command')

        # ... Initialization
        subparsers.add_parser('init-db', help='Initialize the database once')

        spb = subparsers.add_parser('show-env', help='Show the current configuration')
        spb.add_argument('--project', default='', help='Name of the project')
        spb.add_argument('--var', default='', help='Name of the variable for exclusive display')
        spb.add_argument('--list', action='store_true', help='Show the result in a list')

        spb = subparsers.add_parser('set-env', help='Set a global or a project-dependent parameter')
        spb.add_argument('--project', default='', help='Name of the project (if project-dependent)')
        spb.add_argument('name', default='', help='Name of the variable')
        spb.add_argument('value', default='', help='Value of the variable')
        spb.add_argument('--override', action='store_true', help='Remove the existing project-dependent values')
        spb.add_argument('--append', action='store_true', help='Append the value to the existing one')
        spb.add_argument('--remove', action='store_true', help='Remove the value from the existing one')

        spb = subparsers.add_parser('repair-env', help='Fix the incorrect environment variables')
        spb.add_argument('--test', action='store_true', help='Verbose simulation')

        subparsers.add_parser('show-mime', help='Show the MIME types defined on the server (Windows only)')

        # ... Projects
        subparsers.add_parser('show-projects', help='Show the existing projects')

        spb = subparsers.add_parser('create-project', help='Create a new project')
        spb.add_argument('project', default='', help='Project name')
        spb.add_argument('description', default='', help='Project description')
        spb.add_argument('admin', default='', help='User name of the administrator of the project')

        spb = subparsers.add_parser('takeover-project', help='Assign an administrator to a project')
        spb.add_argument('project', default='', help='Project name')
        spb.add_argument('admin', default='', help='User name of the administrator')

        spb = subparsers.add_parser('split-project', help='Copy a project into a dedicated database')
        spb.add_argument('--no-history', action='store_true', help='Remove the history')
        spb.add_argument('project', nargs='+', default='', help='Project name')

        spb = subparsers.add_parser('delete-project', help='Delete an existing project (irreversible)')
        spb.add_argument('project', default='', help='Project name')

        # ... Users
        spb = subparsers.add_parser('list-users', help='List the user accounts')
        spb.add_argument('--project', default='', help='Name of the project (if project-dependent)')

        spb = subparsers.add_parser('show-user', help='Show the current roles for one user')
        spb.add_argument('user', default='', help='User name')

        spb = subparsers.add_parser('create-user', help='Create a user with no assignment to a project')
        spb.add_argument('user', default='', help='User name')
        spb.add_argument('--totp', action='store_true', help='Enable 2FA TOTP for the user')

        spb = subparsers.add_parser('reset-password', help='Reset the password of a user')
        spb.add_argument('user', default='', help='User name')
        spb.add_argument('--create', action='store_true', help='Create the user account if needed')
        spb.add_argument('--oauth', action='store_true', help='Force the federated authentication')

        spb = subparsers.add_parser('reset-totp', help="Reset the user's secret key of the 2FA authentication")
        spb.add_argument('user', default='', help='User name')
        spb.add_argument('--disable', action='store_true', help='Turn off 2FA TOTP')

        spb = subparsers.add_parser('assign-user', help='Assign a user to a project as a reader')
        spb.add_argument('project', default='', help='Project name')
        spb.add_argument('user', default='', help='User name')

        spb = subparsers.add_parser('revoke-user', help='Revoke a user')
        spb.add_argument('user', default='', help='User name')
        spb.add_argument('--force', action='store_true', help='Force the operation despite the user can be the sole administrator of a project')

        # ... Maintenance
        spb = subparsers.add_parser('show-audit', help='Show the log of the database (no HTTP traffic)')
        spb.add_argument('--min', type=int, default=30, help='From MIN days in the past', metavar='30')
        spb.add_argument('--max', type=int, default=0, help='To MAX days in the past', metavar='0')

        spb = subparsers.add_parser('show-login', help='Show the last logins of the users')
        spb.add_argument('--days', type=int, default=30, help='Number of days in the past', metavar='30')

        subparsers.add_parser('show-stats', help='Show some statistics')

        spb = subparsers.add_parser('show-inactivity', help='Show the inactive users who have a write access')
        spb.add_argument('--project', default='', help='Name of the project (if project-dependent)')
        spb.add_argument('--days', type=int, default=90, help='Number of days in the past', metavar='90')

        spb = subparsers.add_parser('compress-static', help='Compress the static files for a faster delivery (optional)')
        spb.add_argument('--revert', action='store_true', help='Revert the operation')

        spb = subparsers.add_parser('clear-cache', help='Clear the cache of the pages (required after upgrade or restoration)')
        spb.add_argument('--project', default='', help='Name of the project (if project-dependent)')
        spb.add_argument('--selective', action='store_true', help='Keep the latest pages in cache')

        spb = subparsers.add_parser('regenerate-cache', help='Regenerate the cache of the pages through mass HTTP requests')
        spb.add_argument('--project', default='', help='Name of the project (if project-dependent)')
        spb.add_argument('--user', default='', help='User account to access some private projects')
        spb.add_argument('--full', action='store_true', help='Include the revisions (not recommended)')
        spb.add_argument('--port', type=int, default=PwicConst.DEFAULTS['port'], help='Target instance defined by the listened port', metavar=PwicConst.DEFAULTS['port'])

        spb = subparsers.add_parser('rotate-logs', help='Rotate Pwic.wiki\'s HTTP log files')
        spb.add_argument('--count', type=int, default=9, help='Number of log files', metavar='9')

        spb = subparsers.add_parser('archive-audit', help='Clean the obsolete entries of audit')
        spb.add_argument('--selective', type=int, default=90, help='Horizon for a selective cleanup', metavar='90')
        spb.add_argument('--complete', type=int, default=0, help='Horizon for a complete cleanup', metavar='365')

        spb = subparsers.add_parser('show-git', help='Show the current git version')
        spb.add_argument('--agree', action='store_true', help='If you understand what this command does')

        subparsers.add_parser('create-backup', help='Make a backup copy of the database file *without* the attached documents')

        spb = subparsers.add_parser('repair-documents', help='Repair the index of the documents (recommended after the database is restored)')
        spb.add_argument('--project', default='', help='Name of the project (if project-dependent)')
        spb.add_argument('--no-hash', action='store_true', help='Do not recalculate the hashes of the files (faster but not recommended)')
        spb.add_argument('--no-magic', action='store_true', help='Do not verify the magic bytes of the files')
        spb.add_argument('--keep-orphans', action='store_true', help='Do not delete the orphaned folders and files')
        spb.add_argument('--test', action='store_true', help='Verbose simulation')

        subparsers.add_parser('execute-optimize', help='Run the optimizer')

        spb = subparsers.add_parser('unlock-db', help='Unlock the database after an internal Python error')
        spb.add_argument('--port', type=int, default=PwicConst.DEFAULTS['port'], help='Target instance defined by the listened port', metavar=PwicConst.DEFAULTS['port'])
        spb.add_argument('--force', action='store_true', help='No confirmation')

        spb = subparsers.add_parser('execute-sql', help='Execute an SQL query on the database (dangerous)')
        spb.add_argument('--file', default='', help='SQL query from file')

        spb = subparsers.add_parser('shutdown-server', help='Terminate the server')
        spb.add_argument('--port', type=int, default=PwicConst.DEFAULTS['port'], help='Target instance defined by the listened port', metavar=PwicConst.DEFAULTS['port'])
        spb.add_argument('--force', action='store_true', help='No confirmation')

        # Parse the command line
        args = parser.parse_args()
        if args.command == 'init-db':
            return self.init_db()
        if args.command == 'show-env':
            return self.show_env(args.project, args.var, args.list)
        if args.command == 'set-env':
            return self.set_env(args.project, args.name, args.value, args.override, args.append, args.remove)
        if args.command == 'repair-env':
            return self.repair_env(args.test)
        if args.command == 'show-mime':
            return self.show_mime()
        if args.command == 'show-projects':
            return self.show_projects()
        if args.command == 'create-project':
            return self.create_project(args.project, args.description, args.admin)
        if args.command == 'takeover-project':
            return self.takeover_project(args.project, args.admin)
        if args.command == 'split-project':
            return self.split_project(args.project, args.no_history)
        if args.command == 'delete-project':
            return self.delete_project(args.project)
        if args.command == 'list-users':
            return self.list_users(args.project)
        if args.command == 'show-user':
            return self.show_user(args.user)
        if args.command == 'create-user':
            return self.create_user(args.user, args.totp)
        if args.command == 'reset-password':
            return self.reset_password(args.user, args.create, args.oauth)
        if args.command == 'reset-totp':
            return self.reset_totp(args.user, args.disable)
        if args.command == 'assign-user':
            return self.assign_user(args.project, args.user)
        if args.command == 'revoke-user':
            return self.revoke_user(args.user, args.force)
        if args.command == 'show-audit':
            return self.show_audit(args.min, args.max)
        if args.command == 'show-login':
            return self.show_login(args.days)
        if args.command == 'show-stats':
            return self.show_stats()
        if args.command == 'show-inactivity':
            return self.show_inactivity(args.project, args.days)
        if args.command == 'compress-static':
            return self.compress_static(args.revert)
        if args.command == 'clear-cache':
            return self.clear_cache(args.project, args.selective)
        if args.command == 'regenerate-cache':
            return self.regenerate_cache(args.project, args.user, args.full, args.port)
        if args.command == 'rotate-logs':
            return self.rotate_logs(args.count)
        if args.command == 'archive-audit':
            return self.archive_audit(args.selective, args.complete)
        if args.command == 'show-git':
            return self.show_git(args.agree)
        if args.command == 'create-backup':
            return self.create_backup()
        if args.command == 'repair-documents':
            return self.repair_documents(args.project, args.no_hash, args.no_magic, args.keep_orphans, args.test)
        if args.command == 'execute-optimize':
            return self.execute_optimize()
        if args.command == 'unlock-db':
            return self.unlock_db(args.port, args.force)
        if args.command == 'execute-sql':
            return self.execute_sql(args.file)
        if args.command == 'shutdown-server':
            return self.shutdown_server(args.port, args.force)

        # Default behavior
        parser.print_help()
        return False

    def _prepare_prettytable(self, fields: List[str], header: bool = True, border: bool = True) -> PrettyTable:
        tab = PrettyTable()
        tab.header = header
        tab.border = border
        tab.field_names = fields
        for f in tab.field_names:
            tab.align[f] = 'l'
        return tab

    # ==========
    #  Database
    # ==========

    def db_connect(self, init: bool = False, dbfile: str = PwicConst.DB_SQLITE) -> Optional[sqlite3.Cursor]:
        if not init and not isfile(dbfile):
            print('Error: the database is not created yet')
            return None
        try:
            self.db, sql = PwicLib.connect(dbfile=dbfile,
                                           dbaudit=PwicConst.DB_SQLITE_AUDIT if dbfile == PwicConst.DB_SQLITE else None)
            return sql
        except sqlite3.OperationalError:
            print('Error: the database cannot be opened')
            return None

    def db_lock(self, sql: sqlite3.Cursor) -> bool:
        if sql is None:
            return False
        try:
            sql.execute(''' BEGIN EXCLUSIVE TRANSACTION''')
            return True
        except sqlite3.OperationalError:
            return False

    def db_create_tables_audit(self) -> bool:
        sql = self.db_connect(init=True, dbfile=PwicConst.DB_SQLITE_AUDIT)
        if sql is None:
            return False

        # Table AUDIT
        sql.execute(''' CREATE TABLE "audit" (
                            "id" INTEGER NOT NULL,
                            "date" TEXT NOT NULL,
                            "time" TEXT NOT NULL,
                            "author" TEXT NOT NULL,
                            "event" TEXT NOT NULL,
                            "user" TEXT NOT NULL DEFAULT '',
                            "project" TEXT NOT NULL DEFAULT '',
                            "page" TEXT NOT NULL DEFAULT '',
                            "reference" INTEGER NOT NULL DEFAULT 0,
                            "string" TEXT NOT NULL DEFAULT '',
                            "ip" TEXT NOT NULL DEFAULT '',
                            PRIMARY KEY("id" AUTOINCREMENT)
                        )''')
        sql.execute(''' CREATE INDEX "audit_index" ON "audit" (
                            "date",
                            "project"
                        )''')
        sql.execute(''' CREATE TABLE "audit_arch" (
                            "id" INTEGER NOT NULL,
                            "date" TEXT NOT NULL,
                            "time" TEXT NOT NULL,
                            "author" TEXT NOT NULL,
                            "event" TEXT NOT NULL,
                            "user" TEXT NOT NULL,
                            "project" TEXT NOT NULL,
                            "page" TEXT NOT NULL,
                            "reference" INTEGER NOT NULL,
                            "string" TEXT NOT NULL,
                            "ip" TEXT NOT NULL,
                            PRIMARY KEY("id")       -- No AUTOINCREMENT
                        )''')

        # Triggers
        sql.execute(''' CREATE TRIGGER audit_no_update
                            BEFORE UPDATE ON audit
                        BEGIN
                            SELECT RAISE (ABORT, 'The table AUDIT should not be modified');
                        END''')
        sql.execute(''' CREATE TRIGGER audit_archiver
                            BEFORE DELETE ON audit
                        BEGIN
                            INSERT INTO audit_arch
                                SELECT *
                                FROM audit
                                WHERE id = OLD.id;
                        END''')
        self.db_commit()
        return True

    def db_create_tables_main(self, dbfile: str = PwicConst.DB_SQLITE) -> bool:
        sql = self.db_connect(init=True, dbfile=dbfile)
        if sql is None:
            return False
        dt = PwicLib.dt()

        # Table PROJECTS
        sql.execute(''' CREATE TABLE "projects" (
                            "project" TEXT NOT NULL,
                            "description" TEXT NOT NULL,
                            "date" TEXT NOT NULL,
                            PRIMARY KEY("project")
                        )''')
        sql.execute(''' INSERT INTO projects (project, description, date)
                        VALUES ('', '', ?)''',
                    (dt['date'], ))

        # Table ENV
        sql.execute(''' CREATE TABLE "env" (
                            "project" TEXT NOT NULL,    -- Never default to ''
                            "key" TEXT NOT NULL,
                            "value" TEXT NOT NULL,
                            FOREIGN KEY("project") REFERENCES "projects"("project"),
                            PRIMARY KEY("key","project")
                        )''')

        # Table USERS
        sql.execute(''' CREATE TABLE "users" (
                            "user" TEXT NOT NULL,
                            "password" TEXT NOT NULL,
                            "initial" TEXT NOT NULL CHECK("initial" IN ('', 'X')),
                            "totp" TEXT NOT NULL,
                            "password_date" TEXT NOT NULL,
                            "password_time" TEXT NOT NULL,
                            PRIMARY KEY("user")
                        )''')
        for e in ['', PwicConst.USERS['anonymous'], PwicConst.USERS['ghost']]:
            sql.execute(''' INSERT INTO users (user, password, initial, totp, password_date, password_time)
                            VALUES (?, '', '', '', ?, ?)''',
                        (e, dt['date'], dt['time']))

        # Table ROLES
        sql.execute(''' CREATE TABLE "roles" (
                            "project" TEXT NOT NULL,
                            "user" TEXT NOT NULL,
                            "admin" TEXT NOT NULL DEFAULT '' CHECK("admin" IN ('', 'X') AND ("admin" = "X" OR "manager" = "X" OR "editor" = "X" OR "validator" = "X" OR "reader" = "X")),
                            "manager" TEXT NOT NULL DEFAULT '' CHECK("manager" IN ('', 'X')),
                            "editor" TEXT NOT NULL DEFAULT '' CHECK("editor" IN ('', 'X')),
                            "validator" TEXT NOT NULL DEFAULT '' CHECK("validator" IN ('', 'X')),
                            "reader" TEXT NOT NULL DEFAULT '' CHECK("reader" IN ('', 'X')),
                            "disabled" TEXT NOT NULL DEFAULT '' CHECK("disabled" IN ('', 'X')),
                            FOREIGN KEY("project") REFERENCES "projects"("project"),
                            FOREIGN KEY("user") REFERENCES "users"("user"),
                            PRIMARY KEY("user","project")
                        )''')

        # Table PAGES
        sql.execute(''' CREATE TABLE "pages" (
                            "project" TEXT NOT NULL,
                            "page" TEXT NOT NULL CHECK("page" <> ''),
                            "revision" INTEGER NOT NULL CHECK("revision" > 0),
                            "latest" TEXT NOT NULL DEFAULT 'X' CHECK("latest" IN ('', 'X')),
                            "draft" TEXT NOT NULL DEFAULT '' CHECK("draft" IN ('', 'X')),
                            "final" TEXT NOT NULL DEFAULT '' CHECK("final" IN ('', 'X')),
                            "header" TEXT NOT NULL DEFAULT '' CHECK("header" IN ('', 'X')),
                            "protection" TEXT NOT NULL DEFAULT '' CHECK("protection" IN ('', 'X')),
                            "author" TEXT NOT NULL CHECK("author" <> ''),
                            "date" TEXT NOT NULL CHECK("date" <> ''),
                            "time" TEXT NOT NULL CHECK("time" <> ''),
                            "title" TEXT NOT NULL CHECK("title" <> ''),
                            "markdown" TEXT NOT NULL DEFAULT '',
                            "tags" TEXT NOT NULL DEFAULT '',
                            "comment" TEXT NOT NULL CHECK("comment" <> ''),
                            "milestone" TEXT NOT NULL DEFAULT '',
                            "valuser" TEXT NOT NULL DEFAULT '',
                            "valdate" TEXT NOT NULL DEFAULT '',
                            "valtime" TEXT NOT NULL DEFAULT '',
                            PRIMARY KEY("project","page","revision"),
                            FOREIGN KEY("author") REFERENCES "users"("user"),
                            FOREIGN KEY("valuser") REFERENCES "users"("user"),
                            FOREIGN KEY("project") REFERENCES "projects"("project")
                        )''')
        sql.execute(''' CREATE INDEX "pages_index" ON "pages" (
                            "project",
                            "page",
                            "latest"
                        )''')

        # Table CACHE
        sql.execute(''' CREATE TABLE "cache" (
                            "project" TEXT NOT NULL,
                            "page" TEXT NOT NULL,
                            "revision" INTEGER NOT NULL,
                            "html" TEXT NOT NULL,
                            FOREIGN KEY("project") REFERENCES "projects"("project"),
                            PRIMARY KEY("project","page","revision")
                        )''')

        # Table DOCUMENTS
        sql.execute(''' CREATE TABLE "documents" (
                            "id" INTEGER NOT NULL,
                            "project" TEXT NOT NULL CHECK("project" <> ''),
                            "page" TEXT NOT NULL CHECK("page" <> ''),
                            "filename" TEXT NOT NULL CHECK("filename" <> ''),
                            "mime" TEXT NOT NULL CHECK("mime" <> ''),
                            "size" INTEGER NOT NULL CHECK("size" > 0),
                            "width" INTEGER NOT NULL CHECK("width" >= 0),
                            "height" INTEGER NOT NULL CHECK("height" >= 0),
                            "hash" TEXT NOT NULL DEFAULT '' CHECK("hash" <> ''),
                            "author" TEXT NOT NULL CHECK("author" <> ''),
                            "date" TEXT NOT NULL CHECK("date" <> ''),
                            "time" TEXT NOT NULL CHECK("time" <> ''),
                            "exturl" TEXT NOT NULL,
                            FOREIGN KEY("project") REFERENCES "projects"("project"),
                            FOREIGN KEY("author") REFERENCES "users"("user"),
                            PRIMARY KEY("id" AUTOINCREMENT),
                            UNIQUE("project","filename")
                        )''')
        self.db_commit()
        return True

    def db_commit(self) -> None:
        if self.db is not None:
            self.db.commit()

    def db_rollback(self) -> None:
        if self.db is not None:
            self.db.rollback()

    def db_sql2table(self, sql: sqlite3.Cursor) -> Optional[PrettyTable]:
        tab = None
        for row in sql.fetchall():
            if tab is None:
                tab = self._prepare_prettytable([k[:1].upper() + k[1:] for k in row])
            tab.add_row([str(row[k]).replace('\r', '').replace('\n', ' ').strip()[:255].strip() for k in row])
        return tab

    # =========
    #  Methods
    # =========

    def init_db(self) -> bool:
        # Check that the database does not exist already
        if not isdir(PwicConst.DB):
            mkdir(PwicConst.DB)
        if isfile(PwicConst.DB_SQLITE) or isfile(PwicConst.DB_SQLITE_AUDIT):
            print('Error: the databases are already created')
            return False

        # Create the dbfiles
        ok = self.db_create_tables_audit() and self.db_create_tables_main()     # Audit first
        if not ok:
            print('Error: the databases cannot be created')
            return False

        # Connect to the databases
        sql = self.db_connect()
        if sql is None:
            print('Error: the databases cannot be opened')
            return False

        # Add the default, safe or mandatory configuration
        PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                            'event': 'init-db'})
        for (key, value) in [('base_url', f'http://127.0.0.1:{PwicConst.DEFAULTS["port"]}')]:
            sql.execute(''' INSERT INTO env (project, key, value)
                            VALUES ('', ?, ?)''',
                        (key, value))
            PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                                'event': f'set-{key}',
                                'string': '' if PwicConst.ENV[key].private else value})

        # Confirmation
        self.db_commit()
        print(f'The databases are created in "{PwicConst.DB_SQLITE}" and "{PwicConst.DB_SQLITE_AUDIT}"')
        return True

    def show_env(self, project: str, var: str, dolist: bool) -> bool:
        # Package info
        if var == '':
            try:
                from importlib.metadata import PackageNotFoundError, version
                print('Python packages:')
                tab = self._prepare_prettytable(['Package', 'Version'])
                tab.align['Version'] = 'r'
                for package in ['aiohttp', 'aiohttp-cors', 'aiohttp-session', 'cryptography', 'imagesize',
                                'jinja2', 'PrettyTable', 'pygments', 'pyotp']:
                    try:
                        tab.add_row([package, version(package)])
                    except PackageNotFoundError:
                        pass
                print(tab.get_string())
            except ImportError:
                pass

        # Environment variables
        sql = self.db_connect()
        if sql is None:
            return False
        print('\nGlobal and project-dependent variables:')
        if var != '':
            sql.execute(''' SELECT project, key, value
                            FROM env
                            WHERE key LIKE ?
                              AND value <> ''
                            ORDER BY project, key''',
                        ('%%%s%%' % var.replace('*', '%'), ))
        else:
            sql.execute(''' SELECT project, key, value
                            FROM env
                            WHERE value <> ''
                            ORDER BY project, key''')
        ok = False
        tab = self._prepare_prettytable(['Project', 'Key', 'Value'])
        for row in sql.fetchall():
            if (project != '') and (row['project'] not in ['', project]):
                continue
            value = row['value']
            if (row['key'] in PwicConst.ENV) and PwicConst.ENV[row['key']].private:
                value = '(Secret value not displayed)'
            value = value.replace('\r', '').replace('\n', '\\n')
            if dolist:
                print(f'{row["project"] or "*"}.{row["key"]} = {value}')
            else:
                tab.add_row([row['project'], row['key'], value])
            ok = True
        if tab.rowcount > 0:
            print(tab.get_string())
        return ok

    def set_env(self, project: str, key: str, value: str, override: bool, append: bool, remove: bool) -> bool:
        # Check the parameters
        if override and (project != ''):
            print('Error: useless parameter --override if a project is indicated')
            return False
        if append and remove:
            print('Error: the options append and remove cannot be used together')
            return False
        allkeys = list(PwicConst.ENV)
        if key not in allkeys:
            print('Error: the name of the variable must be one of "%s"' % ', '.join(allkeys))
            return False
        if (project != '') and not PwicConst.ENV[key].pdep:
            print('Error: the parameter is not project-dependent')
            return False
        if (project == '') and not PwicConst.ENV[key].pindep:
            print('Error: the parameter is not project-independent')
            return False
        value = value.replace('\r', '').strip()

        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Adapt the value
        current = str(PwicLib.option(sql, project, key, ''))
        if remove:
            value = current.replace(value, '').replace('  ', ' ').strip()
        elif append:
            value = f'{current} {value}'.strip()

        # Reset the project-dependent values if --override
        if override:
            sql.execute(''' SELECT project
                            FROM env
                            WHERE project <> ''
                              AND key      = ?''',
                        (key, ))
            for row in sql.fetchall():
                PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                                    'event': f'unset-{key}',
                                    'project': row['project']})
            sql.execute(''' DELETE FROM env WHERE key = ?''', (key, ))

        # Update the variable
        if value == '':
            sql.execute(''' DELETE FROM env
                            WHERE project = ?
                              AND key     = ?''',
                        (project, key))
            verb = 'deleted'
        else:
            sql.execute(''' INSERT OR REPLACE INTO env (project, key, value)
                            VALUES (?, ?, ?)''',
                        (project, key, value))
            verb = 'updated'
        PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                            'event': '%sset-%s' % ('un' if value == '' else '', key),
                            'project': project,
                            'string': '' if PwicConst.ENV[key].private else value})
        self.db_commit()
        if project != '':
            print(f'Variable {verb} for the project "{project}"')
        else:
            print(f'Variable {verb} globally')
        return True

    def repair_env(self, test: bool) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Analyze each variables
        all_keys = list(PwicConst.ENV)
        buffer = []
        sql.execute(''' SELECT project, key, value
                        FROM env
                        ORDER BY project, key''')
        for row in sql.fetchall():
            if (((row['key'] not in all_keys)
                 or ((row['project'] != '') and not PwicConst.ENV[row['key']].pdep)
                 or ((row['project'] == '') and not PwicConst.ENV[row['key']].pindep)
                 or (row['value'] in [None, '']))):
                buffer.append((row['project'], row['key']))
        if not test:
            for e in buffer:
                sql.execute(''' DELETE FROM env
                                WHERE project = ?
                                  AND key     = ?''', e)
                PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                                    'event': f'unset-{e[1]}',
                                    'project': e[0]})
            self.db_commit()

        # Report
        if len(buffer) == 0:
            print('No change is required.')
        else:
            if test:
                print('List of the options to be deleted:')
            else:
                print('List of the deleted options:')
            tab = self._prepare_prettytable(['Project', 'Variable'])
            tab.add_rows(buffer)
            print(tab.get_string())
        return True

    def show_mime(self) -> bool:
        # Load the platform-dependent library
        try:
            import winreg
            win = True
        except ImportError:
            win = False

        # Mime types for Linux
        if not win:
            system('cat /etc/mime.types')
            return True

        # Buffer
        tab = self._prepare_prettytable(['Extension', 'MIME'])
        tab.sortby = 'Extension'

        # Read all the file extensions
        root = winreg.HKEY_CLASSES_ROOT
        for i in range(winreg.QueryInfoKey(root)[0]):
            name = winreg.EnumKey(root, i)
            if name[:1] == '.':

                # Read the declared content type
                handle = winreg.OpenKey(root, name)
                try:
                    value, typ = winreg.QueryValueEx(handle, 'Content Type')
                except FileNotFoundError:
                    value, typ = None, winreg.REG_NONE
                winreg.CloseKey(handle)

                # Consider the mime if it exists
                if typ == winreg.REG_SZ:
                    tab.add_row([name, value])

        # Final output
        print(tab.get_string())
        return True

    def show_projects(self) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Select the projects
        sql.execute(''' SELECT a.project, a.description, b.user
                        FROM projects AS a
                            LEFT OUTER JOIN roles AS b
                                ON  b.project  = a.project
                                AND b.admin    = 'X'
                                AND b.disabled = ''
                        WHERE a.project <> ''
                        ORDER BY a.project ASC,
                                 b.user    ASC''')
        data = {}
        for row in sql.fetchall():
            if row['project'] not in data:
                data[row['project']] = {'description': row['description'],
                                        'admin': []}
            if row['user'] is not None:
                data[row['project']]['admin'].append(row['user'])

        # Display the entries
        tab = self._prepare_prettytable(['Project', 'Description', 'Administrators', 'Count'])
        for key in data:
            tab.add_row([key, data[key]['description'], ', '.join(data[key]['admin']), len(data[key]['admin'])])
        print(tab.get_string())
        return True

    def create_project(self, project: str, description: str, admin: str) -> bool:
        # Check the arguments
        project = PwicLib.safe_name(project)
        description = description.strip()
        admin = PwicLib.safe_user_name(admin)
        if (((project in PwicConst.NOT_PROJECT)
             or ('' in [description, admin])
             or (project[:4] == 'pwic')
             or (admin[:4] == 'pwic'))):
            print('Error: invalid arguments')
            return False

        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False
        dt = PwicLib.dt()

        # Verify that the project does not exist yet
        sql.execute(''' SELECT project FROM projects WHERE project = ?''', (project, ))
        if sql.fetchone() is not None:
            print('Error: the project already exists')
            return False

        # Create the workspace for the documents of the project
        try:
            path = PwicConst.DOCUMENTS_PATH % project
            if not isdir(path):
                makedirs(path)
        except OSError:
            print(f'Error: impossible to create "{path}"')
            return False

        # Add the user account
        sql.execute(''' INSERT OR IGNORE INTO users (user, password, initial, totp, password_date, password_time)
                        VALUES (?, ?, 'X', '', ?, ?)''',
                    (admin, PwicLib.sha256(PwicConst.DEFAULTS['password']), dt['date'], dt['time']))
        if sql.rowcount > 0:
            PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                                'event': 'create-user',
                                'user': admin})

        # Add the project
        sql.execute(''' INSERT INTO projects (project, description, date) VALUES (?, ?, ?)''',
                    (project, description, dt['date']))
        PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                            'event': 'create-project',
                            'project': project})

        # Add the role
        sql.execute(''' INSERT INTO roles (project, user, admin) VALUES (?, ?, 'X')''', (project, admin))
        PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                            'event': 'grant-admin',
                            'project': project,
                            'user': admin})
        sql.execute(''' INSERT INTO roles (project, user, reader, disabled) VALUES (?, ?, 'X', 'X')''', (project, PwicConst.USERS['anonymous']))
        sql.execute(''' INSERT INTO roles (project, user, reader, disabled) VALUES (?, ?, 'X', 'X')''', (project, PwicConst.USERS['ghost']))

        # Add a default homepage
        sql.execute(''' INSERT INTO pages (project, page, revision, latest, header, author, date, time, title, markdown, comment)
                        VALUES (?, ?, 1, 'X', 'X', ?, ?, ?, 'Home', 'Thanks for using **Pwic.wiki**. This is the homepage.', 'Initial commit')''',
                    (project, PwicConst.DEFAULTS['page'], admin, dt['date'], dt['time']))
        PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                            'event': 'create-revision',
                            'project': project,
                            'page': PwicConst.DEFAULTS['page'],
                            'reference': 1})

        # Finalization
        self.db_commit()
        print('The project is created:')
        print(f'- Project       : {project}')
        print(f'- Administrator : {admin}')
        print(f'- Password      : "{PwicConst.DEFAULTS["password"]}" or the existing password')
        print('')
        print('WARNING:')
        print("To create new pages in the project, you must change your password and grant the role 'manager' or 'editor' to the suitable user account.")
        print('')
        print('Thanks for using Pwic.wiki!')
        return True

    def takeover_project(self, project: str, admin: str) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Verify that the project exists
        project = PwicLib.safe_name(project)
        if project == '' or sql.execute(''' SELECT project
                                            FROM projects
                                            WHERE project = ?''',
                                        (project, )).fetchone() is None:
            print(f'Error: the project "{project}" does not exist')
            return False

        # Verify that the user is valid and has changed his password
        admin = PwicLib.safe_user_name(admin)
        if admin[:4] == 'pwic':
            return False
        if sql.execute(''' SELECT user
                           FROM users
                           WHERE user    = ?
                             AND initial = '' ''',
                       (admin, )).fetchone() is None:
            print(f'Error: the user "{admin}" is unknown or has not changed his password yet')
            return False

        # Assign the user to the project
        if not self.db_lock(sql):
            return False
        sql.execute(''' UPDATE roles
                        SET admin    = 'X',
                            disabled = ''
                        WHERE project = ?
                          AND user    = ?''',
                    (project, admin))
        if sql.rowcount == 0:
            sql.execute(''' INSERT INTO roles (project, user, admin) VALUES (?, ?, 'X')''', (project, admin))
        PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                            'event': 'grant-admin',
                            'project': project,
                            'user': admin})
        self.db_commit()
        print(f'The user "{admin}" is now an administrator of the project "{project}"')
        return True

    def split_project(self, projects: List[str], collapse: bool) -> bool:
        # Helpers
        def _transfer_record(sql: sqlite3.Cursor, table: str, row: Dict[str, Any]) -> None:
            for k in row:
                if isinstance(row[k], bool):
                    row[k] = PwicLib.x(row[k])
            query = ''' INSERT OR REPLACE INTO %s
                        (%s) VALUES (%s)''' % (table,
                                               ', '.join(row.keys()),
                                               ', '.join('?' * len(row)))
            sql.execute(query, list(row.values()))

        # Connect to the database
        sql = self.db_connect()             # Don't lock this connection
        if sql is None:
            return False

        # Fetch the projects
        projects = sorted(set(projects))
        if len(projects) == 0:
            return False
        for p in projects:
            sql.execute(''' SELECT project
                            FROM projects
                            WHERE project = ?''',
                        (p, ))
            if (sql.fetchone() is None) or (p != PwicLib.safe_name(p)):
                print(f'Error: unknown project "{p}"')
                return False

        # Create the new database
        fn = PwicConst.DB_SQLITE_BACKUP % 'split'
        if isfile(fn):
            print(f'Error: the split database "{fn}" already exists')
            return False
        if not self.db_create_tables_main(fn):
            print('Error: the tables cannot be created in the the split database')
            return False
        try:
            newsql = sqlite3.connect(fn).cursor()
        except sqlite3.OperationalError:
            print('Error: the split database cannot be opened')
            return False

        # Transfer the data
        if not self.db_lock(sql):
            return False
        # ... projects
        for p in projects:
            row = sql.execute(''' SELECT *
                                  FROM projects
                                  WHERE project = ?''',
                              (p, )).fetchone()
            _transfer_record(newsql, 'projects', row)
        # ... users
        buffer = []
        for p in projects:
            sql.execute(''' SELECT DISTINCT user
                            FROM (	SELECT user
                                    FROM roles
                                    WHERE project = ?
                                UNION
                                    SELECT DISTINCT valuser AS user
                                    FROM pages
                                    WHERE project  = ?
                                      AND valuser <> ''
                                )
                            WHERE user NOT LIKE 'pwic%'
                            ORDER BY user''',
                        (p, p))
            for row in sql.fetchall():
                if row['user'] not in buffer:
                    buffer.append(row['user'])
        for e in buffer:
            sql.execute(''' SELECT *
                            FROM users
                            WHERE user = ?''',
                        (e, ))
            for row in sql.fetchall():
                _transfer_record(newsql, 'users', row)
        # ... roles
        for p in projects:
            sql.execute(''' SELECT *
                            FROM roles
                            WHERE project = ?''',
                        (p, ))
            for row in sql.fetchall():
                _transfer_record(newsql, 'roles', row)
        # ... env
        for p in ([''] + projects):
            sql.execute(''' SELECT *
                            FROM env
                            WHERE project = ?
                              AND key     NOT LIKE 'pwic%'
                              AND value   <> '' ''',
                        (p, ))
            for row in sql.fetchall():
                _transfer_record(newsql, 'env', row)
        # ... pages
        for p in projects:
            keep_last = collapse and (PwicLib.option(sql, p, 'validated_only') is None)
            sql.execute(''' SELECT *
                            FROM pages
                            WHERE project = ?''',
                        (p, ))
            for row in sql.fetchall():
                if keep_last:
                    if not row['latest']:
                        continue
                    row['revision'] = 1
                _transfer_record(newsql, 'pages', row)
        # ... documents
        for p in projects:
            sql.execute(''' SELECT *
                            FROM documents
                            WHERE project = ?''',
                        (p, ))
            for row in sql.fetchall():
                _transfer_record(newsql, 'documents', row)
        # ... custom copy
        PwicExtension.on_admin_split_project(sql, newsql, projects)

        # Result
        newsql.execute(''' COMMIT''')
        for p in projects:
            PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                                'event': 'split-project',
                                'project': p})
        self.db_commit()
        print('The projects "%s" are copied into the separate database "%s" without the audit data and the file documents.' % (', '.join(projects), fn))
        return True

    def delete_project(self, project: str) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Verify that the project exists yet
        project = PwicLib.safe_name(project)
        if (project == '') or (sql.execute(''' SELECT project FROM projects WHERE project = ?''', (project, )).fetchone() is None):
            print(f'Error: the project "{project}" does not exist')
            return False

        # Confirm
        print('This operation is IRREVERSIBLE. You loose all the pages and the uploaded documents.')
        print(f'Type "YES" in uppercase to confirm the deletion of the project "{project}": ', end='')
        if input() != 'YES':
            return False

        # Remove the uploaded files
        if not self.db_lock(sql):
            return False
        sql.execute(''' SELECT id, page, filename, exturl
                        FROM documents
                        WHERE project = ?''',
                    (project, ))
        for row in sql.fetchall():
            fn = join(PwicConst.DOCUMENTS_PATH % project, row['filename'])
            if not PwicExtension.on_api_document_delete(sql, None, project, PwicConst.USERS['system'], row['page'], row['id'], row['filename']):
                print(f'Error: unable to delete "{fn}"')
                self.db_rollback()
                return False
            if row['exturl'] == '':
                try:
                    os.remove(fn)
                except OSError:
                    if isfile(fn):
                        print(f'Error: unable to delete "{fn}"')
                        self.db_rollback()
                        return False

        # Remove the folder of the project used to upload files
        try:
            fn = PwicConst.DOCUMENTS_PATH % project
            rmdir(fn)
        except OSError:
            print(f'Error: unable to remove "{fn}". The folder may be not empty')
            self.db_rollback()
            return False

        # Delete
        sql.execute(''' DELETE FROM env       WHERE project = ?''', (project, ))
        sql.execute(''' DELETE FROM documents WHERE project = ?''', (project, ))
        sql.execute(''' DELETE FROM cache     WHERE project = ?''', (project, ))
        sql.execute(''' DELETE FROM pages     WHERE project = ?''', (project, ))
        sql.execute(''' DELETE FROM roles     WHERE project = ?''', (project, ))
        sql.execute(''' DELETE FROM projects  WHERE project = ?''', (project, ))
        PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                            'event': 'delete-project',
                            'project': project})
        self.db_commit()
        print(f'\nThe project "{project}" is deleted')
        print('Warning: the file structure is now inconsistent with the old backups (if any)')
        return True

    def list_users(self, project: str) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Fetch the users
        project = PwicLib.safe_name(project)
        if project == '':
            sql.execute(''' SELECT user, IIF(password == ?, 'True', 'False') AS oauth,
                                   IIF(totp == '', 'False', 'True') AS totp,
                                   initial, password_date, password_time
                            FROM users
                            WHERE user <> ''
                            ORDER BY user''',
                        (PwicConst.MAGIC_OAUTH, ))
        else:
            sql.execute(''' SELECT a.user, IIF(a.password == ?, 'True', 'False') AS oauth,
                                   IIF(totp == '', 'False', 'True') AS totp,
                                   a.initial, a.password_date, a.password_time, b.disabled
                            FROM users AS a
                                INNER JOIN roles AS b
                                    ON b.user = a.user
                            WHERE a.user    <> ''
                              AND b.project  = ?
                            ORDER BY a.user''',
                        (PwicConst.MAGIC_OAUTH, project))

        # Show the list
        tab = self.db_sql2table(sql)
        if tab is not None:
            print(tab.get_string())
            print(f'\n{tab.rowcount} entries found.')
            return True
        return False

    def show_user(self, user: str) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Display the user
        sql.execute(''' SELECT project, admin, manager, editor, validator, reader, disabled
                        FROM roles
                        WHERE user = ?
                        ORDER BY disabled  ASC,
                                 admin     DESC,
                                 manager   DESC,
                                 editor    DESC,
                                 validator DESC,
                                 reader    DESC,
                                 project   ASC''',
                    (PwicLib.safe_user_name(user), ))
        tab = self.db_sql2table(sql)
        if tab is not None:
            print(tab.get_string())
            return True
        return False

    def create_user(self, user: str, totp: bool) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Verify the user account
        user = PwicLib.safe_user_name(user)
        if user[:4] in ['', 'pwic']:
            print('Error: invalid user')
            return False
        sql.execute(''' SELECT 1
                        FROM users
                        WHERE user = ?''',
                    (user, ))
        if sql.fetchone() is not None:
            print(f'Error: the user "{user}" exists already')
            return False

        # Create the user account
        dt = PwicLib.dt()
        sql.execute(''' INSERT INTO users (user, password, initial, totp, password_date, password_time)
                        VALUES (?, ?, 'X', '', ?, ?)''',
                    (user, PwicLib.sha256(PwicConst.DEFAULTS['password']), dt['date'], dt['time']))
        PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                            'event': 'create-user',
                            'user': user})
        self.db_commit()
        print(f'The user "{user}" is created with the default password "{PwicConst.DEFAULTS["password"]}".')

        # TOTP
        if totp:
            return self.reset_totp(user, False)
        return True

    def reset_password(self, user: str, create: bool, oauth: bool) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Warn if the user is an administrator
        user = PwicLib.safe_user_name(user)
        new_account = sql.execute(''' SELECT 1 FROM users WHERE user = ?''', (user, )).fetchone() is None
        if (user[:4] in ['', 'pwic']) or (not create and new_account):
            print('Error: invalid user')
            return False
        sql.execute(''' SELECT 1
                        FROM roles
                        WHERE user  = ?
                          AND admin = 'X'
                        LIMIT 1''',
                    (user, ))
        if sql.fetchone() is not None:
            print(f'The user "{user}" has administrative rights on some projects')

        # Ask for a new password
        if oauth:
            if '@' not in user:
                print('Error: the user account is not an email')
                return False
            print('The user must use the federated authentication to log in')
            pwd = PwicConst.MAGIC_OAUTH
            initial = False
        else:
            print('Type the new temporary password with 8 characters at least: ', end='')
            pwd = input().strip()
            if len(pwd) < 8:
                print('Error: the password is too short')
                return False
            pwd = PwicLib.sha256(pwd)
            initial = True

        # Reset the password with no rights takedown else some projects may loose their administrators
        dt = PwicLib.dt()
        if new_account:
            sql.execute(''' INSERT INTO users (user, password, initial, totp, password_date, password_time)
                            VALUES (?, ?, ?, '', ?, ?)''',
                        (user, pwd, PwicLib.x(initial), dt['date'], dt['time']))
            PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                                'event': 'create-user',
                                'user': user})
            print(f'\nThe password has been defined for the new user "{user}"')
        else:
            sql.execute(''' UPDATE users
                            SET password      = ?,
                                initial       = ?,
                                password_date = ?,
                                password_time = ?
                            WHERE user = ?''',
                        (pwd, PwicLib.x(initial), dt['date'], dt['time'], user))
            PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                                'event': 'reset-password',
                                'user': user,
                                'string': PwicConst.MAGIC_OAUTH if pwd == PwicConst.MAGIC_OAUTH else ''})
            print(f'\nThe password has been changed for the user "{user}"')
        self.db_commit()
        return True

    def reset_totp(self, user: str, disable: bool) -> bool:
        # Verify the user account
        user = PwicLib.safe_user_name(user)
        if user[:4] in ['', 'pwic']:
            print('Error: invalid user')
            return False
        sql = self.db_connect()
        if sql is None:
            return False
        sql.execute(''' SELECT 1
                        FROM users
                        WHERE user = ?''',
                    (user, ))
        if sql.fetchone() is None:
            print(f'Error: the user "{user}" does not exist')
            return False

        # 2FA TOTP without no_totp
        if disable:
            sql.execute(''' UPDATE users
                            SET totp = ''
                            WHERE user = ?''',
                        (user, ))
            print(f'2FA TOTP is disabled for the user "{user}".')
        else:
            host = urlparse(str(PwicLib.option(sql, '', 'base_url', ''))).netloc
            if host == '':
                print('Error: the option "base_url" is not defined')
                return False
            if PwicLib.option(sql, '', 'totp') is None:
                print('Warning: 2FA TOTP is not enabled yet')
            if '@' in user:
                print('Warning: the embedded 2FA TOTP is not compatible with OAuth')
            totp_secret = pyotp.random_base32()
            sql.execute(''' UPDATE users
                            SET totp = ?
                            WHERE user = ?''',
                        (totp_secret, user))
            totp_url = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=user, issuer_name=host)
            print(f'To configure 2FA TOTP fully, share securely the following info with the user "{user}":')
            print(f'- Key: {totp_secret}')
            print(f'- URL: {totp_url}')
            del totp_secret, totp_url
        PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                            'event': 'reset-totp',
                            'user': user})
        self.db_commit()
        return True

    def assign_user(self, project: str, user: str) -> bool:
        # Verify the parameters
        project = PwicLib.safe_name(project)
        user = PwicLib.safe_user_name(user)
        if (project in PwicConst.NOT_PROJECT) or (user == ''):
            print('Error: invalid parameters')
            return False

        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False
        if not self.db_lock(sql):
            return False

        # Check the existence of the role
        sql.execute(''' SELECT 1
                        FROM roles
                        WHERE project = ?
                          AND user    = ?''',
                    (project, user))
        if sql.fetchone() is not None:
            print('Error: user already assigned to the project')
            self.db_rollback()
            return False

        # Check the existence of the project
        sql.execute(''' SELECT 1
                        FROM projects
                        WHERE project = ?''',
                    (project, ))
        if sql.fetchone() is None:
            print('Error: unknown project')
            self.db_rollback()
            return False

        # Check the existence of the user
        sql.execute(''' SELECT 1
                        FROM users
                        WHERE user = ?''',
                    (user, ))
        if sql.fetchone() is None:
            print('Error: unknown user')
            self.db_rollback()
            return False

        # Assign the user as a reader
        sql.execute(''' INSERT INTO roles (project, user, reader, disabled)
                        VALUES (?, ?, 'X', '')''',
                    (project, user))
        PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                            'event': 'grant-reader',
                            'project': project,
                            'user': user})
        self.db_commit()
        print(f'The user "{user}" is added to the project "{project}" as a reader')
        return True

    def revoke_user(self, user: str, force: bool) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Verify the user name
        user = PwicLib.safe_user_name(user)
        if user[:4] == 'pwic':
            print('Error: this user cannot be managed')
            return False
        if sql.execute(''' SELECT user
                           FROM users
                           WHERE user = ?''',
                       (user, )).fetchone() is None:
            print(f'Error: the user "{user}" does not exist')
            return False

        # Check if there is a project where the user is the sole active administrator
        sql.execute(''' SELECT a.project, c.description
                        FROM roles AS a
                            INNER JOIN (
                                SELECT project, COUNT(admin) AS numAdmin
                                FROM roles
                                WHERE admin    = 'X'
                                  AND disabled = ''
                                GROUP BY project
                            ) AS b
                                ON b.project = a.project
                            INNER JOIN projects AS c
                                ON c.project = a.project
                        WHERE a.user     = ?
                          AND a.admin    = 'X'
                          AND a.disabled = ''
                          AND b.numAdmin = 1
                        ORDER BY a.project''',
                    (user, ))
        tab = None
        for row in sql.fetchall():
            if tab is None:
                tab = self._prepare_prettytable(['Project', 'Description'], header=False, border=False)
                if force:
                    print('Warning: the following projects will have no administrator anymore')
                else:
                    print('Error: organize a transfer of ownership for the following projects before revoking the user')
            tab.add_row([row['project'], row['description']])
        if tab is not None:
            print(tab.get_string())
            if not force:
                return False

        # Confirm
        if not force:
            print('This operation in mass needs your confirmation.')
            print(f'Type "YES" in uppercase to confirm the revocation of the user "{user}": ', end='')
            if input() != 'YES':
                return False

        # Disable the user for every project
        if not self.db_lock(sql):
            return False
        sql.execute(''' SELECT project
                        FROM roles
                        WHERE user = ?''',
                    (user, ))
        for row in sql.fetchall():
            PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                                'event': 'delete-user',
                                'project': row['project'],
                                'user': user})
        sql.execute(''' DELETE FROM roles WHERE user = ?''', (user, ))

        # Final
        self.db_commit()
        print(f'The user "{user}" is fully unassigned to the projects but remains in the database')
        return True

    def show_audit(self, dmin: int, dmax: int) -> bool:
        # Calculate the dates
        dmin = max(0, dmin)
        dmax = max(0, dmax)
        if dmax > dmin:
            dmin, dmax = dmax, dmin
        if dmin == 0:
            print('Error: invalid parameters')
            return False
        dmin_str = str(datetime.date.today() - datetime.timedelta(days=dmin))[:10]
        dmax_str = str(datetime.date.today() - datetime.timedelta(days=dmax))[:10]

        # Select the data
        sql = self.db_connect()
        if sql is None:
            return False
        sql.execute(''' SELECT id, date, time, author, event, user,
                               project, page, reference, ip, string
                        FROM audit.audit
                        WHERE date >= ? AND date <= ?
                        ORDER BY id ASC''',
                    (dmin_str, dmax_str))

        # Report the log
        tab = self.db_sql2table(sql)
        if tab is not None:
            print(tab.get_string())
            return True
        return False

    def show_login(self, days: int) -> bool:
        # Select the data
        sql = self.db_connect()
        if sql is None:
            return False
        dt = PwicLib.dt(days=days)
        sql.execute(''' SELECT a.user, c.date, c.time, b.events
                        FROM users AS a
                            INNER JOIN (
                                SELECT author, MAX(id) AS id, COUNT(id) AS events
                                FROM audit.audit
                                WHERE event = 'login'
                                  AND date >= ?
                                GROUP BY author
                            ) AS b
                                ON b.author = a.user
                            INNER JOIN audit.audit AS c
                                ON c.id = b.id
                        ORDER BY c.date DESC,
                                 c.time DESC,
                                 a.user ASC''',
                    (dt['date-nd'], ))

        # Report the log
        tab = self.db_sql2table(sql)
        if tab is not None:
            print(tab.get_string())
            return True
        return False

    def show_stats(self) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False
        dt = PwicLib.dt()
        tab = self._prepare_prettytable(['Topic', 'Project / Key', 'Period', 'Value'])

        # Macros
        def _totals(sql: sqlite3.Cursor,
                    kpi: str,
                    query: str,
                    tuples: Optional[Tuple[Any, ...]]):
            if tuples is None:
                tuples = ()
            sql.execute(query, tuples)
            for row in sql.fetchall():
                value = row.get('kpi', '')
                if value in [0, None]:
                    value = ''
                tab.add_row([kpi,
                             row.get('project', ''),
                             row.get('period', ''),
                             value])

        # Users
        _totals(sql, 'Number of users (ever created)',
                ''' SELECT COUNT(user) AS kpi
                    FROM users
                    WHERE user NOT LIKE 'pwic%'
                      AND user <> '' ''', None)
        _totals(sql, 'Number of active users',
                ''' SELECT COUNT(user) AS kpi
                    FROM (
                        SELECT DISTINCT user
                        FROM roles
                        WHERE user NOT LIKE 'pwic%'
                          AND disabled = ''
                    )''', None)
        _totals(sql, 'Number of system users',
                ''' SELECT COUNT(user) AS kpi
                    FROM users
                    WHERE user LIKE 'pwic%' ''', None)
        _totals(sql, 'Number of users with OAuth',
                ''' SELECT COUNT(user) AS kpi
                    FROM users
                    WHERE password = ?''', (PwicConst.MAGIC_OAUTH, ))
        _totals(sql, 'Number of users with 2FA TOTP',
                ''' SELECT COUNT(user) AS kpi
                    FROM users
                    WHERE totp <> '' ''', None)
        _totals(sql, 'Number of users with an initial password',
                ''' SELECT COUNT(user) AS kpi
                    FROM users
                    WHERE initial = 'X' ''', None)
        _totals(sql, 'Number of orphaned users',
                ''' SELECT COUNT(a.user) AS kpi
                    FROM users AS a
                        LEFT OUTER JOIN roles AS b
                            ON b.user = a.user
                        LEFT OUTER JOIN pages AS c
                            ON c.author  = a.user
                            OR c.valuser = a.user
                        LEFT OUTER JOIN documents AS d
                            ON d.author = a.user
                    WHERE b.user    IS NULL
                      AND c.author  IS NULL
                      AND c.valuser IS NULL
                      AND d.author  IS NULL''', None)
        _totals(sql, 'Number of duplicate passwords among the users',
                ''' SELECT COUNT(password) AS kpi
                    FROM (
                        SELECT password, COUNT(password) AS total
                        FROM users
                        WHERE initial  = ''
                          AND password <> ''
                          AND password <> ?
                        GROUP BY password
                    )
                    WHERE total > 1''', (PwicConst.MAGIC_OAUTH, ))
        _totals(sql, 'Number of active users per period',
                ''' SELECT date AS period, COUNT(author) AS kpi
                    FROM (
                        SELECT DISTINCT SUBSTR(date,1,7) AS date, author
                        FROM audit.audit
                        WHERE author NOT LIKE 'pwic%'
                    )
                    GROUP BY period
                    ORDER BY period''', None)

        # Projects
        _totals(sql, 'Number of projects',
                ''' SELECT COUNT(project) AS kpi
                    FROM projects
                    WHERE project <> '' ''', None)
        _totals(sql, 'Number of projects created in the last 90 days',
                ''' SELECT COUNT(project) AS kpi
                    FROM projects
                    WHERE project <> ''
                      AND date    >= ?''', (dt['date-90d'], ))
        _totals(sql, 'Number of deleted projects',
                ''' SELECT COUNT(project) AS kpi
                    FROM (
                        SELECT DISTINCT a.project
                        FROM audit.audit AS a
                            LEFT OUTER JOIN projects AS b
                                ON b.project = a.project
                        WHERE a.project <> ''
                          AND b.project IS NULL
                    )''', None)

        # Roles
        _totals(sql, 'Number of administrators',
                ''' SELECT COUNT(user) AS kpi
                    FROM (
                        SELECT DISTINCT user
                        FROM roles
                        WHERE admin    = 'X'
                          AND disabled = ''
                    )''', None)
        _totals(sql, 'Number of administrators per project',
                ''' SELECT project, COUNT(user) AS kpi
                    FROM roles
                    WHERE admin    = 'X'
                      AND disabled = ''
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Number of managers',
                ''' SELECT COUNT(user) AS kpi
                    FROM (
                        SELECT DISTINCT user
                        FROM roles
                        WHERE manager  = 'X'
                          AND disabled = ''
                    )''', None)
        _totals(sql, 'Number of managers per project',
                ''' SELECT project, COUNT(user) AS kpi
                    FROM roles
                    WHERE manager  = 'X'
                      AND disabled = ''
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Number of editors',
                ''' SELECT COUNT(user) AS kpi
                    FROM (
                        SELECT DISTINCT user
                        FROM roles
                        WHERE editor   = 'X'
                          AND disabled = ''
                    )''', None)
        _totals(sql, 'Number of editors per project',
                ''' SELECT project, COUNT(user) AS kpi
                    FROM roles
                    WHERE editor   = 'X'
                      AND disabled = ''
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Number of validators',
                ''' SELECT COUNT(user) AS kpi
                    FROM (
                        SELECT DISTINCT user
                        FROM roles
                        WHERE validator = 'X'
                          AND disabled  = ''
                    )''', None)
        _totals(sql, 'Number of validators per project',
                ''' SELECT project, COUNT(user) AS kpi
                    FROM roles
                    WHERE validator = 'X'
                      AND disabled  = ''
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Number of validators who did it once',
                ''' SELECT COUNT(valuser) AS kpi
                    FROM (
                        SELECT DISTINCT valuser
                        FROM pages
                        WHERE valuser <> ''
                    )''', None)
        _totals(sql, 'Number of readers',
                ''' SELECT COUNT(user) AS kpi
                    FROM (
                        SELECT DISTINCT user
                        FROM roles
                        WHERE reader   = 'X'
                          AND disabled = ''
                    )''', None)
        _totals(sql, 'Number of readers per project',
                ''' SELECT project, COUNT(user) AS kpi
                    FROM roles
                    WHERE reader   = 'X'
                      AND disabled = ''
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Number of disabled users',
                ''' SELECT COUNT(user) AS kpi
                    FROM (
                        SELECT DISTINCT user
                        FROM roles
                        WHERE disabled = 'X'
                    )''', None)
        _totals(sql, 'Number of disabled users per project',
                ''' SELECT project, COUNT(user) AS kpi
                    FROM roles
                    WHERE disabled = 'X'
                    GROUP BY project
                    ORDER BY project''', None)

        # Pages
        _totals(sql, 'Number of pages',
                ''' SELECT COUNT(page) AS kpi
                    FROM pages
                    WHERE latest = 'X' ''', None)
        _totals(sql, 'Number of revisions',
                ''' SELECT COUNT(page) AS kpi
                    FROM pages''', None)
        _totals(sql, 'Number of pages per project',
                ''' SELECT project, COUNT(page) AS kpi
                    FROM pages
                    WHERE latest = 'X'
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Number of revisions per project',
                ''' SELECT project, COUNT(page) AS kpi
                    FROM pages
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Number of drafts per project',
                ''' SELECT project, COUNT(page) AS kpi
                    FROM pages
                    WHERE latest = 'X'
                      AND draft  = 'X'
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Number of validations done',
                ''' SELECT COUNT(page) AS kpi
                    FROM pages
                    WHERE valuser <> '' ''', None)
        _totals(sql, 'Number of validations done per project',
                ''' SELECT project, COUNT(page) AS kpi
                    FROM pages
                    WHERE valuser <> ''
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Number of pages currently validated per project',
                ''' SELECT project, COUNT(page) AS kpi
                    FROM pages
                    WHERE latest   = 'X'
                      AND valuser <> ''
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Percentage of validation per project',
                ''' SELECT a.project, ROUND(100. * COUNT(a.page) / b.nb, 2) AS kpi
                    FROM pages AS a
                        INNER JOIN (
                            SELECT project, COUNT(page) AS nb
                            FROM pages
                            WHERE latest = 'X'
                            GROUP BY project
                        ) AS b
                            ON b.project = a.project
                    WHERE a.latest   = 'X'
                      AND a.valuser <> ''
                    GROUP BY a.project''', None)
        _totals(sql, 'Size of the latest revisions',
                ''' SELECT SUM(LENGTH(markdown)) AS kpi
                    FROM pages
                    WHERE latest = 'X' ''', None)
        _totals(sql, 'Size of the latest revisions per project',
                ''' SELECT project, SUM(LENGTH(markdown)) AS kpi
                    FROM pages
                    WHERE latest = 'X'
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Size of all the revisions',
                ''' SELECT SUM(LENGTH(markdown)) AS kpi
                    FROM pages''', None)
        _totals(sql, 'Size of all the revisions per project',
                ''' SELECT project, SUM(LENGTH(markdown)) AS kpi
                    FROM pages
                    GROUP BY project
                    ORDER BY project''', None)

        # Cache
        _totals(sql, 'Number of pages in the cache',
                ''' SELECT COUNT(*) AS kpi
                    FROM pages AS a
                        INNER JOIN cache AS b
                            ON b.project  = a.project
                           AND b.page     = a.page
                           AND b.revision = a.revision
                    WHERE a.latest = 'X' ''', None)
        _totals(sql, 'Number of revisions in the cache',
                ''' SELECT COUNT(*) AS kpi
                    FROM cache''', None)
        _totals(sql, 'Number of characters in the cache',
                ''' SELECT SUM(LENGTH(html)) AS kpi
                    FROM cache''', None)

        # Dates
        _totals(sql, 'Last modification per project',
                ''' SELECT project, MAX(date, valdate) AS kpi
                    FROM pages
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Last activity per active project',
                ''' SELECT a.project, MAX(a.date) AS kpi
                    FROM audit.audit AS a
                        INNER JOIN projects AS b
                            ON b.project = a.project
                    WHERE a.project <> ''
                    GROUP BY a.project
                    ORDER BY a.project''', None)

        # Documents
        _totals(sql, 'Number of documents',
                ''' SELECT COUNT(id) AS kpi
                    FROM documents''', None)
        _totals(sql, 'Number of documents stored externally',
                ''' SELECT COUNT(id) AS kpi
                    FROM documents
                    WHERE exturl <> '' ''', None)
        _totals(sql, 'Number of documents per project',
                ''' SELECT project, COUNT(id) AS kpi
                    FROM documents
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Size of the documents',
                ''' SELECT SUM(size) AS kpi
                    FROM documents''', None)
        _totals(sql, 'Size of the documents stored externally',
                ''' SELECT SUM(size) AS kpi
                    FROM documents
                    WHERE exturl <> '' ''', None)
        _totals(sql, 'Size of the documents per project',
                ''' SELECT project, SUM(size) AS kpi
                    FROM documents
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Average size of the documents',
                ''' SELECT CAST(AVG(size) AS INT) AS kpi
                    FROM documents''', None)
        _totals(sql, 'Average size of the documents per project',
                ''' SELECT project, CAST(AVG(size) AS INT) AS kpi
                    FROM documents
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Disk space usage per project (%)',
                ''' SELECT  d.project,
                            ROUND(100.0 * d.size / d.maxSize, 2) AS kpi
                    FROM (
                        SELECT  a.project,
                                SUM(size) AS size,
                                IIF(b.value NOTNULL, b.value, IIF(c.value NOTNULL, c.value, 0)) AS maxSize
                        FROM documents AS a
                            LEFT OUTER JOIN env AS b
                                ON  b.project = a.project
                                AND b.key     = 'project_size_max'
                            LEFT OUTER JOIN env AS c
                                ON  c.project = ''
                                AND c.key     = 'project_size_max'
                        GROUP BY a.project
                        ORDER BY a.project
                    ) AS d
                    WHERE d.maxSize > 0
                    ORDER BY d.project''', None)
        _totals(sql, 'Last date of upload',
                ''' SELECT MAX(date) AS kpi
                    FROM documents''', None)
        _totals(sql, 'Last date of upload per project',
                ''' SELECT project, MAX(date) AS kpi
                    FROM documents
                    GROUP BY project
                    ORDER BY project''', None)
        _totals(sql, 'Number of different file formats',
                ''' SELECT COUNT(mime) AS kpi
                    FROM (
                        SELECT DISTINCT mime
                        FROM documents
                    )''', None)

        # Options
        _totals(sql, 'Number of defined options',
                ''' SELECT COUNT(key) AS kpi
                    FROM env
                    WHERE value <> '' ''', None)
        _totals(sql, 'Number of global options',
                ''' SELECT COUNT(key) AS kpi
                    FROM env
                    WHERE project = ''
                      AND value  <> '' ''', None)
        _totals(sql, 'Number of specific options per project',
                ''' SELECT project, COUNT(key) AS kpi
                    FROM env
                    WHERE value <> ''
                    GROUP BY project
                    ORDER BY project''', None)

        # Audit
        _totals(sql, 'Number of events',
                ''' SELECT event AS project, COUNT(event) AS kpi
                    FROM audit.audit
                    GROUP BY event
                    ORDER BY event''', None)

        # Final output
        PwicExtension.on_admin_stats(sql, tab)
        print(tab.get_string())
        return True

    def show_inactivity(self, project: str, days: int) -> bool:
        # Select the data
        sql = self.db_connect()
        if sql is None:
            return False
        dt = PwicLib.dt(days=days)
        sql.execute(''' SELECT a.user, a.project, a.admin, a.manager, a.editor, a.validator
                        FROM roles AS a
                            LEFT OUTER JOIN (
                                SELECT project, author, MAX(date) AS date
                                FROM audit.audit
                                WHERE ((project = ?) OR ('' = ?))
                                  AND date >= ?
                                GROUP BY project, author
                            ) AS b
                                ON  b.project = a.project
                                AND b.author  = a.user
                        WHERE ((a.project = ?) OR ('' = ?))
                          AND ( a.admin     = 'X'
                             OR a.manager   = 'X'
                             OR a.editor    = 'X'
                             OR a.validator = 'X'
                          )
                          AND a.disabled    = ''
                          AND b.date        IS NULL
                        ORDER BY a.user, a.project''',
                    (project, project, dt['date-nd'], project, project))

        # Report the log
        tab = self._prepare_prettytable(['User', 'Project', 'Roles'])
        for row in sql.fetchall():
            roles = ''
            for k in ['admin', 'manager', 'editor', 'validator']:
                if row[k]:
                    roles += k[:1].upper()
            tab.add_row([row['user'], row['project'], roles])
        print('The pure readers are not included in the list.')
        print(tab.get_string())
        return True

    def compress_static(self, revert: bool) -> bool:
        # To reduce the bandwidth, aiohttp automatically delivers the static files as compressed if the .gz file is created
        # Despite the files do not change, many responses 304 are generated with some browsers
        counter = 0
        path = './static/'
        files = [(path + f) for f in listdir(path) if isfile(join(path, f)) and (f.endswith('.js') or f.endswith('.css'))]
        for fn in files:
            if getsize(fn) >= 25600:
                if not revert:
                    with open(fn, 'rb') as src:
                        with gzip.open(fn + '.gz', 'wb') as dst:
                            print(f'Compressing "{fn}"')
                            copyfileobj(src, dst)
                            counter += 1
                else:
                    try:
                        fn = fn + '.gz'
                        os.remove(fn)
                        print(f'Removing "{fn}"')
                        counter += 1
                    except OSError:
                        print(f'Failed to remove "{fn}"')
        if counter > 0:
            print(f'{counter} files were processed')
        return counter > 0

    def clear_cache(self, project: str, selective: bool) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Prepare the query
        project = PwicLib.safe_name(project)
        q = ''' DELETE FROM cache'''
        if project == '':
            if selective:
                q += ''' WHERE ROWID IN (
                             SELECT a.ROWID
                             FROM cache AS a
                                 INNER JOIN pages AS b
                                     ON  b.project  = a.project
                                     AND b.page     = a.page
                                     AND b.revision = a.revision
                                     AND b.latest   = ''
                                     AND b.valuser  = ''
                         )'''
        else:
            if not selective:
                q += ''' WHERE project = ?'''
            else:
                q += ''' WHERE ROWID IN (
                             SELECT a.ROWID
                             FROM cache AS a
                                 INNER JOIN pages AS b
                                     ON  b.project  = a.project
                                     AND b.page     = a.page
                                     AND b.revision = a.revision
                                     AND b.latest   = ''
                                     AND b.valuser  = ''
                             WHERE a.project = ?
                         )'''

        # Clear the cache
        sql.execute(q, (project, ) if '?' in q else ())
        PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                            'event': 'clear-cache',
                            'project': project})
        self.db_commit()
        if selective:
            print('The cache is partially cleared.')
        else:
            print('Please expect a workload of regeneration for a short period of time.')
        return True

    def regenerate_cache(self, project: str, user: str, full: bool, port: int) -> bool:
        # Connect to the database
        sql = self.db_connect()             # Don't lock this connection
        if sql is None:
            return False

        # Fetch the projects
        user = PwicLib.safe_user_name(user or PwicConst.USERS['anonymous'])
        project = PwicLib.safe_name(project)
        sql.execute(''' SELECT project
                        FROM roles
                        WHERE user     = ?
                          AND disabled = '' ''',
                    (user, ))
        projects = [row['project'] for row in sql.fetchall()]
        if project != '':
            if project in projects:
                projects = [project]
            else:
                projects = []
        if len(projects) == 0:
            print('Error: no project found')
            return False
        projects.sort()

        # Detection of HTTPS
        if PwicLib.option(sql, '', 'https') is None:
            protocol = 'http'
        else:
            protocol = 'https'
            ssl._create_default_https_context = ssl._create_unverified_context

        # Authentication
        headers = {}
        if user[:4] != 'pwic':
            print(f'Password of the account "{user}": ', end='')
            try:
                with urlopen(Request(f'{protocol}://127.0.0.1:{port}/api/login',
                                     urlencode({'user': user,
                                                'password': input()}).encode(),
                                     method='POST')) as response:
                    headers['Cookie'] = response.headers.get('Set-Cookie', '')
            except Exception as e:
                if isinstance(e, HTTPError):
                    print('Error: %d %s' % (PwicLib.intval(e.getcode()), e.reason))
                elif isinstance(e, URLError):
                    print('Error: the host is not running or cannot be reached')
                else:
                    print(str(e))
                return False

        # Prepare the query
        query = ''' SELECT a.project, a.page, a.revision
                    FROM pages AS a
                        LEFT OUTER JOIN cache AS b
                            ON  b.project  = a.project
                            AND b.page     = a.page
                            AND b.revision = a.revision
                    WHERE a.project  = ?
                      AND b.html    IS NULL'''
        if not full:
            query += ''' AND ( a.latest   = 'X'
                            OR a.valuser != '' )'''
        query += ''' LIMIT 500'''

        # Select the pages by project and by blocks of N entries (to avoid concurrent locks)
        nmax = 0
        ok = 0
        ko = 0
        for p in projects:
            if (((PwicLib.option(sql, p, 'no_cache') is not None)
                 or (PwicLib.option(sql, p, 'no_history') is not None)
                 or (PwicLib.option(sql, p, 'validated_only') is not None))):
                print(f'\rProject "{p}" is excluded')
                continue
            sql.execute(''' SELECT COUNT(*) AS total
                            FROM pages
                            WHERE project = ?''',
                        (p, ))
            nmax += sql.fetchone()['total']             # Moving max number of regeneratable pages
            while True:
                once = False
                sql.execute(query, (p, ))
                for row in sql.fetchall():
                    # Refresh the page
                    try:
                        url = f'{protocol}://127.0.0.1:{port}/{row["project"]}/{row["page"]}/rev{row["revision"]}'
                        urlopen(Request(url, None, headers=headers, method='GET'))
                        once = True
                        ok += 1
                        if ok % 10 == 0:
                            print(f'\r{ok} pages', end='', flush=True)
                    except Exception:
                        ko += 1
                    if ok + ko > nmax:
                        print('\nError: possible infinite loop, check your options')
                        return False
                if not once:
                    break
        print(f'\r{ok} pages')
        del headers
        return (ok > 0) and (ko == 0)

    def rotate_logs(self, nfiles: int) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Read the file name
        fn = PwicLib.option(sql, '', 'http_log_file')
        if fn is None:
            print('Error: option "http_log_file" not defined')
            return False

        # Rotate the files
        nfiles = max(3, nfiles)
        # ... first file
        try:
            rename(fn, fn + '.tmp')
        except OSError:
            print('Error: Pwic.wiki is running, never ran recently, incorrect file name, or no authorization')
            return False
        # ... remove the oldest file
        try:
            os.remove(f'{fn}.{nfiles}.gz')
        except OSError:
            pass
        # ... rotate the files
        for i in reversed(range(1, nfiles)):    # i=[1..nfiles-1]
            try:
                rename(f'{fn}.{i}.gz', f'{fn}.{i+1}.gz')
            except OSError:
                pass
        # ... compress the last file
        try:
            with open(f'{fn}.0', 'rb') as src:
                with gzip.open(f'{fn}.1.gz', 'wb') as dst:
                    copyfileobj(src, dst)
        except OSError:
            pass
        # ... remove the compressed file
        try:
            os.remove(f'{fn}.0')
        except OSError:
            pass
        # ... rotate the first file
        try:
            rename(f'{fn}.tmp', f'{fn}.0')
        except OSError:
            pass

        # Final
        print('Done')
        return True

    def archive_audit(self, selective: int, complete: int) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Ask for confirmation
        print('This command will remove some irrelevant old entries of audit.')
        print('Type "YES" to agree and continue: ', end='')
        if input() != 'YES':
            return False

        # Initialization
        mindays = 90                                        # 3 months minimum
        dt = PwicLib.dt(days=max(mindays, selective))
        counter = 0
        if not self.db_lock(sql):
            return False

        # Remove the history of the deleted projects
        for e in ['create-project', 'delete-project']:
            sql.execute(''' SELECT project, MAX(id) AS id
                            FROM audit.audit
                            WHERE event    = ?
                              AND project <> ''
                            GROUP BY project''',
                        (e, ))
            for row in sql.fetchall():
                sql.execute(''' DELETE FROM audit.audit
                                WHERE id      < ?
                                  AND date    < ?
                                  AND project = ?''',
                            (row['id'], dt['date-nd'], row['project']))
                counter += sql.rowcount

        # Remove the poor events
        sql.execute(''' DELETE FROM audit.audit
                        WHERE date   < ?
                          AND event IN ('change-password',
                                        'clear-cache',
                                        'export-project',
                                        'login',
                                        'logout',
                                        'reset-password',
                                        'shutdown-server',
                                        'split-project',
                                        'start-server')''',
                    (dt['date-nd'], ))
        counter += sql.rowcount

        # Remove all the old entries
        if complete >= mindays:
            dt = PwicLib.dt(days=complete)
            sql.execute(''' DELETE FROM audit.audit
                            WHERE date < ?''',
                        (dt['date-nd'], ))

        # Result
        PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                            'event': 'archive-audit'})
        self.db_commit()
        print(f'{counter} entries moved to the table "audit_arch". Do what you want with them.')
        return True

    def show_git(self, agree: bool = False) -> bool:
        # Check the git repository
        if not isdir('./.git/'):
            print('Error: no git repository is used')
            return False

        # Show the warning
        if not agree:
            print('For security reasons, you should run this command with the parameter "--agree".\n')
            print('Latest commit: unknown')
            print('Current version: unknown')
            return False

        # Show the information
        print('Latest commit: ', end='', flush=True)
        call(['git', 'rev-parse', 'HEAD'])                      # nosec B603
        print('Current version: ', end='', flush=True)
        call(['git', 'describe', '--tags'])                     # nosec B603
        return True

    def create_backup(self) -> bool:
        # Check the database
        if not isfile(PwicConst.DB_SQLITE):
            print('Error: the database is not created yet')
            return False

        # Prepare the new file name
        dt = PwicLib.dt()
        stamp = '%s_%s' % (dt['date'].replace('-', ''), dt['time'].replace(':', ''))
        new = PwicConst.DB_SQLITE_BACKUP % stamp
        try:
            copyfile(PwicConst.DB_SQLITE, new)
            if not isfile(new):
                raise FileNotFoundError(f'Error: file "{new}" not created')

            # Log the event
            audit_id = 0
            sql = self.db_connect()
            if sql is not None:
                sql.execute(''' SELECT MAX(id) AS id
                                FROM audit''')
                audit_id = PwicLib.intval(sql.fetchone()['id'])
                PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                                    'event': 'create-backup',
                                    'string': stamp})
                self.db_commit()

            # Mark the new database
            if audit_id > 0:
                sql = self.db_connect(dbfile=new)
                if sql is not None:
                    sql.execute(''' INSERT OR REPLACE INTO env (project, key, value)
                                    VALUES ('', 'pwic_audit_id', ?)''',
                                (audit_id, ))
                    self.db_commit()

            # Final
            chmod(new, S_IREAD)
            print(f'Backup of the main database created in "{new}"')
            print('The uploaded documents remain in their place')
            return True
        except Exception as e:
            print(str(e))
            return False

    def repair_documents(self, project: str, no_hash: bool, no_magic: bool, keep_orphans: bool, test: bool) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Ask for confirmation
        magic_bytes = not no_magic and (PwicLib.option(sql, '', 'magic_bytes') is not None)
        print('This tool will perform the following actions:')
        print('    - Create a folder for each project')
        print('    - Delete the folders of all the unknown projects')
        print('    - Delete the documents from the database if there is no associated physical file')
        print('    - Delete the orphaned physical files that are not indexed in the database')
        if magic_bytes:
            print('    - Delete retroactively the files whose magic bytes are incorrect')
        print('    - Update the size of the files in the database')
        if not no_hash:
            print('    - Update the hash of the files in the database')
        print('    - Update the dimensions of the pictures in the database')
        print('')
        print('The database will be locked during the whole process.')
        print('Please ensure that the server is not running.')
        print('Use the test mode to ensure that the changes are relevant.')
        print('The changes cannot be reverted.')
        print('')
        print('Type "YES" to agree and continue: ', end='')
        if input() != 'YES':
            return False
        print('')

        # Initialization
        projects = []
        multi = project == ''
        tab = self._prepare_prettytable(['Action', 'Type', 'Project', 'Value', 'Reason'])

        # Select the projects
        if not self.db_lock(sql):
            return False
        sql.execute(''' SELECT project
                        FROM projects
                        WHERE project <> ''
                        ORDER BY project''')
        for row in sql.fetchall():
            projects.append(PwicLib.safe_name(row['project']))
        if not multi:
            if project not in projects:
                self.db_commit()            # To end the empty transaction
                return False
            projects = [project]

        # Each project should have a folder
        for p in projects.copy():
            path = PwicConst.DOCUMENTS_PATH % p
            if not isdir(path):
                try:
                    if not test:
                        makedirs(path)
                    tab.add_row(['Create', 'Folder', p, path, 'Missing'])
                except OSError:
                    print(f'Failed to create the folder "{path}"')
                    projects.remove(p)
        if multi and not keep_orphans:
            dirs = sorted([f for f in listdir(PwicConst.DOCUMENTS_PATH % '') if isdir(PwicConst.DOCUMENTS_PATH % f)])
            for p in dirs:
                if p not in projects:
                    path = PwicConst.DOCUMENTS_PATH % p
                    try:
                        for f in listdir(PwicConst.DOCUMENTS_PATH % p):
                            if not test:
                                os.remove(join(path, f))    # No call to PwicExtension.on_api_document_delete because the project does not exist
                            tab.add_row(['Delete', 'File', p, join(path, f), 'Orphaned'])
                        if not test:
                            removedirs(path)
                        tab.add_row(['Delete', 'Folder', p, path, 'Orphaned'])
                    except OSError:
                        print(f'Failed to delete the folder "{path}"')

        # Check the files per project
        for p in projects:
            if not isdir(PwicConst.DOCUMENTS_PATH % p):
                continue
            files = sorted([f for f in listdir(PwicConst.DOCUMENTS_PATH % p) if isfile(join(PwicConst.DOCUMENTS_PATH % p, f))])
            sql.execute(''' SELECT id, filename, exturl
                            FROM documents
                            WHERE project = ?
                              AND exturl  = ''
                            ORDER BY filename''',
                        (p, ))
            # Each document should match with a file
            for row in sql.fetchall():
                if row['filename'] in files:
                    files.remove(row['filename'])
                else:
                    if PwicExtension.on_api_document_delete(sql, None, p, PwicConst.USERS['system'], None, None, row['filename']):
                        if not test:
                            sql.execute(''' DELETE FROM documents
                                            WHERE ID = ?''',
                                        (row['id'], ))
                        tab.add_row(['Delete', 'Database', p, f'{row["id"]},{row["filename"]}', 'Missing'])
            # Delete the left files that can't be reassigned to the right objects
            if not keep_orphans:
                for f in files:
                    if PwicExtension.on_api_document_delete(sql, None, p, PwicConst.USERS['system'], None, None, f):
                        path = join(PwicConst.DOCUMENTS_PATH % p, f)
                        try:
                            if not test:
                                os.remove(path)
                            tab.add_row(['Delete', 'File', p, path, 'Orphaned'])
                        except OSError:
                            print(f'Failed to delete the file "{path}"')

        # Verify the integrity of the files
        for p in projects:
            sql.execute(''' SELECT id, filename, mime, size, width, height, hash
                            FROM documents
                            WHERE project = ?
                              AND exturl  = '' ''',
                        (p, ))
            for row in sql.fetchall():
                path = join(PwicConst.DOCUMENTS_PATH % p, row['filename'])
                try:
                    # Magic bytes
                    if magic_bytes:
                        magics = PwicLib.magic_bytes(splitext(path)[1][1:])
                        if magics is not None:
                            with open(path, 'rb') as fh:
                                content = fh.read(32)
                            ok = False
                            for mb in magics:
                                ok = ok or (content[:len(mb)] == PwicLib.str2bytearray(mb))
                            if not ok:
                                if not test:
                                    os.remove(path)
                                    sql.execute(''' DELETE FROM documents WHERE ID = ?''', (row['id'], ))
                                tab.add_row(['Delete', 'File', p, path, 'Unsafe'])
                                tab.add_row(['Delete', 'Database', p, f'{row["id"]},{row["filename"]}', 'Unsafe'])

                    # Size and hash
                    size = getsize(path)
                    hashval = row['hash'] if no_hash else PwicLib.sha256_file(path)
                    if (size != row['size']) or (hashval != row['hash']):
                        if not test:
                            sql.execute(''' UPDATE documents
                                            SET size = ?, hash = ?
                                            WHERE ID = ?''',
                                        (size, hashval, row['id']))
                        tab.add_row(['Update', 'Database', p, f'{row["id"]},{path}', 'Modified'])

                    # Width and height
                    if row['mime'][:6] == 'image/':
                        try:
                            width, height = imagesize.get(path)
                            if (width != row['width']) or (height != row['height']):
                                if not test:
                                    sql.execute(''' UPDATE documents
                                                    SET width = ?, height = ?
                                                    WHERE ID = ?''',
                                                (width, height, row['id']))
                                tab.add_row(['Update', 'Database', p, f'{row["id"]},{path}', 'Modified'])
                        except ValueError:
                            pass

                except OSError:    # Can occur in test mode
                    print(f'Failed to analyze the file "{path}"')
                    continue

        # Result
        if tab.rowcount == 0:
            print('\nNo change occurred in the database or the file system.')
        else:
            print(f'\nList of the {tab.rowcount} changes:')
            print(tab.get_string())
            if not test:
                PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                                    'event': 'repair-documents',
                                    'project': project,
                                    'string': tab.rowcount})
        self.db_commit()
        return True

    def execute_optimize(self) -> bool:
        # The documentation of SQLite states that long-running applications might benefit from running this command every few hours

        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Run the optimizer
        sql.execute(''' PRAGMA optimize''')
        print('Done')
        return True

    def unlock_db(self, port: bool, force: bool) -> bool:
        # Ask for confirmation
        if not force:
            print('This special function must be called with full knowledge of the facts.')
            print('The changes will be reverted and the database unlocked.')
            print('Type "YES" to agree and continue: ', end='')
            if input() != 'YES':
                return False

        # Detection of HTTPS
        sql = self.db_connect()
        if sql is None:
            return False
        if PwicLib.option(sql, '', 'https') is None:
            protocol = 'http'
        else:
            protocol = 'https'
            ssl._create_default_https_context = ssl._create_unverified_context

        # Connect to the API
        print('Sending the signal... ', end='', flush=True)
        try:
            url = f'{protocol}://127.0.0.1:{port}/api/server/unlock'
            urlopen(Request(url, None, method='POST'))
            print('OK')
            return True
        except Exception as e:
            print(f'failed\nError: {e}')
            return False

    def execute_sql(self, filename: str) -> bool:
        def _validate_sql(queries: List[str]) -> Dict[str, Union[int, bool]]:
            query = '\n'.join(queries).strip()
            if (len(query) > 0) and (query[-1:] != ';'):
                query += ';'
            statements = 0
            quote = None
            brackets = 0
            cm1 = ''
            cm2 = ''
            for i, c in enumerate(query):
                escaped = (cm1 == '\\') and (cm2 != '\\')
                if (c == ';') and (brackets == 0) and (quote is None):
                    statements += 1
                elif (c in ['"', "'"]) and not escaped:
                    if quote == c:
                        quote = None
                    elif quote is None:
                        quote = c
                elif (c == '(') and (not escaped) and (quote is None):
                    brackets += 1
                elif (c == ')') and (not escaped) and (quote is None):
                    brackets -= 1
                cm2 = cm1
                cm1 = c
            return {'statements': statements,
                    'ok': (statements > 0) and (brackets == 0) and (quote is None)}

        # Ask for queries
        print('This feature may corrupt the database. Please use it to upgrade Pwic.wiki upon explicit request only.')
        queries = []
        if filename == '':
            print("\nType the queries separated by semicolons. Leave a blank line after the last statement to validate the input:")
            while True:
                query = input()
                queries.append(query)
                validation = _validate_sql(queries)
                if (len(query) == 0) and validation['ok']:
                    break
        else:
            try:
                with open(filename, 'rb') as fh:
                    query = fh.read().decode()
            except (OSError, FileNotFoundError):
                print('Error: unknown file')
                return False
            queries = query.split('\n')
            validation = _validate_sql(queries)
            if not validation['ok']:
                print('Error: invalid SQL syntax')
                return False
            print('You are about to execute the following statements:\n')
            print(query.strip())

        # Ask for the confirmation
        print('\nTo continue, please confirm by typing "YES": ', end='')
        if input() != 'YES':
            return False

        # Execute
        query = '\n'.join(queries).replace('\r', '')
        sql = self.db_connect()
        if sql is None:
            return False
        try:
            if validation['statements'] == 1:
                sql.execute(query)
                print(f'Affected rows = {sql.rowcount}')
                tab = self.db_sql2table(sql)
                if tab is not None:
                    print(tab.get_string())
            else:
                sql.executescript(query)
                print('\nNo log')
        except sqlite3.OperationalError as e:
            print(f'\nError: {e}')
            self.db_rollback()
            return False

        # Trace
        try:
            PwicLib.audit(sql, {'author': PwicConst.USERS['system'],
                                'event': 'execute-sql',
                                'string': query.replace('\n', ' ')})
        except sqlite3.OperationalError:
            print('\nWarning: no audit saved for technical reasons')
        self.db_commit()
        return True

    def shutdown_server(self, port: int, force: bool) -> bool:
        # Ask for confirmation
        if not force:
            print('This command will try to terminate Pwic.wiki server at its earliest convenience.')
            print('This will disconnect the users and interrupt their work.')
            print('Type "YES" to agree and continue: ', end='')
            if input() != 'YES':
                return False

        # Detection of HTTPS
        sql = self.db_connect()
        if sql is None:
            return False
        if PwicLib.option(sql, '', 'https') is None:
            protocol = 'http'
        else:
            protocol = 'https'
            ssl._create_default_https_context = ssl._create_unverified_context

        # Terminate
        print('Sending the kill signal... ', end='', flush=True)
        try:
            url = f'{protocol}://127.0.0.1:{port}/api/server/shutdown'
            urlopen(Request(url, None, method='POST'))
        except Exception as e:
            if isinstance(e, RemoteDisconnected):
                print('OK')
                return True
            print(f'failed\nError: {e}')
        return False


# =====================
#  Program entry point
# =====================

app = PwicAdmin()
if app.main():
    sys.exit(0)
else:
    print('\nThe operation failed')
    sys.exit(1)
