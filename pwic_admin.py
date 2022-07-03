# Pwic.wiki server running on Python and SQLite
# Copyright (C) 2020-2022 Alexandre Bréard
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

from typing import Optional, Dict, List, Tuple, Any
import argparse
import sqlite3
from prettytable import PrettyTable
import imagesize
import gzip
import datetime
import sys
import os
import ssl
from os import chmod, listdir, makedirs, mkdir, removedirs, rename, rmdir
from os.path import getsize, isdir, isfile, join, splitext
from shutil import copyfile, copyfileobj
from subprocess import call
from stat import S_IREAD
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from http.client import RemoteDisconnected

from pwic_lib import PWIC_VERSION, PWIC_DB, PWIC_DB_SQLITE, PWIC_DB_SQLITE_BACKUP, PWIC_DB_SQLITE_AUDIT, PWIC_DOCUMENTS_PATH, \
    PWIC_USERS, PWIC_DEFAULTS, PWIC_ENV_PROJECT_INDEPENDENT, PWIC_ENV_PROJECT_DEPENDENT, PWIC_ENV_PROJECT_DEPENDENT_ONLY, \
    PWIC_ENV_PRIVATE, PWIC_MAGIC_OAUTH, PWIC_NOT_PROJECT, pwic_audit, pwic_dt, pwic_int, pwic_option, pwic_magic_bytes, \
    pwic_row_factory, pwic_safe_name, pwic_safe_user_name, pwic_sha256, pwic_sha256_file, pwic_str2bytearray, pwic_xb
from pwic_extension import PwicExtension


class PwicAdmin():
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
        parser = argparse.ArgumentParser(prog='python3 pwic_admin.py', description='Pwic.wiki Management Console v%s' % PWIC_VERSION)

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
        spb = subparsers.add_parser('create-user', help='Create a user with no assignment to a project')
        spb.add_argument('user', default='', help='User name')

        spb = subparsers.add_parser('reset-password', help='Reset the password of a user')
        spb.add_argument('user', default='', help='User name')
        spb.add_argument('--create', action='store_true', help='Create the user account if needed')
        spb.add_argument('--oauth', action='store_true', help='Force the federated authentication')

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
        spb.add_argument('--port', type=int, default=PWIC_DEFAULTS['port'], help='Target instance defined by the listened port', metavar=PWIC_DEFAULTS['port'])

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
        spb.add_argument('--port', type=int, default=PWIC_DEFAULTS['port'], help='Target instance defined by the listened port', metavar=PWIC_DEFAULTS['port'])
        spb.add_argument('--force', action='store_true', help='No confirmation')

        subparsers.add_parser('execute-sql', help='Execute an SQL query on the database (dangerous)')

        spb = subparsers.add_parser('shutdown-server', help='Terminate the server')
        spb.add_argument('--port', type=int, default=PWIC_DEFAULTS['port'], help='Target instance defined by the listened port', metavar=PWIC_DEFAULTS['port'])
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
        if args.command == 'create-user':
            return self.create_user(args.user)
        if args.command == 'reset-password':
            return self.reset_password(args.user, args.create, args.oauth)
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
            return self.execute_sql()
        if args.command == 'shutdown-server':
            return self.shutdown_server(args.port, args.force)

        # Default behavior
        parser.print_help()
        return False

    # ===== Database =====

    def db_connect(self, init: bool = False, master: bool = True, dbfile: str = PWIC_DB_SQLITE) -> Optional[sqlite3.Cursor]:
        if not init and not isfile(dbfile):
            print('Error: the database is not created yet')
            return None
        try:
            self.db = sqlite3.connect(dbfile)
            self.db.row_factory = pwic_row_factory
            sql = self.db.cursor()
            sql.execute(''' PRAGMA main.journal_mode = MEMORY''')
            if master:
                sql.execute(''' ATTACH DATABASE ? AS audit''', (PWIC_DB_SQLITE_AUDIT, ))
                sql.execute(''' PRAGMA audit.journal_mode = MEMORY''')
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
        sql = self.db_connect(init=True, master=False, dbfile=PWIC_DB_SQLITE_AUDIT)
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

    def db_create_tables_main(self, dbfile: str = PWIC_DB_SQLITE) -> bool:
        sql = self.db_connect(init=True, master=True, dbfile=dbfile)
        if sql is None:
            return False
        dt = pwic_dt()

        # Table PROJECTS
        sql.execute(''' CREATE TABLE "projects" (
                            "project" TEXT NOT NULL,
                            "description" TEXT NOT NULL,
                            "date" TEXT NOT NULL,
                            PRIMARY KEY("project")
                        )''')
        sql.execute(''' INSERT INTO projects (project, description, date) VALUES ('', '', '')''')   # Empty projects.project

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
                            "password_date" TEXT NOT NULL,
                            "password_time" TEXT NOT NULL,
                            PRIMARY KEY("user")
                        )''')
        for e in ['', PWIC_USERS['anonymous'], PWIC_USERS['ghost']]:
            sql.execute(''' INSERT INTO users (user, password, initial, password_date, password_time)
                            VALUES (?, '', '', ?, ?)''',
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

    # ===== Methods =====

    def init_db(self) -> bool:
        # Check that the database does not exist already
        if not isdir(PWIC_DB):
            mkdir(PWIC_DB)
        if isfile(PWIC_DB_SQLITE) or isfile(PWIC_DB_SQLITE_AUDIT):
            print('Error: the databases are already created')
            return False

        # Create the dbfiles
        ok = self.db_create_tables_audit() and self.db_create_tables_main()
        if not ok:
            print('Error: the databases cannot be created')
            return False

        # Connect to the databases
        sql = self.db_connect()
        if sql is None:
            print('Error: the databases cannot be opened')
            return False

        # Add the default, safe or mandatory configuration
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'init-db'})
        for (key, value) in [('base_url', 'http://127.0.0.1:%s' % PWIC_DEFAULTS['port']),
                             ('robots', 'noarchive noindex nofollow')]:
            sql.execute(''' INSERT INTO env (project, key, value)
                            VALUES ('', ?, ?)''',
                        (key, value))
            pwic_audit(sql, {'author': PWIC_USERS['system'],
                             'event': 'set-%s' % key,
                             'string': '' if key in PWIC_ENV_PRIVATE else value})

        # Confirmation
        self.db_commit()
        print('The databases are created in "%s" and "%s"' % (PWIC_DB_SQLITE, PWIC_DB_SQLITE_AUDIT))
        return True

    def show_env(self, project: str, var: str, dolist: bool) -> bool:
        # Package info
        if var == '':
            try:
                from importlib.metadata import PackageNotFoundError, version
                print('Python packages:')
                tab = PrettyTable()
                tab.field_names = ['Package', 'Version']
                tab.align[tab.field_names[0]] = 'l'
                tab.align[tab.field_names[1]] = 'r'
                tab.header = True
                tab.border = True
                for package in ['aiohttp', 'aiohttp-cors', 'aiohttp-session', 'cryptography', 'imagesize',
                                'jinja2', 'parsimonious', 'PrettyTable', 'pygments']:
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
        tab = PrettyTable()
        for row in sql.fetchall():
            if (project != '') and (row['project'] not in ['', project]):
                continue
            value = '(Secret value not displayed)' if (row['key'] in PWIC_ENV_PRIVATE) or (row['key'][:4] == 'pwic') else row['value']
            value = value.replace('\n', '\\n')
            if dolist:
                print('%s.%s = %s' % ('*' if row['project'] == '' else row['project'], row['key'], value))
            else:
                tab.add_row([row['project'], row['key'], value])
            ok = True
        if tab.rowcount > 0:
            tab.field_names = ['Project', 'Key', 'Value']
            for f in tab.field_names:
                tab.align[f] = 'l'
            tab.header = True
            tab.border = True
            print(tab.get_string())
        return ok

    def set_env(self, project: str, key: str, value: str, override: bool, append: bool, remove: bool) -> bool:
        # Check the parameters
        if override and (project != ''):
            print('Error: useless parameter --override if a project is indicated')
            return False
        if append and remove and True:
            print('Error: the options append and remove cannot be used together')
            return False
        allkeys = sorted(PWIC_ENV_PROJECT_INDEPENDENT + PWIC_ENV_PROJECT_DEPENDENT)
        if key not in allkeys:
            print('Error: the name of the variable must be one of "%s"' % ', '.join(allkeys))
            return False
        if (project != '') and (key in PWIC_ENV_PROJECT_INDEPENDENT):
            print('Error: the parameter is project-independent')
            return False
        if (project == '') and (key in PWIC_ENV_PROJECT_DEPENDENT_ONLY):
            print('Error: the parameter is project-dependent only')
            return False
        value = value.replace('\r', '').strip()

        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Adapt the value
        current = str(pwic_option(sql, project, key, ''))
        if remove:
            value = current.replace(value, '').replace('  ', ' ').strip()
        elif append:
            value = ('%s %s' % (current, value)).strip()

        # Reset the project-dependent values if --override
        if override:
            sql.execute(''' SELECT project
                            FROM env
                            WHERE project <> ''
                              AND key      = ?''',
                        (key, ))
            for row in sql.fetchall():
                pwic_audit(sql, {'author': PWIC_USERS['system'],
                                 'event': 'unset-%s' % key,
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
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': '%sset-%s' % ('un' if value == '' else '', key),
                         'project': project,
                         'string': '' if key in PWIC_ENV_PRIVATE else value})
        self.db_commit()
        if project != '':
            print('Variable %s for the project "%s"' % (verb, project))
        else:
            print('Variable %s globally' % verb)
        return True

    def repair_env(self, test: bool) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Analyze each variables
        all_keys = PWIC_ENV_PROJECT_INDEPENDENT + PWIC_ENV_PROJECT_DEPENDENT
        buffer = []
        sql.execute(''' SELECT project, key, value
                        FROM env
                        WHERE key NOT LIKE 'pwic%'
                        ORDER BY project, key''')
        for row in sql.fetchall():
            if (row['key'] not in all_keys) or \
               ((row['project'] != '') and (row['key'] in PWIC_ENV_PROJECT_INDEPENDENT)) or \
               ((row['project'] == '') and (row['key'] in PWIC_ENV_PROJECT_DEPENDENT_ONLY)) or \
               (row['value'] == ''):
                buffer.append((row['project'], row['key']))
        if not test:
            for e in buffer:
                sql.execute(''' DELETE FROM env
                                WHERE project = ?
                                  AND key     = ?''', e)
                pwic_audit(sql, {'author': PWIC_USERS['system'],
                                 'event': 'unset-%s' % e[1],
                                 'project': e[0]})
            self.db_commit()

        # Report
        if len(buffer) == 0:
            print('No change is required')
        else:
            if test:
                print('List of the options to be deleted:')
            else:
                print('List of the deleted options:')
            tab = PrettyTable()
            tab.field_names = ['Project', 'Variable']
            for f in tab.field_names:
                tab.align[f] = 'l'
            tab.header = True
            tab.border = True
            tab.add_rows(buffer)
            print(tab.get_string())
        return True

    def show_mime(self) -> bool:
        # Load the platform-dependent library
        try:
            import winreg
        except ImportError:
            print('Error: unsupported operating system')
            return False

        # Buffer
        tab = PrettyTable()
        tab.field_names = ['Extension', 'MIME']
        tab.sortby = 'Extension'
        for f in tab.field_names:
            tab.align[f] = 'l'
        tab.header = True
        tab.border = True

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
        tab = PrettyTable()
        tab.field_names = ['Project', 'Description', 'Administrators', 'Count']
        for f in tab.field_names:
            tab.align[f] = 'l'
        tab.header = True
        tab.border = True
        for key in data:
            tab.add_row([key, data[key]['description'], ', '.join(data[key]['admin']), len(data[key]['admin'])])
        print(tab.get_string())
        return True

    def create_project(self, project: str, description: str, admin: str) -> bool:
        # Check the arguments
        project = pwic_safe_name(project)
        description = description.strip()
        admin = pwic_safe_user_name(admin)
        if (project in ['api', 'special', 'static']) or \
           ('' in [project, description, admin]) or     \
           (project[:4] == 'pwic') or                   \
           (admin[:4] == 'pwic'):
            print('Error: invalid arguments')
            return False

        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False
        dt = pwic_dt()

        # Verify that the project does not exist yet
        sql.execute(''' SELECT project FROM projects WHERE project = ?''', (project, ))
        if sql.fetchone() is not None:
            print('Error: the project already exists')
            return False

        # Create the workspace for the documents of the project
        try:
            path = PWIC_DOCUMENTS_PATH % project
            if not isdir(path):
                makedirs(path)
        except OSError:
            print('Error: impossible to create "%s"' % path)
            return False

        # Add the user account
        sql.execute(''' INSERT OR IGNORE INTO users (user, password, initial, password_date, password_time)
                        VALUES (?, ?, 'X', ?, ?)''',
                    (admin, pwic_sha256(PWIC_DEFAULTS['password']), dt['date'], dt['time']))
        if sql.rowcount > 0:
            pwic_audit(sql, {'author': PWIC_USERS['system'],
                             'event': 'create-user',
                             'user': admin})

        # Add the project
        sql.execute(''' INSERT INTO projects (project, description, date) VALUES (?, ?, ?)''',
                    (project, description, dt['date']))
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'create-project',
                         'project': project})

        # Add the role
        sql.execute(''' INSERT INTO roles (project, user, admin) VALUES (?, ?, 'X')''', (project, admin))
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'grant-admin',
                         'project': project,
                         'user': admin})
        sql.execute(''' INSERT INTO roles (project, user, reader, disabled) VALUES (?, ?, 'X', 'X')''', (project, PWIC_USERS['anonymous']))
        sql.execute(''' INSERT INTO roles (project, user, reader, disabled) VALUES (?, ?, 'X', 'X')''', (project, PWIC_USERS['ghost']))

        # Add a default homepage
        sql.execute(''' INSERT INTO pages (project, page, revision, latest, header, author, date, time, title, markdown, comment)
                        VALUES (?, ?, 1, 'X', 'X', ?, ?, ?, 'Home', 'Thanks for using **Pwic.wiki**. This is the homepage.', 'Initial commit')''',
                    (project, PWIC_DEFAULTS['page'], admin, dt['date'], dt['time']))
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'create-revision',
                         'project': project,
                         'page': PWIC_DEFAULTS['page'],
                         'reference': 1})

        # Finalization
        self.db_commit()
        print('The project is created:')
        print('- Project       : %s' % project)
        print('- Administrator : %s' % admin)
        print('- Password      : "%s" or the existing password' % PWIC_DEFAULTS['password'])
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
        project = pwic_safe_name(project)
        if project == '' or sql.execute(''' SELECT project
                                            FROM projects
                                            WHERE project = ?''',
                                        (project, )).fetchone() is None:
            print('Error: the project "%s" does not exist' % project)
            return False

        # Verify that the user is valid and has changed his password
        admin = pwic_safe_user_name(admin)
        if admin[:4] == 'pwic':
            return False
        if sql.execute(''' SELECT user
                           FROM users
                           WHERE user    = ?
                             AND initial = '' ''',
                       (admin, )).fetchone() is None:
            print('Error: the user "%s" is unknown or has not changed his password yet' % admin)
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
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'grant-admin',
                         'project': project,
                         'user': admin})
        self.db_commit()
        print('The user "%s" is now an administrator of the project "%s"' % (admin, project))
        return True

    def split_project(self, projects: List[str], collapse: bool) -> bool:
        # Helpers
        def _transfer_record(sql: sqlite3.Cursor, table: str, row: Dict[str, Any]) -> None:
            query = ''' INSERT OR REPLACE INTO %s
                        (%s) VALUES (%s)''' % (table,
                                               ', '.join(row.keys()),
                                               ', '.join('?' * len(row)))
            sql.execute(query, [e for e in row.values()])

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
            if (sql.fetchone() is None) or (p != pwic_safe_name(p)):
                print('Error: unknown project "%s"' % p)
                return False

        # Create the new database
        fn = PWIC_DB_SQLITE_BACKUP % 'split'
        if isfile(fn):
            print('Error: the split database "%s" already exists' % fn)
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
            keep_last = collapse and (pwic_option(sql, p, 'validated_only') is None)
            sql.execute(''' SELECT *
                            FROM pages
                            WHERE project = ?''',
                        (p, ))
            for row in sql.fetchall():
                if keep_last:
                    if not pwic_xb(row['latest']):
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

        # Result
        newsql.execute(''' COMMIT''')
        for p in projects:
            pwic_audit(sql, {'author': PWIC_USERS['system'],
                             'event': 'split-project',
                             'project': p})
        self.db_commit()
        print('The projects "%s" are copied into the separate database "%s" without the audit data and the documents.' % (', '.join(projects), fn))
        return True

    def delete_project(self, project: str) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Verify that the project exists yet
        project = pwic_safe_name(project)
        if (project == '') or (sql.execute(''' SELECT project FROM projects WHERE project = ?''', (project, )).fetchone() is None):
            print('Error: the project "%s" does not exist' % project)
            return False

        # Confirm
        print('This operation is IRREVERSIBLE. You loose all the pages and the uploaded documents.')
        print('Type "YES" in uppercase to confirm the deletion of the project "%s": ' % project, end='')
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
            fn = join(PWIC_DOCUMENTS_PATH % project, row['filename'])
            if not PwicExtension.on_api_document_delete(sql, None, project, PWIC_USERS['system'], row['page'], row['id'], row['filename']):
                print('Error: unable to delete "%s"' % fn)
                self.db_rollback()
                return False
            if row['exturl'] == '':
                try:
                    os.remove(fn)
                except OSError:
                    if isfile(fn):
                        print('Error: unable to delete "%s"' % fn)
                        self.db_rollback()
                        return False

        # Remove the folder of the project used to upload files
        try:
            fn = PWIC_DOCUMENTS_PATH % project
            rmdir(fn)
        except OSError:
            print('Error: unable to remove "%s". The folder may be not empty' % fn)
            self.db_rollback()
            return False

        # Delete
        sql.execute(''' DELETE FROM env       WHERE project = ?''', (project, ))
        sql.execute(''' DELETE FROM documents WHERE project = ?''', (project, ))
        sql.execute(''' DELETE FROM cache     WHERE project = ?''', (project, ))
        sql.execute(''' DELETE FROM pages     WHERE project = ?''', (project, ))
        sql.execute(''' DELETE FROM roles     WHERE project = ?''', (project, ))
        sql.execute(''' DELETE FROM projects  WHERE project = ?''', (project, ))
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'delete-project',
                         'project': project})
        self.db_commit()
        print('\nThe project "%s" is deleted' % project)
        print('Warning: the file structure is now inconsistent with the old backups (if any)')
        return True

    def create_user(self, user: str) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Verify the user account
        user = pwic_safe_user_name(user)
        if user[:4] in ['', 'pwic']:
            print('Error: invalid user')
            return False
        sql.execute(''' SELECT user FROM users WHERE user = ?''', (user, ))
        if sql.fetchone() is not None:
            print('Error: the user "%s" already exists' % user)
            return False

        # Create the user account
        dt = pwic_dt()
        sql.execute(''' INSERT INTO users (user, password, initial, password_date, password_time)
                        VALUES (?, ?, 'X', ?, ?)''',
                    (user, pwic_sha256(PWIC_DEFAULTS['password']), dt['date'], dt['time']))
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'create-user',
                         'user': user})
        self.db_commit()
        print('The user "%s" is created with the default password "%s".' % (user, PWIC_DEFAULTS['password']))
        return True

    def reset_password(self, user: str, create: bool, oauth: bool) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Warn if the user is an administrator
        user = pwic_safe_user_name(user)
        new_account = sql.execute(''' SELECT 1 FROM users WHERE user = ?''', (user, )).fetchone() is None
        if (user[:4] in ['', 'pwic']) or (not create and new_account):
            print('Error: invalid user')
            return False
        if sql.execute(''' SELECT user
                           FROM roles
                           WHERE user  = ?
                             AND admin = 'X'
                           LIMIT 1''',
                       (user, )).fetchone() is not None:
            print("The user '%s' has administrative rights on some projects" % user)

        # Ask for a new password
        if oauth:
            if '@' not in user:
                print('Error: the user account is not an email')
                return False
            print('The user must use the federated authentication to log in')
            pwd = PWIC_MAGIC_OAUTH
            initial = ''
        else:
            print('Type the new temporary password with 8 characters at least: ', end='')
            pwd = input().strip()
            if len(pwd) < 8:
                print('Error: the password is too short')
                return False
            pwd = pwic_sha256(pwd)
            initial = 'X'

        # Reset the password with no rights takedown else some projects may loose their administrators
        dt = pwic_dt()
        if new_account:
            sql.execute(''' INSERT INTO users (user, password, initial, password_date, password_time)
                            VALUES (?, ?, ?, ?, ?)''',
                        (user, pwd, initial, dt['date'], dt['time']))
            pwic_audit(sql, {'author': PWIC_USERS['system'],
                             'event': 'create-user',
                             'user': user})
            print('\nThe password has been defined for the new user "%s"' % user)
        else:
            sql.execute(''' UPDATE users
                            SET password      = ?,
                                initial       = ?,
                                password_date = ?,
                                password_time = ?
                            WHERE user = ?''',
                        (pwd, initial, dt['date'], dt['time'], user))
            pwic_audit(sql, {'author': PWIC_USERS['system'],
                             'event': 'reset-password',
                             'user': user,
                             'string': PWIC_MAGIC_OAUTH if pwd == PWIC_MAGIC_OAUTH else ''})
            print('\nThe password has been changed for the user "%s"' % user)
        self.db_commit()
        return True

    def assign_user(self, project: str, user: str) -> bool:
        # Verify the parameters
        project = pwic_safe_name(project)
        user = pwic_safe_user_name(user)
        if (project in PWIC_NOT_PROJECT) or (user == ''):
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
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'grant-reader',
                         'project': project,
                         'user': user})
        self.db_commit()
        print('The user "%s" is added to the project "%s" as a reader' % (user, project))
        return True

    def revoke_user(self, user: str, force: bool) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Verify the user name
        user = pwic_safe_user_name(user)
        if user[:4] == 'pwic':
            print('Error: this user cannot be managed')
            return False
        if sql.execute(''' SELECT user
                           FROM users
                           WHERE user = ?''',
                       (user, )).fetchone() is None:
            print('Error: the user "%s" does not exist' % user)
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
        found = False
        for row in sql.fetchall():
            if not found:
                found = True
                tab = PrettyTable()
                tab.field_names = ['Project', 'Description']
                for f in tab.field_names:
                    tab.align[f] = 'l'
                if force:
                    print('Warning: the following projects will have no administrator anymore')
                else:
                    print('Error: organize a transfer of ownership for the following projects before revoking the user')
            tab.add_row([row['project'], row['description']])
        if found:
            tab.header = False
            tab.border = False
            print(tab.get_string())
            if not force:
                return False

        # Confirm
        if not force:
            print('This operation in mass needs your confirmation.')
            print('Type "YES" in uppercase to confirm the revocation of the user "%s": ' % user, end='')
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
            pwic_audit(sql, {'author': PWIC_USERS['system'],
                             'event': 'delete-user',
                             'project': row['project'],
                             'user': user})
        sql.execute(''' DELETE FROM roles WHERE user = ?''', (user, ))

        # Final
        self.db_commit()
        print('The user "%s" is fully unassigned to the projects but remains in the database' % user)
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
        tab = PrettyTable()
        tab.field_names = ['ID', 'Date', 'Time', 'Author', 'Event', 'User', 'Project', 'Page', 'Reference', 'IP', 'String']
        for f in tab.field_names:
            tab.align[f] = 'l'
        for row in sql.fetchall():
            tab.add_row([row['id'], row['date'], row['time'], row['author'], row['event'], row['user'], row['project'],
                         row['page'], '' if row['reference'] == 0 else str(row['reference']), row['ip'], row['string']])
        tab.header = True
        tab.border = True
        print(tab.get_string())
        return True

    def show_login(self, days: int) -> bool:
        # Select the data
        sql = self.db_connect()
        if sql is None:
            return False
        dt = pwic_dt(days=days)
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
        tab = PrettyTable()
        tab.field_names = ['User', 'Date', 'Time', 'Events']
        for f in tab.field_names:
            tab.align[f] = 'l'
        for row in sql.fetchall():
            tab.add_row([row['user'], row['date'], row['time'], row['events']])
        tab.header = True
        tab.border = True
        print(tab.get_string())
        return True

    def show_stats(self) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False
        dt = pwic_dt()

        # Structure of the log
        tab = PrettyTable()
        tab.field_names = ['Topic', 'Project / Key', 'Period', 'Value']
        for f in tab.field_names:
            tab.align[f] = 'l'
        tab.header = True
        tab.border = True

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
                    WHERE password = ?''', (PWIC_MAGIC_OAUTH, ))
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
                    WHERE total > 1''', (PWIC_MAGIC_OAUTH, ))
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
        print(tab.get_string())
        return True

    def show_inactivity(self, project: str, days: int) -> bool:
        # Select the data
        sql = self.db_connect()
        if sql is None:
            return False
        dt = pwic_dt(days=days)
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
        tab = PrettyTable()
        tab.field_names = ['User', 'Project', 'Roles']
        for f in tab.field_names:
            tab.align[f] = 'l'
        for row in sql.fetchall():
            roles = ''
            for k in ['admin', 'manager', 'editor', 'validator']:
                if pwic_xb(row[k]):
                    roles += k[:1].upper()
            tab.add_row([row['user'], row['project'], roles])
        tab.header = True
        tab.border = True
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
                            print('Compressing "%s"' % fn)
                            copyfileobj(src, dst)
                            counter += 1
                else:
                    try:
                        fn = fn + '.gz'
                        os.remove(fn)
                        print('Removing "%s"' % fn)
                        counter += 1
                    except OSError:
                        print('Failed to remove "%s"' % fn)
        if counter > 0:
            print('%d files were processed' % counter)
        return counter > 0

    def clear_cache(self, project: str, selective: bool) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Prepare the query
        project = pwic_safe_name(project)
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
        pwic_audit(sql, {'author': PWIC_USERS['system'],
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
        user = pwic_safe_user_name(user or PWIC_USERS['anonymous'])
        project = pwic_safe_name(project)
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
        if pwic_option(sql, '', 'https') is None:
            protocol = 'http'
        else:
            protocol = 'https'
            ssl._create_default_https_context = ssl._create_unverified_context

        # Authentication
        headers = {}
        if user[:4] != 'pwic':
            print('Password of the account "%s": ' % user, end='')
            try:
                response = urlopen(Request('%s://127.0.0.1:%d/api/login' % (protocol, port),
                                           urlencode({'user': user,
                                                      'password': input()}).encode(),
                                           method='POST'))
            except Exception as e:
                if isinstance(e, HTTPError):
                    print('Error: %d %s' % (pwic_int(e.getcode()), e.reason))
                elif isinstance(e, URLError):
                    print('Error: the host is not running or cannot be reached')
                else:
                    print(str(e))
                return False
            headers['Cookie'] = response.headers.get('Set-Cookie', '')

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
            if (((pwic_option(sql, p, 'no_cache') is not None)
                 or (pwic_option(sql, p, 'no_history') is not None)
                 or (pwic_option(sql, p, 'validated_only') is not None))):
                print('\rProject "%s" is excluded' % p)
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
                        url = '%s://127.0.0.1:%d/%s/%s/rev%d' % (protocol, port, row['project'], row['page'], row['revision'])
                        urlopen(Request(url, None, headers=headers, method='GET'))
                        once = True
                        ok += 1
                        if ok % 10 == 0:
                            print('\r%d pages' % ok, end='', flush=True)
                    except Exception:
                        ko += 1
                    if ok + ko > nmax:
                        print('\nError: possible infinite loop, check your options')
                        return False
                if not once:
                    break
        print('\r%d pages' % ok)
        del headers
        return (ok > 0) and (ko == 0)

    def rotate_logs(self, nfiles: int) -> bool:
        # Connect to the database
        sql = self.db_connect()
        if sql is None:
            return False

        # Read the file name
        fn = pwic_option(sql, '', 'http_log_file')
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
            os.remove('%s.%d.gz' % (fn, nfiles))
        except OSError:
            pass
        # ... rotate the files
        for i in reversed(range(1, nfiles)):    # i=[1..nfiles-1]
            try:
                rename('%s.%d.gz' % (fn, i),
                       '%s.%d.gz' % (fn, i + 1))
            except OSError:
                pass
        # ... compress the last file
        try:
            with open(fn + '.0', 'rb') as src:
                with gzip.open(fn + '.1.gz', 'wb') as dst:
                    copyfileobj(src, dst)
        except OSError:
            pass
        # ... remove the compressed file
        try:
            os.remove(fn + '.0')
        except OSError:
            pass
        # ... rotate the first file
        try:
            rename(fn + '.tmp', fn + '.0')
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
        dt = pwic_dt(days=max(mindays, selective))
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
            dt = pwic_dt(days=complete)
            sql.execute(''' DELETE FROM audit.audit
                            WHERE date < ?''',
                        (dt['date-nd'], ))

        # Result
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'archive-audit'})
        self.db_commit()
        print('%d entries moved to the table "audit_arch". Do what you want with them.' % counter)
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

    def create_backup(self, ) -> bool:
        # Check the database
        if not isfile(PWIC_DB_SQLITE):
            print('Error: the database is not created yet')
            return False

        # Prepare the new file name
        dt = pwic_dt()
        stamp = '%s_%s' % (dt['date'].replace('-', ''), dt['time'].replace(':', ''))
        new = PWIC_DB_SQLITE_BACKUP % stamp
        try:
            copyfile(PWIC_DB_SQLITE, new)
            if not isfile(new):
                raise FileNotFoundError('Error: file "%s" not created' % new)

            # Log the event
            audit_id = 0
            sql = self.db_connect()
            if sql is not None:
                sql.execute(''' SELECT MAX(id) AS id
                                FROM audit''')
                audit_id = pwic_int(sql.fetchone()['id'])
                pwic_audit(sql, {'author': PWIC_USERS['system'],
                                 'event': 'create-backup',
                                 'string': stamp})
                self.db_commit()

            # Mark the new database
            if audit_id > 0:
                sql = self.db_connect(master=False, dbfile=new)
                if sql is not None:
                    sql.execute(''' INSERT OR REPLACE INTO env (project, key, value)
                                    VALUES ('', 'pwic_audit_id', ?)''',
                                (audit_id, ))
                    self.db_commit()

            # Final
            chmod(new, S_IREAD)
            print('Backup of the main database created in "%s"' % new)
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
        magic_bytes = not no_magic and (pwic_option(sql, '', 'magic_bytes') is not None)
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
        multi = (project == '')
        tab = PrettyTable()
        tab.field_names = ['Action', 'Type', 'Project', 'Value', 'Reason']
        for f in tab.field_names:
            tab.align[f] = 'l'
        tab.header = True
        tab.border = True

        # Select the projects
        if not self.db_lock(sql):
            return False
        sql.execute(''' SELECT project
                        FROM projects
                        WHERE project <> ''
                        ORDER BY project''')
        for row in sql.fetchall():
            projects.append(pwic_safe_name(row['project']))
        if not multi:
            if project not in projects:
                self.db_commit()            # To end the empty transaction
                return False
            projects = [project]

        # Each project should have a folder
        for p in projects:
            path = PWIC_DOCUMENTS_PATH % p
            if not isdir(path):
                try:
                    if not test:
                        makedirs(path)
                    tab.add_row(['Create', 'Folder', p, path, 'Missing'])
                except OSError:
                    print('Failed to create the folder "%s"' % path)
                    projects.remove(p)
        if multi and not keep_orphans:
            dirs = sorted([f for f in listdir(PWIC_DOCUMENTS_PATH % '') if isdir(PWIC_DOCUMENTS_PATH % f)])
            for p in dirs:
                if p not in projects:
                    path = PWIC_DOCUMENTS_PATH % p
                    try:
                        for f in listdir(PWIC_DOCUMENTS_PATH % p):
                            if not test:
                                os.remove(join(path, f))    # No call to PwicExtension.on_api_document_delete because the project does not exist
                            tab.add_row(['Delete', 'File', p, join(path, f), 'Orphaned'])
                        if not test:
                            removedirs(path)
                        tab.add_row(['Delete', 'Folder', p, path, 'Orphaned'])
                    except OSError:
                        print('Failed to delete the folder "%s"' % path)

        # Check the files per project
        for p in projects:
            if not isdir(PWIC_DOCUMENTS_PATH % p):
                continue
            files = sorted([f for f in listdir(PWIC_DOCUMENTS_PATH % p) if isfile(join(PWIC_DOCUMENTS_PATH % p, f))])
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
                    if PwicExtension.on_api_document_delete(sql, None, p, PWIC_USERS['system'], None, None, row['filename']):
                        if not test:
                            sql.execute(''' DELETE FROM documents
                                            WHERE ID = ?''',
                                        (row['id'], ))
                        tab.add_row(['Delete', 'Database', p, '%d,%s' % (row['id'], row['filename']), 'Missing'])
            # Delete the left files that can't be reassigned to the right objects
            if not keep_orphans:
                for f in files:
                    if PwicExtension.on_api_document_delete(sql, None, p, PWIC_USERS['system'], None, None, f):
                        path = join(PWIC_DOCUMENTS_PATH % p, f)
                        try:
                            if not test:
                                os.remove(path)
                            tab.add_row(['Delete', 'File', p, path, 'Orphaned'])
                        except OSError:
                            print('Failed to delete the file "%s"' % path)

        # Verify the integrity of the files
        for p in projects:
            sql.execute(''' SELECT id, filename, mime, size, width, height, hash
                            FROM documents
                            WHERE project = ?
                              AND exturl  = '' ''',
                        (p, ))
            for row in sql.fetchall():
                path = join(PWIC_DOCUMENTS_PATH % p, row['filename'])
                try:
                    # Magic bytes
                    if magic_bytes:
                        magics = pwic_magic_bytes(splitext(path)[1][1:])
                        if magics is not None:
                            with open(path, 'rb') as fh:
                                content = fh.read(32)
                            ok = False
                            for mb in magics:
                                ok = ok or (content[:len(mb)] == pwic_str2bytearray(mb))
                            if not ok:
                                if not test:
                                    os.remove(path)
                                    sql.execute(''' DELETE FROM documents WHERE ID = ?''', (row['id'], ))
                                tab.add_row(['Delete', 'File', p, path, 'Unsafe'])
                                tab.add_row(['Delete', 'Database', p, '%d,%s' % (row['id'], row['filename']), 'Unsafe'])

                    # Size and hash
                    size = getsize(path)
                    hashval = row['hash'] if no_hash else pwic_sha256_file(path)
                    if (size != row['size']) or (hashval != row['hash']):
                        if not test:
                            sql.execute(''' UPDATE documents
                                            SET size = ?, hash = ?
                                            WHERE ID = ?''',
                                        (size, hashval, row['id']))
                        tab.add_row(['Update', 'Database', p, '%d,%s' % (row['id'], path), 'Modified'])

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
                                tab.add_row(['Update', 'Database', p, '%d,%s' % (row['id'], path), 'Modified'])
                        except ValueError:
                            pass

                except OSError:    # Can occur in test mode
                    print('Failed to analyze the file "%s"' % path)
                    continue

        # Result
        if tab.rowcount == 0:
            print('\nNo change occurred in the database or the file system.')
        else:
            print('\nList of the %d changes:' % tab.rowcount)
            print(tab.get_string())
            if not test:
                pwic_audit(sql, {'author': PWIC_USERS['system'],
                                 'event': 'repair-documents',
                                 'project': project,
                                 'string': str(tab.rowcount)},
                           None)
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
        if pwic_option(sql, '', 'https') is None:
            protocol = 'http'
        else:
            protocol = 'https'
            ssl._create_default_https_context = ssl._create_unverified_context

        # Connect to the API
        print('Sending the signal... ', end='', flush=True)
        try:
            url = '%s://127.0.0.1:%d/api/server/unlock' % (protocol, port)
            urlopen(Request(url, None, method='POST'))
            print('OK')
            return True
        except Exception as e:
            print('failed\nError: %s' % str(e))
            return False

    def execute_sql(self) -> bool:
        # Ask for a query
        tab = PrettyTable()
        print('This feature may corrupt the database. Please use it to upgrade Pwic.wiki upon explicit request only.')
        print("\nType the query to execute on a single line:")
        query = input()
        if len(query) > 0:

            # Ask for the confirmation
            print('\nAre you sure to execute << %s >> ?\nType "YES" to continue: ' % query, end='')
            if input() == 'YES':

                # Execute
                sql = self.db_connect()
                if sql is None:
                    return False
                sql.execute(query)
                rc = sql.rowcount

                # Buffering
                fields = None
                for row in sql.fetchall():
                    tab.add_row([str(row[k]).replace('\r', '').replace('\n', ' ')[:255] for k in row])
                    if (fields is None) and (row is not None) and (len(row) > 0):
                        fields = [k for k in row]

                # Trace
                pwic_audit(sql, {'author': PWIC_USERS['system'],
                                 'event': 'execute-sql',
                                 'string': query})
                self.db_commit()

                # Output
                print('Affected rows = %d' % rc)
                if fields is not None:
                    tab.field_names = fields
                    for f in tab.field_names:
                        tab.align[f] = 'l'
                    tab.header = True
                    tab.border = True
                    print(tab.get_string())
                return True

        # Default behavior
        print('Aborted')
        return False

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
        if pwic_option(sql, '', 'https') is None:
            protocol = 'http'
        else:
            protocol = 'https'
            ssl._create_default_https_context = ssl._create_unverified_context

        # Terminate
        print('Sending the kill signal... ', end='', flush=True)
        try:
            url = '%s://127.0.0.1:%d/api/server/shutdown' % (protocol, port)
            urlopen(Request(url, None, method='POST'))
        except Exception as e:
            if isinstance(e, RemoteDisconnected):
                print('OK')
                return True
            print('failed\nError: %s' % str(e))
        return False


# Entry point
app = PwicAdmin()
if app.main():
    exit(0)
else:
    print('\nThe operation failed')
    exit(1)
