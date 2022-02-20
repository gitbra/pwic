#!/usr/bin/env python

from typing import Optional, Dict, List, Tuple, Any
import argparse
import sqlite3
from prettytable import PrettyTable
import imagesize
import gzip
import datetime
import sys
import os
from os import chmod, listdir, makedirs, mkdir, removedirs, rmdir
from os.path import getsize, isdir, isfile, join, splitext
from shutil import copyfile, copyfileobj
from stat import S_IREAD
from urllib.request import Request, urlopen
from http.client import RemoteDisconnected

from pwic_lib import PWIC_VERSION, PWIC_DB, PWIC_DB_SQLITE, PWIC_DB_SQLITE_BACKUP, PWIC_DB_SQLITE_AUDIT, PWIC_DOCUMENTS_PATH, \
    PWIC_USERS, PWIC_DEFAULTS, PWIC_PRIVATE_KEY, PWIC_PUBLIC_KEY, PWIC_ENV_PROJECT_INDEPENDENT, PWIC_ENV_PROJECT_DEPENDENT, \
    PWIC_ENV_PRIVATE, PWIC_MAGIC_OAUTH, pwic_audit, pwic_dt, pwic_int, pwic_option, pwic_list, pwic_magic_bytes, \
    pwic_row_factory, pwic_safe_name, pwic_safe_user_name, pwic_sha256, pwic_sha256_file, pwic_str2bytearray, pwic_xb
from pwic_extension import PwicExtension


db = None


def main() -> bool:
    # Default encoding
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

    # Prepare the command line (subparsers cannot be grouped)
    parser = argparse.ArgumentParser(prog='python3 pwic_admin.py', description='Pwic Management Console v%s' % PWIC_VERSION)

    subparsers = parser.add_subparsers(dest='command')

    # ... Initialization
    subparsers.add_parser('generate-ssl', help='Generate the self-signed certificates')

    subparsers.add_parser('init-db', help='Initialize the database once')

    spb = subparsers.add_parser('show-env', help='Show the current configuration')
    spb.add_argument('--project', default='', help='Name of the project')
    spb.add_argument('--var', default='', help='Name of the variable for exclusive display')

    spb = subparsers.add_parser('set-env', help='Set a global or a project-dependent parameter')
    spb.add_argument('--project', default='', help='Name of the project (if project-dependent)')
    spb.add_argument('name', default='', help='Name of the variable')
    spb.add_argument('value', default='', help='Value of the variable')
    spb.add_argument('--override', action='store_true', help='Remove the existing project-dependent values')

    subparsers.add_parser('repair-env', help='Fix the incorrect environment variables')

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

    spb = subparsers.add_parser('archive-audit', help='Clean the obsolete entries of audit')
    spb.add_argument('--selective', type=int, default=90, help='Horizon for a selective cleanup', metavar='90')
    spb.add_argument('--complete', type=int, default=0, help='Horizon for a complete cleanup', metavar='365')

    subparsers.add_parser('create-backup', help='Make a backup copy of the database file *without* the attached documents')

    spb = subparsers.add_parser('repair-documents', help='Repair the index of the documents (recommended after the database is restored)')
    spb.add_argument('--project', default='', help='Name of the project (if project-dependent)')
    spb.add_argument('--no-hash', action='store_true', help='Do not recalculate the hashes of the files (faster but not recommended)')
    spb.add_argument('--no-magic', action='store_true', help='Do not verify the magic bytes of the files')
    spb.add_argument('--keep-orphans', action='store_true', help='Do not delete the orphaned folders and files')
    spb.add_argument('--test', action='store_true', help='Verbose simulation')

    subparsers.add_parser('execute-optimize', help='Run the optimizer')

    subparsers.add_parser('execute-sql', help='Execute an SQL query on the database (dangerous)')

    spb = subparsers.add_parser('shutdown-server', help='Terminate the server')
    spb.add_argument('--port', type=int, default=PWIC_DEFAULTS['port'], help='Target instance defined by the listened port', metavar=PWIC_DEFAULTS['port'])

    # Parse the command line
    args = parser.parse_args()
    if args.command == 'generate-ssl':
        return generate_ssl()
    elif args.command == 'init-db':
        return init_db()
    elif args.command == 'show-env':
        return show_env(args.project, args.var)
    elif args.command == 'set-env':
        return set_env(args.project, args.name, args.value, args.override)
    elif args.command == 'repair-env':
        return repair_env()
    elif args.command == 'show-mime':
        return show_mime()
    elif args.command == 'show-projects':
        return show_projects()
    elif args.command == 'create-project':
        return create_project(args.project, args.description, args.admin)
    elif args.command == 'takeover-project':
        return takeover_project(args.project, args.admin)
    elif args.command == 'split-project':
        return split_project(args.project, args.no_history)
    elif args.command == 'delete-project':
        return delete_project(args.project)
    elif args.command == 'create-user':
        return create_user(args.user)
    elif args.command == 'reset-password':
        return reset_password(args.user, args.create, args.oauth)
    elif args.command == 'revoke-user':
        return revoke_user(args.user, args.force)
    elif args.command == 'show-audit':
        return show_audit(args.min, args.max)
    elif args.command == 'show-login':
        return show_login(args.days)
    elif args.command == 'show-stats':
        return show_stats()
    elif args.command == 'show-inactivity':
        return show_inactivity(args.project, args.days)
    elif args.command == 'compress-static':
        return compress_static(args.revert)
    elif args.command == 'clear-cache':
        return clear_cache(args.project)
    elif args.command == 'archive-audit':
        return archive_audit(args.selective, args.complete)
    elif args.command == 'create-backup':
        return create_backup()
    elif args.command == 'repair-documents':
        return repair_documents(args.project, args.no_hash, args.no_magic, args.keep_orphans, args.test)
    elif args.command == 'execute-optimize':
        return execute_optimize()
    elif args.command == 'execute-sql':
        return execute_sql()
    elif args.command == 'shutdown-server':
        return shutdown_server(args.port)
    else:
        parser.print_help()
        return False


# ===== Database =====

def db_connect(init: bool = False, master: bool = True, dbfile: str = PWIC_DB_SQLITE) -> Optional[sqlite3.Cursor]:
    global db
    if not init and not isfile(dbfile):
        print('Error: the database is not created yet')
        return None
    try:
        db = sqlite3.connect(dbfile)
        db.row_factory = pwic_row_factory
        sql = db.cursor()
        sql.execute(''' PRAGMA main.journal_mode = MEMORY''')
        if master:
            sql.execute(''' ATTACH DATABASE ? AS audit''', (PWIC_DB_SQLITE_AUDIT, ))
            sql.execute(''' PRAGMA audit.journal_mode = MEMORY''')
        return sql
    except sqlite3.OperationalError:
        print('Error: the database cannot be opened')
        return None


def db_lock(sql: sqlite3.Cursor) -> bool:
    if sql is None:
        return False
    try:
        sql.execute(''' BEGIN EXCLUSIVE TRANSACTION''')
        return True
    except sqlite3.OperationalError:
        return False


def db_create_tables_audit() -> bool:
    sql = db_connect(init=True, master=False, dbfile=PWIC_DB_SQLITE_AUDIT)
    if sql is None:
        return False

    # Table AUDIT
    sql.execute('''
CREATE TABLE "audit" (
    "id" INTEGER NOT NULL,
    "date" TEXT NOT NULL,
    "time" TEXT NOT NULL,
    "author" TEXT NOT NULL,
    "event" TEXT NOT NULL,
    "user" TEXT NOT NULL DEFAULT '',
    "project" TEXT NOT NULL DEFAULT '',
    "page" TEXT NOT NULL DEFAULT '',
    "revision" INTEGER NOT NULL DEFAULT 0,
    "string" TEXT NOT NULL DEFAULT '',
    "ip" TEXT NOT NULL DEFAULT '',
    PRIMARY KEY("id" AUTOINCREMENT)
)''')
    sql.execute('''
CREATE TABLE "audit_arch" (
    "id" INTEGER NOT NULL,
    "date" TEXT NOT NULL,
    "time" TEXT NOT NULL,
    "author" TEXT NOT NULL,
    "event" TEXT NOT NULL,
    "user" TEXT NOT NULL,
    "project" TEXT NOT NULL,
    "page" TEXT NOT NULL,
    "revision" INTEGER NOT NULL,
    "string" TEXT NOT NULL,
    "ip" TEXT NOT NULL,
    PRIMARY KEY("id")       -- No AUTOINCREMENT
)''')

    # Triggers
    sql.execute('''
CREATE TRIGGER audit_no_update
    BEFORE UPDATE ON audit
BEGIN
    SELECT RAISE (ABORT, 'The table AUDIT should not be modified');
END''')
    sql.execute('''
CREATE TRIGGER audit_archiver
    BEFORE DELETE ON audit
BEGIN
    INSERT INTO audit_arch
        SELECT *
        FROM audit
        WHERE id = OLD.id;
END''')
    db_commit()
    return True


def db_create_tables_main(dbfile: str = PWIC_DB_SQLITE) -> bool:
    sql = db_connect(init=True, master=True, dbfile=dbfile)
    if sql is None:
        return False
    dt = pwic_dt()

    # Table PROJECTS
    sql.execute('''
CREATE TABLE "projects" (
    "project" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "date" TEXT NOT NULL,
    PRIMARY KEY("project")
)''')
    sql.execute(''' INSERT INTO projects (project, description, date) VALUES ('', '', '')''')   # Empty projects.project

    # Table ENV
    sql.execute('''
CREATE TABLE "env" (
    "project" TEXT NOT NULL,    -- Never default to ''
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    FOREIGN KEY("project") REFERENCES "projects"("project"),
    PRIMARY KEY("key","project")
)''')

    # Table USERS
    sql.execute('''
CREATE TABLE "users" (
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
    sql.execute('''
CREATE TABLE "roles" (
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
    sql.execute('''
CREATE TABLE "pages" (
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
    sql.execute('''
CREATE INDEX "pages_index" ON "pages" (
    "project" ASC,
    "page" ASC,
    "latest" ASC
)''')

    # Table CACHE
    sql.execute('''
CREATE TABLE "cache" (
    "project" TEXT NOT NULL,
    "page" TEXT NOT NULL,
    "revision" INTEGER NOT NULL,
    "html" TEXT NOT NULL,
    FOREIGN KEY("project") REFERENCES "projects"("project"),
    PRIMARY KEY("project","page","revision")
)''')

    # Table DOCUMENTS
    sql.execute('''
CREATE TABLE "documents" (
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
    db_commit()
    return True


def db_commit() -> None:
    global db
    if db is not None:
        db.commit()


def db_rollback() -> None:
    global db
    if db is not None:
        db.rollback()


# ===== Methods =====

def generate_ssl() -> bool:
    # stackoverflow.com/questions/51645324

    # Check the database
    if not isdir(PWIC_DB):
        print('Error: the database is not created yet')
        return False

    # Imports
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        return False

    # Private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    with open(PWIC_PRIVATE_KEY, 'wb') as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.NoEncryption()))

    # Public key
    def _ssl_input(topic: str, sample: str) -> str:
        print('%s (ex: %s) : ' % (topic, sample), end='')
        return input()

    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, _ssl_input('ISO code of the country on 2 characters', 'FR')),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, _ssl_input('Full country', 'France')),
        x509.NameAttribute(NameOID.LOCALITY_NAME, _ssl_input('Your town', 'Paris')),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, _ssl_input('Your organization', 'Pwic')),
        x509.NameAttribute(NameOID.COMMON_NAME, _ssl_input('Common name', 'Pwic')),
    ])
    hosts = pwic_list(_ssl_input('Your hosts separated by space', 'www.your.tld'))
    if len(hosts) == 0:
        return False
    cert = x509.CertificateBuilder() \
               .subject_name(issuer) \
               .issuer_name(issuer) \
               .public_key(key.public_key()) \
               .serial_number(x509.random_serial_number()) \
               .not_valid_before(datetime.datetime.utcnow()) \
               .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365 * 5)) \
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]), critical=False) \
               .sign(key, hashes.SHA256(), default_backend())
    with open(PWIC_PUBLIC_KEY, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Final output
    sql = db_connect()
    if sql is not None:
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'generate-ssl'})
        db_commit()
    print('\nThe SSL certificates are generated:')
    print('- Private key: ' + PWIC_PRIVATE_KEY)
    print('- Public key: ' + PWIC_PUBLIC_KEY)
    return True


def init_db() -> bool:
    # Check that the database does not exist already
    if not isdir(PWIC_DB):
        mkdir(PWIC_DB)
    if isfile(PWIC_DB_SQLITE) or isfile(PWIC_DB_SQLITE_AUDIT):
        print('Error: the databases are already created')
        return False

    # Create the dbfiles
    ok = db_create_tables_audit() and db_create_tables_main()
    if not ok:
        print('Error: the databases cannot be created')
        return False

    # Connect to the databases
    sql = db_connect()
    if sql is None:
        print('Error: the databases cannot be opened')
        return False

    # Add the default, safe or mandatory configuration
    pwic_audit(sql, {'author': PWIC_USERS['system'],
                     'event': 'init-db'})
    for (key, value) in [('base_url', 'http://127.0.0.1:%s' % PWIC_DEFAULTS['port']),
                         ('file_formats', 'md html odt'),
                         ('robots', 'noarchive noindex nofollow'),
                         ('safe_mode', 'X')]:
        sql.execute(''' INSERT INTO env (project, key, value)
                        VALUES ('', ?, ?)''',
                    (key, value))
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'set-%s' % key,
                         'string': '' if key in PWIC_ENV_PRIVATE else value})

    # Confirmation
    db_commit()
    print('The databases are created in "%s" and "%s"' % (PWIC_DB_SQLITE, PWIC_DB_SQLITE_AUDIT))
    return True


def show_env(project: str, var: str) -> bool:
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
    sql = db_connect()
    if sql is None:
        return False
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
    found = False
    tab = PrettyTable()
    tab.field_names = ['Project', 'Key', 'Value']
    for f in tab.field_names:
        tab.align[f] = 'l'
    tab.header = True
    tab.border = True
    for row in sql.fetchall():
        if (project != '') and (row['project'] not in ['', project]):
            continue
        value = '(Secret value not displayed)' if (row['key'] in PWIC_ENV_PRIVATE) or (row['key'][:4] == 'pwic') else row['value']
        value = value.replace('\r', '').replace('\n', '\\n')
        tab.add_row([row['project'], row['key'], value])
        found = True
    if found:
        print('\nGlobal and project-dependent Pwic variables:')
        print(tab.get_string())
        return True
    else:
        return var == ''


def set_env(project: str, key: str, value: str, override: bool) -> bool:
    # Check the parameters
    if override and (project != ''):
        print('Error: useless parameter --override if a project is indicated')
        return False
    allkeys = sorted(PWIC_ENV_PROJECT_INDEPENDENT + PWIC_ENV_PROJECT_DEPENDENT)
    if key not in allkeys:
        print('Error: the name of the variable must be one of "%s"' % ', '.join(allkeys))
        return False
    if (project != '') and (key in PWIC_ENV_PROJECT_INDEPENDENT):
        print('Error: the parameter is project-independent')
        return False
    value = value.strip().replace('\r', '')

    # Connect to the database
    sql = db_connect()
    if sql is None:
        return False

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
    db_commit()
    if project != '':
        print('Variable %s for the project "%s"' % (verb, project))
    else:
        print('Variable %s globally' % verb)
    return True


def repair_env() -> bool:
    # Connect to the database
    sql = db_connect()
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
           (row['value'] == ''):
            buffer.append((row['project'], row['key']))
    for e in buffer:
        sql.execute(''' DELETE FROM env
                        WHERE project = ?
                          AND key     = ?''', e)
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'unset-%s' % e[1],
                         'project': e[0]})

    # Report
    if len(buffer) == 0:
        print('No change is required.')
    else:
        db_commit()
        tab = PrettyTable()
        tab.field_names = ['Project', 'Variable']
        for f in tab.field_names:
            tab.align[f] = 'l'
        tab.header = True
        tab.border = True
        tab.add_rows(buffer)
        print(tab.get_string())
    return True


def show_mime() -> bool:
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
                value, type = winreg.QueryValueEx(handle, 'Content Type')
            except FileNotFoundError:
                value, type = None, winreg.REG_NONE
            winreg.CloseKey(handle)

            # Consider the mime if it exists
            if type == winreg.REG_SZ:
                tab.add_row([name, value])

    # Final output
    print(tab.get_string())
    return True


def show_projects() -> bool:
    # Connect to the database
    sql = db_connect()
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


def create_project(project: str, description: str, admin: str) -> bool:
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
    sql = db_connect()
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
    assert(sql.rowcount > 0)
    pwic_audit(sql, {'author': PWIC_USERS['system'],
                     'event': 'create-project',
                     'project': project})

    # Add the role
    sql.execute(''' INSERT INTO roles (project, user, admin) VALUES (?, ?, 'X')''', (project, admin))
    assert(sql.rowcount > 0)
    pwic_audit(sql, {'author': PWIC_USERS['system'],
                     'event': 'grant-admin',
                     'project': project,
                     'user': admin})
    sql.execute(''' INSERT INTO roles (project, user, reader, disabled) VALUES (?, ?, 'X', 'X')''', (project, PWIC_USERS['anonymous']))
    sql.execute(''' INSERT INTO roles (project, user, reader, disabled) VALUES (?, ?, 'X', 'X')''', (project, PWIC_USERS['ghost']))

    # Add a default homepage
    sql.execute(''' INSERT INTO pages (project, page, revision, latest, header, author, date, time, title, markdown, comment)
                    VALUES (?, ?, 1, 'X', 'X', ?, ?, ?, 'Home', 'Thanks for using Pwic. This is the homepage.', 'Initial commit')''',
                (project, PWIC_DEFAULTS['page'], admin, dt['date'], dt['time']))
    assert(sql.rowcount > 0)
    pwic_audit(sql, {'author': PWIC_USERS['system'],
                     'event': 'create-revision',
                     'project': project,
                     'page': PWIC_DEFAULTS['page'],
                     'revision': 1})

    # Finalization
    db_commit()
    print('The project is created:')
    print('- Project       : %s' % project)
    print('- Administrator : %s' % admin)
    print('- Password      : "%s" or the existing password' % PWIC_DEFAULTS['password'])
    print('')
    print("To create new pages in the project, you must change your password and grant the role 'manager' or 'editor' to the suitable user account.")
    print('')
    print('Thanks for using Pwic!')
    return True


def takeover_project(project: str, admin: str) -> bool:
    # Connect to the database
    sql = db_connect()
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
    if not db_lock(sql):
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
    db_commit()
    print('The user "%s" is now an administrator of the project "%s"' % (admin, project))
    return True


def split_project(projects: List[str], collapse: bool) -> bool:
    # Helpers
    def _transfer_record(sql: sqlite3.Cursor, table: str, row: Dict[str, Any]) -> None:
        query = ''' INSERT OR REPLACE INTO %s
                    (%s) VALUES (%s)''' % (table,
                                           ', '.join(row.keys()),
                                           ', '.join('?' * len(row)))
        sql.execute(query, [e for e in row.values()])

    # Connect to the database
    sql = db_connect()                      # Don't lock this connection
    if sql is None:
        return False

    # Fetch the projects
    projects = sorted(set(projects))
    assert(len(projects) > 0)
    ok = True
    for p in projects:
        sql.execute(''' SELECT project
                        FROM projects
                        WHERE project = ?''',
                    (p, ))
        if sql.fetchone() is None:
            ok = False
            projects.remove(p)
            print('Error: unknown project "%s"' % p)
    if not ok:
        return False

    # Create the new database
    fn = PWIC_DB_SQLITE_BACKUP % 'split'
    if isfile(fn):
        print('Error: the split database "%s" already exists' % fn)
        return False
    if not db_create_tables_main(fn):
        print('Error: the tables cannot be created in the the split database')
        return False
    try:
        newsql = sqlite3.connect(fn).cursor()
    except sqlite3.OperationalError:
        print('Error: the split database cannot be opened')
        return False

    # Transfer the data
    if not db_lock(sql):
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
        sql.execute(''' SELECT *
                        FROM pages
                        WHERE project = ?''',
                    (p, ))
        for row in sql.fetchall():
            if collapse:
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
    db_commit()
    print('The projects "%s" are copied into the separate database "%s" without the audit data and the documents.' % (', '.join(projects), fn))
    return True


def delete_project(project: str) -> bool:
    # Connect to the database
    sql = db_connect()
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
    if not db_lock(sql):
        return False
    sql.execute(''' SELECT id, page, filename, exturl
                    FROM documents
                    WHERE project = ?''',
                (project, ))
    for row in sql.fetchall():
        fn = join(PWIC_DOCUMENTS_PATH % project, row['filename'])
        if not PwicExtension.on_api_document_delete(sql, project, PWIC_USERS['system'], row['page'], row['id'], row['filename']):
            print('Error: unable to delete "%s"' % fn)
            db_rollback()
            return False
        if row['exturl'] == '':
            try:
                os.remove(fn)
            except (OSError, FileNotFoundError):
                if isfile(fn):
                    print('Error: unable to delete "%s"' % fn)
                    db_rollback()
                    return False

    # Remove the folder of the project used to upload files
    try:
        fn = PWIC_DOCUMENTS_PATH % project
        rmdir(fn)
    except OSError:
        print('Error: unable to remove "%s". The folder may be not empty' % fn)
        db_rollback()
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
    db_commit()
    print('\nThe project "%s" is deleted' % project)
    print('Warning: the file structure is now inconsistent with the old backups (if any)')
    return True


def create_user(user: str) -> bool:
    # Connect to the database
    sql = db_connect()
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
    db_commit()
    print('The user "%s" is created with the default password "%s".' % (user, PWIC_DEFAULTS['password']))
    return True


def reset_password(user: str, create: bool, oauth: bool) -> bool:
    # Connect to the database
    sql = db_connect()
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
    db_commit()
    return True


def revoke_user(user: str, force: bool) -> bool:
    # Connect to the database
    sql = db_connect()
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
    if not db_lock(sql):
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
    db_commit()
    print('The user "%s" is fully unassigned to the projects but remains in the database' % user)
    return True


def show_audit(dmin: int, dmax: int) -> bool:
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
    sql = db_connect()
    if sql is None:
        return False
    sql.execute(''' SELECT id, date, time, author, event, user,
                           project, page, revision, ip, string
                    FROM audit.audit
                    WHERE date >= ? AND date <= ?
                    ORDER BY id ASC''',
                (dmin_str, dmax_str))

    # Report the log
    tab = PrettyTable()
    tab.field_names = ['ID', 'Date', 'Time', 'Author', 'Event', 'User', 'Project', 'Page', 'Revision', 'IP', 'String']
    for f in tab.field_names:
        tab.align[f] = 'l'
    for row in sql.fetchall():
        tab.add_row([row['id'], row['date'], row['time'], row['author'], row['event'], row['user'], row['project'], row['page'], row['revision'], row['ip'], row['string']])
    tab.header = True
    tab.border = True
    print(tab.get_string())
    return True


def show_login(days: int) -> bool:
    # Select the data
    sql = db_connect()
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


def show_stats() -> bool:
    # Connect to the database
    sql = db_connect()
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
            tab.add_row([kpi,
                         row.get('project', ''),
                         row.get('period', ''),
                         row.get('kpi', '')])

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
                            AND b.key     = 'max_project_size'
                        LEFT OUTER JOIN env AS c
                            ON  c.project = ''
                            AND c.key     = 'max_project_size'
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


def show_inactivity(project: str, days: int) -> bool:
    # Select the data
    sql = db_connect()
    if sql is None:
        return False
    dt = pwic_dt(days=days)
    sql.execute(''' SELECT b.date, a.user, a.project, a.admin
                    FROM roles AS a
                        INNER JOIN (
                            SELECT project, author, MAX(date) AS date
                            FROM audit.audit
                            WHERE (project = ?) OR ('' = ?)
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
                      AND b.date       <= ?
                    ORDER BY b.date, a.user, a.project''',
                (project, project, project, project, dt['date-nd']))

    # Report the log
    tab = PrettyTable()
    tab.field_names = ['Last date', 'User', 'Project', 'Administrator']
    for f in tab.field_names:
        tab.align[f] = 'l'
    for row in sql.fetchall():
        tab.add_row([row['date'], row['user'], row['project'], row['admin']])
    tab.header = True
    tab.border = True
    print(tab.get_string())
    return True


def compress_static(revert: bool) -> bool:
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
                except (OSError, FileNotFoundError):
                    print('Failed to remove "%s"' % fn)
    if counter > 0:
        print('%d files were processed' % counter)
    return counter > 0


def clear_cache(project: str) -> bool:
    # Connect to the database
    sql = db_connect()
    if sql is None:
        return False

    # Clear the cache
    project = pwic_safe_name(project)
    if project != '':
        sql.execute(''' DELETE FROM cache WHERE project = ?''', (project, ))
    else:
        sql.execute(''' DELETE FROM cache''')
    pwic_audit(sql, {'author': PWIC_USERS['system'],
                     'event': 'clear-cache',
                     'project': project})
    db_commit()
    print('The cache is cleared. Do expect a workload of regeneration for a short period of time.')
    return True


def archive_audit(selective: int, complete: int) -> bool:
    # Connect to the database
    sql = db_connect()
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
    if not db_lock(sql):
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
    db_commit()
    print('%d entries moved to the table "audit_arch". Do what you want with it.' % counter)
    return True


def create_backup() -> bool:
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
        if isfile(new):
            # Log the event
            audit_id = 0
            sql = db_connect()
            if sql is not None:
                sql.execute(''' SELECT MAX(id) AS id
                                FROM audit''')
                audit_id = pwic_int(sql.fetchone()['id'])
                pwic_audit(sql, {'author': PWIC_USERS['system'],
                                 'event': 'create-backup',
                                 'string': stamp})
                db_commit()

            # Mark the new database
            if audit_id > 0:
                sql = db_connect(master=False, dbfile=new)
                if sql is not None:
                    sql.execute(''' INSERT OR REPLACE INTO env (project, key, value)
                                    VALUES ('', 'pwic_audit_id', ?)''',
                                (audit_id, ))
                    db_commit()

            # Final
            chmod(new, S_IREAD)
            print('Backup of the main database created in "%s"' % new)
            print('The uploaded documents remain in their place')
            return True
        else:
            raise FileNotFoundError('Error: file "%s" not created' % new)
    except Exception as e:
        print(str(e))
        return False


def repair_documents(project: str, no_hash: bool, no_magic: bool, keep_orphans: bool, test: bool) -> bool:
    # Connect to the database
    sql = db_connect()
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
    if not db_lock(sql):
        return False
    sql.execute(''' SELECT project
                    FROM projects
                    WHERE project <> ''
                    ORDER BY project''')
    for row in sql.fetchall():
        projects.append(pwic_safe_name(row['project']))
    if not multi:
        if project not in projects:
            db_commit()     # To end the empty transaction
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
                except (OSError, FileNotFoundError):
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
                if PwicExtension.on_api_document_delete(sql, p, PWIC_USERS['system'], None, None, row['filename']):
                    if not test:
                        sql.execute(''' DELETE FROM documents
                                        WHERE ID = ?''',
                                    (row['id'], ))
                    tab.add_row(['Delete', 'Database', p, '%d,%s' % (row['id'], row['filename']), 'Missing'])
        # Delete the left files that can't be reassigned to the right objects
        if not keep_orphans:
            for f in files:
                if PwicExtension.on_api_document_delete(sql, p, PWIC_USERS['system'], None, None, f):
                    path = join(PWIC_DOCUMENTS_PATH % p, f)
                    try:
                        if not test:
                            os.remove(path)
                        tab.add_row(['Delete', 'File', p, path, 'Orphaned'])
                    except (OSError, FileNotFoundError):
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
                        for bytes in magics:
                            ok = ok or (content[:len(bytes)] == pwic_str2bytearray(bytes))
                        if not ok:
                            if not test:
                                os.remove(path)
                                sql.execute(''' DELETE FROM documents WHERE ID = ?''', (row['id'], ))
                            tab.add_row(['Delete', 'File', p, path, 'Unsafe'])
                            tab.add_row(['Delete', 'Database', p, '%d,%s' % (row['id'], row['filename']), 'Unsafe'])

                # Size and hash
                size = getsize(path)
                hash = row['hash'] if no_hash else pwic_sha256_file(path)
                if (size != row['size']) or (hash != row['hash']):
                    if not test:
                        sql.execute(''' UPDATE documents
                                        SET size = ?, hash = ?
                                        WHERE ID = ?''',
                                    (size, hash, row['id']))
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

            except (OSError, FileNotFoundError):    # Can occur in test mode
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
    db_commit()
    return True


def execute_optimize() -> bool:
    # The documentation of SQLite states that long-running applications might benefit from running this command every few hours

    # Connect to the database
    sql = db_connect()
    if sql is None:
        return False

    # Run the optimizer
    sql.execute(''' PRAGMA optimize''')
    print('Done.')
    return True


def execute_sql() -> bool:
    # Ask for a query
    tab = PrettyTable()
    print('This feature may corrupt the database. Please use it to upgrade Pwic upon explicit request only.')
    print("\nType the query to execute on a single line:")
    query = input()
    if len(query) > 0:

        # Ask for the confirmation
        print('\nAre you sure to execute << %s >> ?\nType "YES" to continue: ' % query, end='')
        if input() == 'YES':

            # Execute
            sql = db_connect()
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
            db_commit()

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


def shutdown_server(port: int) -> bool:
    # Connect to the database
    sql = db_connect()
    if sql is None:
        return False

    # Ask for confirmation
    print('This command will try to terminate Pwic server at its earliest convenience.')
    print('This will disconnect the users and interrupt their work.')
    print('Type "YES" to agree and continue: ', end='')
    if input() != 'YES':
        return False

    # Authorize
    if not db_lock(sql):
        return False
    sql.execute(''' INSERT OR IGNORE INTO env (project, key, value)
                    VALUES ('', 'pwic_shutdown', 'X')''')
    pwic_audit(sql, {'author': PWIC_USERS['system'],
                     'event': 'set-pwic_shutdown',
                     'string': 'X'})
    db_commit()

    # Terminate
    print('Sending the kill signal... ', end='', flush=True)
    ok = False
    try:
        ssl = pwic_option(sql, '', 'ssl') is not None
        url = 'http%s://127.0.0.1:%d/api/server/shutdown' % ('s' if ssl else '', port)
        urlopen(Request(url, None, method='POST'))
    except Exception as e:
        if isinstance(e, RemoteDisconnected):
            ok = True
            print('OK')
        else:
            print('failed\nError: %s' % str(e))

    # Remove the authorization after a failure
    if not ok:
        sql.execute(''' DELETE FROM env
                        WHERE project = ''
                          AND key     = 'pwic_shutdown' ''')
        if sql.rowcount > 0:
            pwic_audit(sql, {'author': PWIC_USERS['system'],
                             'event': 'unset-pwic_shutdown',
                             'string': 'Shutdown failed'})
        db_commit()
    return ok


if main():
    exit(0)
else:
    print('\nThe operation failed')
    exit(1)
