#!/usr/bin/env python

from typing import Optional
import argparse
import sqlite3
from prettytable import PrettyTable
import re
import gzip
import datetime
import sys
import os
from os.path import getsize, isdir, isfile, join
from shutil import copyfile, copyfileobj
from stat import S_IREAD

from pwic_lib import PWIC_DB, PWIC_DB_SQLITE, PWIC_DB_SQLITE_BACKUP, PWIC_DOCUMENTS_PATH, PWIC_USERS, PWIC_DEFAULTS, \
    PWIC_PRIVATE_KEY, PWIC_PUBLIC_KEY, PWIC_ENV_PROJECT_INDEPENDENT, PWIC_ENV_PROJECT_DEPENDENT, \
    PWIC_ENV_PRIVATE, PWIC_MAGIC_OAUTH, pwic_audit, pwic_dt, pwic_list, pwic_row_factory, pwic_sha256, \
    pwic_safe_name, pwic_safe_user_name


db = None


def main() -> bool:
    # Default encoding
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

    # Prepare the command line
    parser = argparse.ArgumentParser(prog='python pwic_admin.py', description='Pwic Management Console')
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('generate-ssl', help='Generate the self-signed certificates')

    subparsers.add_parser('init-db', help='Initialize the database once')

    spb = subparsers.add_parser('show-env', help='Show the current configuration')
    spb.add_argument('--var', default='', help='Name of the variable for exclusive display')

    spb = subparsers.add_parser('set-env', help='Set a global or a project-dependent parameter')
    spb.add_argument('--project', default='', help='Name of the project (if project-dependent)')
    spb.add_argument('name', default='', help='Name of the variable')
    spb.add_argument('value', default='', help='Value of the variable')
    spb.add_argument('--override', action='store_true', help='Remove the existing project-dependent values')

    subparsers.add_parser('show-mime', help='Show the MIME types defined on the server (Windows only)')

    subparsers.add_parser('create-backup', help='Make a backup copy of the database file *without* the attached documents')

    subparsers.add_parser('show-projects', help='Show the existing projects')

    spb = subparsers.add_parser('create-project', help='Create a new project')
    spb.add_argument('project', default='', help='Project name')
    spb.add_argument('description', default='', help='Project description')
    spb.add_argument('admin', default='', help='User name of the administrator of the project')

    spb = subparsers.add_parser('takeover-project', help='Assign an administrator to a project')
    spb.add_argument('project', default='', help='Project name')
    spb.add_argument('admin', default='', help='User name of the administrator')

    spb = subparsers.add_parser('delete-project', help='Delete an existing project (irreversible)')
    spb.add_argument('project', default='', help='Project name')

    spb = subparsers.add_parser('create-user', help='Create a user with no assignment to a project')
    spb.add_argument('user', default='', help='User name')

    spb = subparsers.add_parser('reset-password', help='Reset the password of a user')
    spb.add_argument('user', default='', help='User name')
    spb.add_argument('--oauth', action='store_true', help='Force the federated authentication')

    spb = subparsers.add_parser('revoke-user', help='Revoke a user')
    spb.add_argument('user', default='', help='User name')
    spb.add_argument('--force', action='store_true', help='Force the operation despite the user can be the sole administrator of a project')

    subparsers.add_parser('show-logon', help='Show the last logons of the users')

    spb = subparsers.add_parser('show-audit', help='Show the log of the database (no HTTP traffic)')
    spb.add_argument('--min', type=int, default=30, help='From MIN days in the past', metavar='30')
    spb.add_argument('--max', type=int, default=0, help='To MAX days in the past', metavar='0')

    subparsers.add_parser('compress-static', help='Compress the static files for a faster delivery (optional)')

    spb = subparsers.add_parser('clear-cache', help='Clear the cache of the pages (required after upgrade or restoration)')
    spb.add_argument('--project', default='', help='Name of the project (if project-dependent)')

    subparsers.add_parser('execute-sql', help='Execute an SQL query on the database (dangerous)')

    # Parse the command line
    args = parser.parse_args()
    if args.command == 'generate-ssl':
        return generate_ssl()
    elif args.command == 'init-db':
        return init_db()
    elif args.command == 'show-env':
        return show_env(args.var)
    elif args.command == 'set-env':
        return set_env(args.project, args.name, args.value, args.override)
    elif args.command == 'show-mime':
        return show_mime()
    elif args.command == 'create-backup':
        return create_backup()
    elif args.command == 'show-projects':
        return show_projects()
    elif args.command == 'create-project':
        return create_project(args.project, args.description, args.admin)
    elif args.command == 'takeover-project':
        return takeover_project(args.project, args.admin)
    elif args.command == 'delete-project':
        return delete_project(args.project)
    elif args.command == 'create-user':
        return create_user(args.user)
    elif args.command == 'reset-password':
        return reset_password(args.user, args.oauth)
    elif args.command == 'revoke-user':
        return revoke_user(args.user, args.force)
    elif args.command == 'show-logon':
        return show_logon()
    elif args.command == 'show-audit':
        return show_audit(args.min, args.max)
    elif args.command == 'compress-static':
        return compress_static()
    elif args.command == 'clear-cache':
        return clear_cache(args.project)
    elif args.command == 'execute-sql':
        return execute_sql()
    else:
        parser.print_help()
        return False


def db_connect(init: bool = False) -> Optional[sqlite3.Cursor]:
    global db
    if not init and not isfile(PWIC_DB_SQLITE):
        print('Error: the database is not created yet')
        return None
    try:
        db = sqlite3.connect(PWIC_DB_SQLITE)
        db.row_factory = pwic_row_factory
        return db.cursor()
    except sqlite3.OperationalError:
        print('Error: the database cannot be opened')
        return None


def db_commit() -> None:
    global db
    if db is not None:
        db.commit()


def generate_ssl() -> bool:
    # Ownership by https://stackoverflow.com/questions/51645324/how-to-setup-a-aiohttp-https-server-and-client/51646535

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
    print('- ' + PWIC_PRIVATE_KEY)
    print('- ' + PWIC_PUBLIC_KEY)
    return True


def init_db() -> bool:
    if not isdir(PWIC_DB):
        os.mkdir(PWIC_DB)
    if isfile(PWIC_DB_SQLITE):
        print('Error: the database is already created')
    else:
        sql = db_connect(init=True)
        if sql is None:
            print('Error: cannot create the database')
        else:
            # Table PROJECTS
            sql.execute('''
CREATE TABLE "projects" (
    "project" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    PRIMARY KEY("project")
)''')
            sql.execute(''' INSERT INTO projects (project, description) VALUES ('', '')''')     # Empty projects.project
            # Table ENV
            sql.execute('''
CREATE TABLE "env" (
    "project" TEXT NOT NULL,    -- Don't default to '' else there is a unicity key for 'key'
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    FOREIGN KEY("project") REFERENCES "projects"("project"),
    PRIMARY KEY("key","project")
)''')
            sql.execute(''' INSERT INTO env (project, key, value) VALUES ('', 'file_formats', 'md html odt')''')
            sql.execute(''' INSERT INTO env (project, key, value) VALUES ('', 'robots', 'noarchive, noindex')''')
            sql.execute(''' INSERT INTO env (project, key, value) VALUES ('', 'safe_mode', 'X')''')
            # Table USERS
            sql.execute('''
CREATE TABLE "users" (
    "user" TEXT NOT NULL,
    "password" TEXT NOT NULL DEFAULT '',
    "initial" TEXT NOT NULL DEFAULT 'X' CHECK("initial" IN ('', 'X')),
    PRIMARY KEY("user")
)''')
            sql.execute(''' INSERT INTO users (user, password, initial) VALUES ('', '', '')''')     # Empty pages.valuser
            sql.execute(''' INSERT INTO users (user, password, initial) VALUES (?, '', '')''', (PWIC_USERS['anonymous'], ))
            sql.execute(''' INSERT INTO users (user, password, initial) VALUES (?, '', '')''', (PWIC_USERS['ghost'], ))
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
            # Index for the pages
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
    "hash" TEXT NOT NULL DEFAULT '' CHECK("hash" <> ''),
    "author" TEXT NOT NULL CHECK("author" <> ''),
    "date" TEXT NOT NULL CHECK("date" <> ''),
    "time" TEXT NOT NULL CHECK("time" <> ''),
    FOREIGN KEY("project") REFERENCES "projects"("project"),
    FOREIGN KEY("author") REFERENCES "users"("user"),
    PRIMARY KEY("id" AUTOINCREMENT),
    UNIQUE("project","filename")
)''')
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
            # No delete on AUDIT
            sql.execute('''
CREATE TRIGGER audit_no_delete
BEFORE DELETE ON audit
BEGIN
    SELECT RAISE (ABORT, 'The table AUDIT should not be modified');
END''')
            # No update on AUDIT
            sql.execute('''
CREATE TRIGGER audit_no_update
BEFORE UPDATE ON audit
BEGIN
    SELECT RAISE (ABORT, 'The table AUDIT should not be modified');
END''')

            # Trace
            pwic_audit(sql, {'author': PWIC_USERS['system'],
                             'event': 'init-db'})
            db_commit()
            print('The database is created at "%s"' % PWIC_DB_SQLITE)
            return True
    return False


def show_env(var: str = '') -> bool:
    # Package info
    if var == '':
        try:
            from importlib.metadata import PackageNotFoundError, version
            print('Python packages:\n')
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
        value = '(Secret value not displayed)' if row['key'] in PWIC_ENV_PRIVATE else row['value']
        tab.add_row([row['project'], row['key'], value])
        found = True
    if found:
        print('\nGlobal and project-dependent Pwic variables:\n')
        print(tab.get_string())
        return True
    else:
        return var == ''


def set_env(project: str, key: str, value: str, override: bool) -> bool:
    # Check the parameters
    if override and (project != ''):
        print('Error: useless parameter --override if a project is indicated')
        return False
    merged = sorted(PWIC_ENV_PROJECT_INDEPENDENT + PWIC_ENV_PROJECT_DEPENDENT)
    if key not in merged:
        print('Error: the name of the variable must be one of <%s>' % ', '.join(merged))
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
        sql.execute(''' DELETE FROM env WHERE project = ? AND key = ?''', (project, key))
        verb = 'deleted'
    else:
        sql.execute(''' INSERT OR REPLACE INTO env (project, key, value) VALUES (?, ?, ?)''', (project, key, value))
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
    tab.border = False

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


def create_backup() -> bool:
    # Check the database
    if not isfile(PWIC_DB_SQLITE):
        print('Error: the database is not created yet')
        return False

    # Prepare the new file name
    dt = pwic_dt()
    new = PWIC_DB_SQLITE_BACKUP % ('%s_%s' % (dt['date'].replace('-', ''), dt['time'].replace(':', '')))
    try:
        copyfile(PWIC_DB_SQLITE, new, follow_symlinks=False)
        if isfile(new):
            os.chmod(new, S_IREAD)
            print('Backup of the database file created as "%s"' % new)
            print('The uploaded documents remain in their place')
            return True
        else:
            raise FileNotFoundError('Error: file "%s" not created' % new)
    except Exception as e:
        print(str(e))
        return False


def show_projects() -> bool:
    # Connect to the database
    sql = db_connect()
    if sql is None:
        return False

    # Select the projects
    sql.execute(''' SELECT a.project, a.description, b.user
                    FROM projects AS a
                        INNER JOIN roles AS b
                            ON  b.project  = a.project
                            AND b.admin    = 'X'
                            AND b.disabled = ''
                    ORDER BY a.project ASC,
                             b.user    ASC''')
    data = {}
    for row in sql.fetchall():
        if row['project'] not in data:
            data[row['project']] = {'description': row['description'],
                                    'admin': []}
        data[row['project']]['admin'].append(row['user'])

    # Display the entries
    tab = PrettyTable()
    tab.field_names = ['Project', 'Description', 'Administrators']
    for f in tab.field_names:
        tab.align[f] = 'l'
    tab.header = True
    tab.border = True
    for key in data:
        tab.add_row([key, data[key]['description'], ', '.join(data[key]['admin'])])
    print(tab.get_string())
    return True


def create_project(project: str, description: str, admin: str) -> bool:
    # Check the arguments
    project = pwic_safe_name(project)
    description = description.strip()
    admin = pwic_safe_user_name(admin)
    if project in ['api', 'special'] or '' in [project, description, admin] or \
       project[:4] == 'pwic' or admin[:4] == 'pwic':
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
        os.makedirs(path)
    except OSError:
        print('Error: impossible to create "%s"' % path)
        return False

    # Add the user account if not existent. The default password is encoded in the SQLite database
    sql.execute(''' INSERT INTO users (user, password)
                    SELECT ?, ?
                    WHERE NOT EXISTS ( SELECT 1 FROM users WHERE user = ? )''',
                (admin, pwic_sha256(PWIC_DEFAULTS['password']), admin))
    if sql.rowcount > 0:
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'create-user',
                         'user': admin})

    # Add the project
    sql.execute(''' INSERT INTO projects (project, description) VALUES (?, ?)''', (project, description))
    assert(sql.rowcount > 0)
    pwic_audit(sql, {'author': PWIC_USERS['system'],
                     'event': 'create-project',
                     'project': project})

    # Add the role
    sql.execute(''' INSERT INTO roles (project, user, admin, reader) VALUES (?, ?, 'X', 'X')''', (project, admin))
    assert(sql.rowcount > 0)
    pwic_audit(sql, {'author': PWIC_USERS['system'],
                     'event': 'grant-admin',
                     'project': project,
                     'user': admin})
    sql.execute(''' INSERT INTO roles (project, user, reader, disabled) VALUES (?, ?, 'X', 'X')''', (project, PWIC_USERS['anonymous']))

    # Add a default homepage
    sql.execute(''' INSERT INTO pages (project, page, revision, latest, header, author, date, time, title, markdown, comment)
                    VALUES (?, ?, 1, 'X', 'X', ?, ?, ?, 'Home', 'Thanks for using Pwic. This is the homepage.', 'Initial commit')''',
                (project, PWIC_DEFAULTS['page'], admin, dt['date'], dt['time']))
    assert(sql.rowcount > 0)
    pwic_audit(sql, {'author': PWIC_USERS['system'],
                     'event': 'create-page',
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


def delete_project(project: str) -> bool:
    # Connect to the database
    sql = db_connect()
    if sql is None:
        return False

    # Verify that the project exists yet
    project = pwic_safe_name(project)
    if project == '' or sql.execute(''' SELECT project FROM projects WHERE project = ?''', (project, )).fetchone() is None:
        print('Error: the project "%s" does not exist' % project)
        return False

    # Confirm
    print('This operation is IRREVERSIBLE. You loose all the pages and the uploaded documents.')
    print('Type "YES" in uppercase to confirm the deletion of the project "%s": ' % project, end='')
    if input() != 'YES':
        return False

    # Remove the uploaded files
    sql.execute(''' SELECT filename FROM documents WHERE project = ?''', (project, ))
    for row in sql.fetchall():
        fn = (PWIC_DOCUMENTS_PATH % project) + row['filename']
        try:
            os.remove(fn)
        except (OSError, FileNotFoundError):
            if isfile(fn):
                print('Error: unable to delete "%s"' % fn)
                return False

    # Remove the folder of the project used to upload files
    try:
        fn = PWIC_DOCUMENTS_PATH % project
        os.rmdir(fn)
    except OSError:
        print('Error: unable to remove "%s". The folder may be not empty' % fn)
        return False

    # Delete
    sql.execute(''' DELETE FROM env       WHERE project = ?''', (project, ))
    sql.execute(''' DELETE FROM documents WHERE project = ?''', (project, ))
    sql.execute(''' DELETE FROM pages     WHERE project = ?''', (project, ))
    sql.execute(''' DELETE FROM cache     WHERE project = ?''', (project, ))
    sql.execute(''' DELETE FROM roles     WHERE project = ?''', (project, ))
    sql.execute(''' DELETE FROM projects  WHERE project = ?''', (project, ))
    pwic_audit(sql, {'author': PWIC_USERS['system'],
                     'event': 'delete-project',
                     'project': project})
    db_commit()
    print('The project "%s" is deleted' % project)
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
    sql.execute(''' INSERT INTO users (user, password, initial) VALUES (?, ?, ?)''',
                (user, pwic_sha256(PWIC_DEFAULTS['password']), 'X'))
    pwic_audit(sql, {'author': PWIC_USERS['system'],
                     'event': 'create-user',
                     'user': user})
    db_commit()
    print('The user "%s" is created with the default password "%s".' % (user, PWIC_DEFAULTS['password']))
    return True


def reset_password(user: str, oauth: bool) -> bool:
    # Connect to the database
    sql = db_connect()
    if sql is None:
        return False

    # Warn if the user is an administrator
    user = pwic_safe_user_name(user)
    if user[:4] in ['', 'pwic']:
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
            print('Error: password too short')
            return False
        pwd = pwic_sha256(pwd)
        initial = 'X'

    # Reset the password with no rights takedown else some projects may loose their administrators
    ok = False
    sql.execute(''' UPDATE users
                    SET password = ?,
                        initial  = ?
                    WHERE user = ?''',
                (pwd, initial, user))
    if sql.rowcount > 0:
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'reset-password',
                         'user': user,
                         'string': PWIC_MAGIC_OAUTH if pwd == PWIC_MAGIC_OAUTH else ''})
        db_commit()
        ok = True
    if not ok:
        print('Error: unknown user')
    else:
        print('The password has been changed for the user "%s"' % (user, ))
    return ok


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
    if sql.execute(''' SELECT user FROM users WHERE user = ?''', (user, )).fetchone() is None:
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
    sql.execute(''' SELECT project FROM roles WHERE user = ?''', (user, ))
    for row in sql.fetchall():
        pwic_audit(sql, {'author': PWIC_USERS['system'],
                         'event': 'delete-user',
                         'project': row['project'],
                         'user': user})
    sql.execute(''' DELETE FROM roles WHERE user = ?''', (user, ))
    db_commit()
    print('The user "%s" is fully unassigned to the projects but remains known in the database' % user)
    return True


def show_logon() -> bool:
    # Select the data
    sql = db_connect()
    if sql is None:
        return False
    sql.execute(''' SELECT a.user, c.date, c.time, b.events
                    FROM users AS a
                        INNER JOIN (
                            SELECT author, MAX(id) AS id, COUNT(id) AS events
                            FROM audit
                            WHERE event = 'logon'
                            GROUP BY author
                        ) AS b
                            ON b.author = a.user
                        INNER JOIN audit AS c
                            ON c.id = b.id
                    ORDER BY c.date DESC,
                             c.time DESC,
                             a.user ASC''')

    # Report the log
    tab = PrettyTable()
    tab.field_names = ['User', 'Date', 'Time', 'Events']
    for f in tab.field_names:
        tab.align[f] = 'l'
    for row in sql.fetchall():
        tab.add_row([row['user'], row['date'], row['time'], row['events']])
    tab.header = True
    tab.border = False
    print(tab.get_string(), flush=True)
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
                    FROM audit
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
    tab.border = False
    print(re.compile(r'\s+(\r?\n)\s').sub('\n', tab.get_string().rstrip()[1:]), flush=True)
    return True


def compress_static() -> bool:
    # To reduce the bandwidth, aiohttp automatically delivers the static files as compressed if the .gz file is created
    # Despite the files do not change, many responses 304 are generated with some browsers
    counter = 0
    path = './static/'
    files = [(path + f) for f in os.listdir(path) if isfile(join(path, f)) and (f.endswith('.js') or f.endswith('.css'))]
    for fn in files:
        if getsize(fn) >= 25600:
            with open(fn, 'rb') as src:
                with gzip.open(fn + '.gz', 'wb') as dst:
                    print('Compressing "%s"' % fn)
                    copyfileobj(src, dst)
                    counter += 1
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


def execute_sql() -> bool:
    # Warn the user
    print('This feature may corrupt the database. Please use it to upgrade Pwic upon explicit request only.')
    print('Type "YES" to continue: ', end='')
    if input() == 'YES':

        # Ask for a query
        print("\nType the query to execute on a single line. You can't select any data.")
        query = input()
        if len(query) > 0:

            # Ask for the confirmation
            print('\nAre you sure to execute << %s >> ?\nType "YES" to continue: ' % query, end='')
            if input() == 'YES':

                # Execute
                sql = db_connect()
                if sql is None:
                    return False
                rownone = sql.execute(query).fetchone() is None
                rowcount = sql.rowcount
                pwic_audit(sql, {'author': PWIC_USERS['system'],
                                 'event': 'execute-sql',
                                 'string': query})
                db_commit()
                print('\nFirst row is null = %s' % str(rownone))
                print('Affected rows = %d' % rowcount)
                return True

    # Default behavior
    print('Aborted')
    return False


if main():
    exit(0)
else:
    print('\nThe operation failed')
    exit(1)
