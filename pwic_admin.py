#!/usr/bin/env python

import argparse
import sqlite3
from prettytable import PrettyTable
import re
import datetime
import os
from os.path import isfile
from shutil import copyfile
from stat import S_IREAD

from pwic_lib import PWIC_DB, PWIC_DB_BACKUP, PWIC_DOCUMENTS_PATH, PWIC_USER, \
    PWIC_DEFAULT_PASSWORD, PWIC_PRIVATE_KEY, PWIC_PUBLIC_KEY, \
    _dt, _sha256, _safeName, pwic_audit


def main():
    # Prepare the command line
    parser = argparse.ArgumentParser(prog='python pwic_admin.py', description='Pwic Management Console')
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('ssl', help='Generate self-signed certificates')

    subparsers.add_parser('init-db', help='Initialize the database once')

    subparsers.add_parser('create-backup', help='Make a backup copy of the database')

    parser_newproj = subparsers.add_parser('create-project', help='Create a new project')
    parser_newproj.add_argument('project', default='', help='Project name')
    parser_newproj.add_argument('description', default='', help='Project description')
    parser_newproj.add_argument('admin', default='', help='User name of the administrator of the project')

    parser_delproj = subparsers.add_parser('delete-project', help='Delete an existing project (irreversible)')
    parser_delproj.add_argument('project', default='', help='Project name')

    parser_reset_user = subparsers.add_parser('reset-password', help='Reset the password of a user')
    parser_reset_user.add_argument('user', default='', help='User name')

    parser_log = subparsers.add_parser('show-log', help='Show the full log')
    parser_log.add_argument('--min', type=int, default=30, help='From MIN days in the past', metavar=30)
    parser_log.add_argument('--max', type=int, default=0, help='To MAX days in the past', metavar=0)

    parser_env = subparsers.add_parser('set-env', help='Set a global value')
    parser_env.add_argument('name', default='', help='Name of the variable')
    parser_env.add_argument('value', default='', help='Value of the variable')

    subparsers.add_parser('execute-sql', help='Execute an SQL query on the database (dangerous)')

    # Parse the command line
    args = parser.parse_args()
    if args.command == 'ssl':
        return generate_ssl()
    elif args.command == 'init-db':
        return generate_db()
    elif args.command == 'create-backup':
        return create_backup()
    elif args.command == 'create-project':
        return create_project(args.project, args.description, args.admin)
    elif args.command == 'delete-project':
        return delete_project(args.project)
    elif args.command == 'reset-password':
        return reset_password(args.user)
    elif args.command == 'show-log':
        return show_log(args.min, args.max)
    elif args.command == 'set-env':
        return set_env(args.name, args.value)
    elif args.command == 'execute-sql':
        return execute_sql()


def db_connect():
    return sqlite3.connect(PWIC_DB).cursor()


def generate_ssl():
    # Ownership by https://stackoverflow.com/questions/51645324/how-to-setup-a-aiohttp-https-server-and-client/51646535

    # Imports
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes

    # Private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    with open(PWIC_PRIVATE_KEY, 'wb') as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.NoEncryption()))

    # Public key
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'FR'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'France'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'Paris'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Pwic'),
        x509.NameAttribute(NameOID.COMMON_NAME, u'Pwic'),
    ])
    cert = x509.CertificateBuilder() \
               .subject_name(issuer) \
               .issuer_name(issuer) \
               .public_key(key.public_key()) \
               .serial_number(x509.random_serial_number()) \
               .not_valid_before(datetime.datetime.utcnow()) \
               .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365 * 5)) \
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(u'localhost'),
                                                           x509.DNSName(u'127.0.0.1')]), critical=False) \
               .sign(key, hashes.SHA256(), default_backend())
    with open(PWIC_PUBLIC_KEY, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Final output
    pwic_audit(db_connect(), {'author': PWIC_USER,
                              'event': 'ssl-regen'},
               commit=True)
    print('The certificates are generated:')
    print('- ' + PWIC_PRIVATE_KEY)
    print('- ' + PWIC_PUBLIC_KEY)
    return True


def generate_db():
    if isfile(PWIC_DB):
        print('Error: the database is already created')
    else:
        sql = db_connect()
        if sql is None:
            print('Error: cannot create the database')
        else:
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
            # Table DOCUMENTS
            sql.execute('''
CREATE TABLE "documents" (
    "id" INTEGER NOT NULL,
    "project" TEXT NOT NULL CHECK("project" <> ''),
    "page" TEXT NOT NULL CHECK("page" <> ''),
    "filename" TEXT NOT NULL CHECK("filename" <> ''),
    "mime" TEXT NOT NULL CHECK("mime" <> ''),
    "size" INTEGER NOT NULL,
    "author" TEXT NOT NULL CHECK("author" <> ''),
    "date" TEXT NOT NULL CHECK("date" <> ''),
    "time" TEXT NOT NULL CHECK("time" <> ''),
    UNIQUE("project","filename"),
    FOREIGN KEY("author") REFERENCES "users"("user"),
    FOREIGN KEY("project") REFERENCES "projects"("project"),
    PRIMARY KEY("id" AUTOINCREMENT)
)''')
            # Table ENV
            sql.execute('''
CREATE TABLE "env" (
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    PRIMARY KEY("key")
)''')
            # Table PAGES
            sql.execute('''
CREATE TABLE "pages" (
    "project" TEXT NOT NULL,
    "page" TEXT NOT NULL CHECK("page" <> ''),
    "revision" INTEGER NOT NULL CHECK("revision" > 0),
    "latest" TEXT NOT NULL DEFAULT 'X' CHECK("latest" = '' OR "latest" = 'X'),
    "draft" TEXT NOT NULL DEFAULT '' CHECK(draft='' or draft="X"),
    "final" TEXT NOT NULL DEFAULT '' CHECK("final" = "" OR "final" = "X"),
    "header" TEXT NOT NULL DEFAULT '' CHECK("header" = "" OR "header" = "X"),
    "protection" TEXT NOT NULL DEFAULT '' CHECK("protection" = "" OR "protection" = "X"),
    "author" TEXT NOT NULL CHECK("author" <> ''),
    "date" TEXT NOT NULL CHECK("date" <> ''),
    "time" TEXT NOT NULL CHECK("time" <> ''),
    "title" TEXT NOT NULL CHECK("title" <> ''),
    "markdown" TEXT NOT NULL DEFAULT '',
    "comment" TEXT NOT NULL CHECK("comment" <> ''),
    "milestone" TEXT NOT NULL DEFAULT '',
    "valuser" TEXT NOT NULL DEFAULT '',
    "valdate" TEXT NOT NULL DEFAULT '',
    "valtime" TEXT NOT NULL DEFAULT '',
    PRIMARY KEY("project","page","revision"),
    FOREIGN KEY("project") REFERENCES "projects"("project"),
    FOREIGN KEY("author") REFERENCES "users"("user"),
    FOREIGN KEY("valuser") REFERENCES "users"("user")
)''')
            # Table PROJECTS
            sql.execute('''
CREATE TABLE "projects" (
    "project" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    PRIMARY KEY("project")
)''')
            # Table ROLES
            sql.execute('''
CREATE TABLE "roles" (
    "project" TEXT NOT NULL,
    "user" TEXT NOT NULL,
    "admin" TEXT NOT NULL DEFAULT '' CHECK(("admin" = "" OR "admin" = "X") AND ("admin" = "X" OR "manager" = "X" OR "editor" = "X" OR "validator" = "X" OR "reader" = "X")),
    "manager" TEXT NOT NULL DEFAULT '' CHECK("manager" = "" OR "manager" = "X"),
    "editor" TEXT NOT NULL DEFAULT '' CHECK("editor" = "" OR "editor" = "X"),
    "validator" TEXT NOT NULL DEFAULT '' CHECK("validator" = "" OR "validator" = "X"),
    "reader" TEXT NOT NULL DEFAULT '' CHECK("reader" = "" OR "reader" = "X"),
    PRIMARY KEY("user","project"),
    FOREIGN KEY("user") REFERENCES "users"("user"),
    FOREIGN KEY("project") REFERENCES "projects"("project")
)''')
            # Table USERS
            sql.execute('''
CREATE TABLE "users" (
    "user" TEXT NOT NULL,
    "password" TEXT NOT NULL DEFAULT '',
    "initial" TEXT NOT NULL DEFAULT 'X' CHECK("initial" = "" OR "initial" = "X"),
    PRIMARY KEY("user")
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
            print('The database is created at "%s"' % PWIC_DB)
            return True
    return False


def create_backup():
    # Check
    if not isfile(PWIC_DB):
        print('Error: the database is not created yet')
        return False

    # Prepare the new file name
    dt = _dt()
    new = PWIC_DB_BACKUP % ('%s_%s' % (dt['date'].replace('-', ''), dt['time'].replace(':', '')))
    try:
        copyfile(PWIC_DB, new, follow_symlinks=False)
        if isfile(new):
            os.chmod(new, S_IREAD)
            print('Backup of the database file created as "%s"' % new)
            print('The uploaded documents remain in their place')
            return True
        else:
            raise FileNotFoundError('File "%s" not created' % new)
    except Exception as e:
        print(str(e))
        return False


def create_project(project, description, admin):
    # Check the arguments
    project = _safeName(project)
    description = description.strip()
    admin = _safeName(admin)
    if project in ['api', 'special'] or '' in [project, description, admin]:
        print('Error: invalid arguments')
        return False

    # Connect to the database
    sql = db_connect()
    dt = _dt()

    # Verify that the project does not exist yet
    sql.execute('SELECT project FROM projects WHERE project = ?', (project, ))
    if sql.fetchone() is not None:
        print('Error: project already exists')
        return False

    # Create the workspace for the documents of the project
    try:
        path = PWIC_DOCUMENTS_PATH % project
        os.mkdir(path)
    except OSError:
        print('Error: impossible to create "%s"' % path)
        return False

    # Add the user account if not existent. The default password is encoded in the SQLite database
    sql.execute(''' INSERT INTO users (user, password)
                    SELECT ?, ?
                    WHERE NOT EXISTS ( SELECT 1 FROM users WHERE user = ? )''',
                (admin, _sha256(PWIC_DEFAULT_PASSWORD), admin))
    if sql.rowcount > 0:
        pwic_audit(sql, {'author': PWIC_USER,
                         'event': 'create-user',
                         'user': admin})

    # Add the project
    sql.execute('INSERT INTO projects (project, description) VALUES (?, ?)', (project, description))
    assert(sql.rowcount > 0)
    pwic_audit(sql, {'author': PWIC_USER,
                     'event': 'create-project',
                     'project': project})

    # Add the role
    sql.execute("INSERT INTO roles (project, user, admin) VALUES (?, ?, 'X')", (project, admin))
    assert(sql.rowcount > 0)
    pwic_audit(sql, {'author': PWIC_USER,
                     'event': 'grant-admin',
                     'project': project,
                     'user': admin})

    # Add a default homepage
    page = 'home'
    sql.execute(''' INSERT INTO pages (project, page, revision, author, date, time, title, markdown, comment)
                    VALUES (?, ?, 1, ?, ?, ?, "Home page", "Thanks for using Pwic. This is the homepage.", "Initial commit")''',
                (project, page, admin, dt['date'], dt['time']))
    assert(sql.rowcount > 0)
    pwic_audit(sql, {'author': PWIC_USER,
                     'event': 'create-page',
                     'project': project,
                     'page': page,
                     'revision': 1})

    # Finalization
    sql.execute('COMMIT')
    print('The project is created:')
    print('- Project       : %s' % project)
    print('- Administrator : %s' % admin)
    print('- Password      : "%s" or the existing password' % PWIC_DEFAULT_PASSWORD)
    print('')
    print('Thanks for using Pwic!')
    return True


def delete_project(project):
    # Verify that the project exists yet
    sql = db_connect()
    project = _safeName(project)
    if sql.execute('SELECT project FROM projects WHERE project = ?', (project, )).fetchone() is None:
        print('Error: project does not exist')
        return False

    # Confirm
    print('This operation is IRREVERSIBLE. You loose all the pages and the uploaded documents.')
    print('Type "YES" in uppercase to confirm the deletion of the project "%s": ' % project, end='')
    if input() == 'YES':

        # Remove the uploaded files
        sql.execute('SELECT filename FROM documents WHERE project = ?', (project, ))
        for row in sql.fetchall():
            fn = (PWIC_DOCUMENTS_PATH % project) + row[0]
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
        sql.execute('DELETE FROM documents WHERE project = ?', (project, ))
        sql.execute('DELETE FROM pages     WHERE project = ?', (project, ))
        sql.execute('DELETE FROM roles     WHERE project = ?', (project, ))
        sql.execute('DELETE FROM projects  WHERE project = ?', (project, ))
        pwic_audit(sql, {'author': PWIC_USER,
                         'event': 'delete-project'},
                   commit=True)
        print('Project "%s" is deleted' % project)
        return True
    else:
        print('Aborted')
        return False


def reset_password(user):
    # Check if the user is administrator
    sql = db_connect()
    user = _safeName(user)
    sql.execute(''' SELECT COUNT(*) AS total
                    FROM roles
                    WHERE user  = ?
                      AND admin = "X"''',
                (user, ))
    if sql.fetchone()[0] > 0:
        print("The user '%s' has administrative rights on some projects." % user)
        print("For that reason, you must provide a manual password.")
        print("Type the new temporary password with 8 characters at least: ", end='')
        pwd = input()
        if len(pwd) < 8:
            print('Error: password too short')
            return False
    else:
        pwd = PWIC_DEFAULT_PASSWORD

    # Reset the password with no rights takedown else some projects may loose their administrators
    ok = False
    sql.execute('UPDATE users SET password = ?, initial = "X" WHERE user = ?',
                (_sha256(pwd), user))
    if sql.rowcount > 0:
        pwic_audit(sql, {'author': PWIC_USER,
                         'event': 'reset-password',
                         'user': user},
                   commit=True)
        ok = True
    if not ok:
        print('Error: unknown user')
    else:
        print('The user "%s" has the new temporary password "%s"' % (user, pwd))
    return ok


def show_log(dmin, dmax):
    # Calculate the dates
    dmin = max(0, dmin)
    dmax = max(0, dmax)
    if dmax > dmin:
        dmin, dmax = dmax, dmin
    if dmin == 0:
        print('Error: invalid parameters')
        return False
    dmin = str(datetime.date.today() - datetime.timedelta(days=dmin))[:10]
    dmax = str(datetime.date.today() - datetime.timedelta(days=dmax))[:10]

    # Select the data
    sql = db_connect()
    sql.execute(''' SELECT id, date, time, author, event, user,
                           project, page, revision, count, ip, string
                    FROM audit
                    WHERE date >= ? AND date <= ?
                    ORDER BY id ASC''',
                (dmin, dmax))

    # Report the log
    tab = PrettyTable()
    tab.field_names = ['ID', 'Date', 'Time', 'Author', 'Event', 'User', 'Project', 'Page', 'Revision', 'IP', 'String']
    for f in tab.field_names:
        tab.align[f] = 'l'
    for row in sql.fetchall():
        tab.add_row([row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7],
                     '' if row[8] == 0 else row[8], row[9], row[10]])
    tab.header = True
    tab.border = False
    print(re.compile(r'\s+(\r?\n)\s').sub('\n', tab.get_string().rstrip()[1:]), flush=True)
    return True


def set_env(name, value):
    # Check the keys
    keys = ['document_name_regex', 'maintenance', 'max_document_size']
    if name not in keys:
        print('Error: the name of the variable must be one of "%s"' % ', '.join(keys))
        return False

    # Update the variable
    sql = db_connect()
    sql.execute('INSERT OR REPLACE INTO env (key, value) VALUES (?, ?)', (name, value))
    pwic_audit(sql, {'author': PWIC_USER,
                     'event': '%sset-%s' % ('un' if value == '' else '', name),
                     'string': value},
               commit=True)
    print('Variable updated')
    return True


def execute_sql():
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
                rownone = sql.execute(query).fetchone() is None
                rowcount = sql.rowcount
                pwic_audit(sql, {'author': PWIC_USER,
                                 'event': 'execute-sql',
                                 'string': query},
                           commit=True)
                print('\nFirst row is null = %s' % str(rownone))
                print('Affected rows = %d' % rowcount)
                return True

    # Default behavior
    print('Aborted')
    return False


main()
