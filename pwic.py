#!/usr/bin/env python

from typing import Any, Dict, List, Optional, Tuple
import argparse
from aiohttp import web, MultipartReader, hdrs
from aiohttp_session import setup, get_session, new_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from urllib.parse import parse_qs, quote, urlencode
from urllib.request import Request, urlopen
from jinja2 import Environment, FileSystemLoader
import sqlite3
from difflib import HtmlDiff
import zipfile
from io import BytesIO
import os
from os import listdir, urandom
from os.path import getsize, isdir, isfile, join, splitext
import json
import re
import imagesize
from ipaddress import ip_network, ip_address
from bisect import insort, bisect_left
from multidict import MultiDict
from html import escape
from random import randint

from pwic_md import Markdown
from pwic_lib import PWIC_VERSION, PWIC_DB, PWIC_DB_SQLITE, PWIC_DOCUMENTS_PATH, PWIC_TEMPLATES_PATH, PWIC_USERS, \
    PWIC_DEFAULTS, PWIC_PRIVATE_KEY, PWIC_PUBLIC_KEY, PWIC_ENV_PROJECT_DEPENDENT, PWIC_ENV_PROJECT_DEPENDENT_ONLINE, \
    PWIC_ENV_PRIVATE, PWIC_EMOJIS, PWIC_CHARS_UNSAFE, PWIC_MAGIC_OAUTH, PWIC_MIMES, PWIC_REGEXES, \
    pwic_apostrophe, pwic_attachment_name, pwic_dt, pwic_int, pwic_list, pwic_mime, pwic_mime2icon, pwic_option, \
    pwic_random_hash, pwic_row_factory, pwic_sha256, pwic_safe_name, pwic_safe_file_name, pwic_safe_user_name, \
    pwic_size2str, pwic_sql_print, pwic_str2bytearray, pwic_x, pwic_xb, pwic_extended_syntax, pwic_audit, \
    pwic_search_parse, pwic_search2string, pwic_html2odt
from pwic_extension import PwicExtension
from pwic_styles import pwic_styles_html, pwic_styles_odt

IPR_EQ, IPR_NET, IPR_REG = range(3)


# ===================================================
#  This class handles the rendering of the web pages
# ===================================================

class PwicServer():
    def _connect(self) -> sqlite3.Cursor:
        return app['sql'].cursor()

    def _commit(self) -> None:
        ''' Commit the current transactions '''
        app['sql'].commit()

    def _rollback(self) -> None:
        ''' Rollback the current transactions '''
        app['sql'].rollback()

    def _lock(self, sql):
        ''' Lock the current database '''
        if sql is None:
            return False
        try:
            sql.execute(''' BEGIN EXCLUSIVE TRANSACTION''')
            return True
        except sqlite3.OperationalError:
            return False

    def _sanitize_tags(self, tags: str) -> str:
        ''' Reorder a list of tags written as a string '''
        return ' '.join(sorted(pwic_list(tags.replace('#', ''))))

    def _md2html(self,
                 sql: sqlite3.Cursor,
                 project: str,
                 page: Optional[str],
                 revision: int,
                 markdown: str,
                 cache: bool = True,
                 headerNumbering: bool = True) -> Tuple[str, object]:
        ''' Convert the text from Markdown to HTML '''
        # Read the cache
        if (page is None) or (revision <= 0) or (pwic_option(sql, project, 'no_cache') is not None):
            cache = False
        if cache:
            row = sql.execute(''' SELECT html
                                  FROM cache
                                  WHERE project  = ?
                                    AND page     = ?
                                    AND revision = ?''',
                              (project, page, revision)).fetchone()
        else:
            row = None

        # Update the cache
        if row is not None:
            html = row['html']
        else:
            html = app['markdown'].convert(markdown).replace('<span></span>', '')
            html = PwicExtension.on_html(sql, project, page, revision, html)
            if cache:
                sql.execute(''' INSERT OR REPLACE INTO cache (project, page, revision, html) VALUES (?, ?, ?, ?)''',
                            (project, page, revision, html))
                self._commit()
        return pwic_extended_syntax(html,
                                    pwic_option(sql, project, 'heading_mask'),
                                    headerNumbering=headerNumbering)

    def _check_mime(self, obj: Dict[str, Any]) -> bool:
        ''' Check the consistency of the MIME with the file signature'''
        extension = splitext(obj['filename'])[1][1:]
        for (mext, mtyp, mhdr) in PWIC_MIMES:
            if extension in mext:
                # Expected mime
                if obj['mime'] == '':
                    obj['mime'] = mtyp
                elif mtyp != obj['mime']:
                    return False

                # Magic bytes
                if mhdr is not None:
                    for bytes in mhdr:
                        if obj['content'][:len(bytes)] == pwic_str2bytearray(bytes):
                            return True
                    return False
                break
        return obj['mime'] != ''

    def _check_ip(self, request: web.Request) -> None:
        ''' Check if the IP address is authorized '''
        # Initialization
        okIncl = False
        hasIncl = False
        koExcl = False
        ip = str(PwicExtension.on_ip_header(request))

        # Apply the rules
        for mask in app['ip_filter']:
            if mask[0] == IPR_NET:
                condition = ip_address(ip) in mask[2]
            elif mask[0] == IPR_REG:
                condition = mask[2].match(ip) is not None
            else:
                condition = (ip == mask[2])

            # Evaluate
            if mask[1]:  # Negated
                koExcl = koExcl or condition
                if koExcl:  # Boolean accelerator
                    break
            else:
                okIncl = okIncl or condition
                hasIncl = True

        # Validate the access
        unauth = koExcl or (hasIncl != okIncl)
        unauth = not PwicExtension.on_ip_check(ip, not unauth)
        if unauth:
            raise web.HTTPUnauthorized()

    def _is_pure_reader(self, sql: sqlite3.Cursor, project: str, user: str) -> Optional[bool]:
        # Check if the user is a pure reader
        sql.execute(''' SELECT admin, manager, editor, validator, reader
                        FROM roles
                        WHERE project  = ?
                          AND user     = ?
                          AND disabled = '' ''',
                    (project, user))
        row = sql.fetchone()
        if row is None:
            return None
        return (row['admin'] == '') and  \
               (row['manager'] == '') and \
               (row['editor'] == '') and   \
               (row['validator'] == '') and \
               (row['reader'] == 'X')

    def _redirect_revision(self, sql: sqlite3.Cursor, project: str, user: str, page: str, revision: int) -> int:
        # Check if the user is a pure reader
        pure_reader = self._is_pure_reader(sql, project, user)
        if pure_reader is None:
            return 0

        # Route to the latest validated version
        if pure_reader:
            if pwic_option(sql, project, 'no_history') is not None:
                revision = 0
            if (revision == 0) and (pwic_option(sql, project, 'validated_only') is not None):
                sql.execute(''' SELECT MAX(revision) AS revision
                                FROM pages
                                WHERE project  = ?
                                  AND page     = ?
                                  AND valuser <> '' ''',
                            (project, page))
                row = sql.fetchone()
                if row['revision'] is not None:
                    revision = row['revision']

        # Check if the chosen revision exists
        if revision > 0:
            sql.execute(''' SELECT 1
                            FROM pages
                            WHERE project  = ?
                              AND page     = ?
                              and revision = ?''',
                        (project, page, revision))
            if sql.fetchone() is None:
                revision = 0

        # Find the default latest revision
        else:
            sql.execute(''' SELECT revision
                            FROM pages
                            WHERE project = ?
                              AND page    = ?
                              AND latest  = 'X' ''',
                        (project, page))
            row = sql.fetchone()
            if row is not None:
                revision = row['revision']
        return revision

    async def _suser(self, request: web.Request) -> str:
        ''' Retrieve the logged user '''
        self._check_ip(request)
        session = await get_session(request)
        user = pwic_safe_user_name(session.get('user', ''))
        return PWIC_USERS['anonymous'] if (user == '') and app['no_logon'] else user

    async def _handle_post(self, request: web.Request) -> Dict[str, Any]:
        ''' Return the POST as a readable object.get() '''
        result: Dict[str, Any] = {}
        if request.body_exists:
            data = await request.text()
            result = parse_qs(data)
            for res in result:
                result[res] = result[res][0]
        return result

    async def _handle_logon(self, request: web.Request) -> web.Response:
        ''' Show the logon page '''
        session = await new_session(request)
        session['user_secret'] = pwic_random_hash()
        return await self._handle_output(request, 'logon', {'title': 'Connect to Pwic'})

    async def _handle_output(self, request: web.Request, name: str, pwic: Dict[str, Any]) -> web.Response:
        ''' Serve the right template, in the right language, with the right PWIC structure and additional data '''
        pwic['user'] = await self._suser(request)
        pwic['emojis'] = PWIC_EMOJIS
        pwic['constants'] = {'anonymous_user': PWIC_USERS['anonymous'],
                             'db_path': PWIC_DB,
                             'default_language': PWIC_DEFAULTS['language'],
                             'changeable_env_variables': sorted(PWIC_ENV_PROJECT_DEPENDENT_ONLINE),
                             'languages': app['langs'],
                             'unsafe_chars': PWIC_CHARS_UNSAFE,
                             'version': PWIC_VERSION}

        # The project-dependent variables have the priority
        sql = self._connect()
        sql.execute(''' SELECT project, key, value
                        FROM env
                        WHERE value <> ''
                          AND ( project = ?
                             OR project = '' )
                        ORDER BY key     ASC,
                                 project DESC''',
                    (pwic.get('project', ''), ))
        pwic['env'] = {}
        for row in sql.fetchall():
            (global_, key, value) = (row['project'] == '', row['key'], row['value'])
            if key in PWIC_ENV_PRIVATE:
                value = None
            if key not in pwic['env']:
                pwic['env'][key] = {'value': value,
                                    'global': global_}
                if key in ['max_document_size', 'max_project_size']:
                    pwic['env'][key + '_str'] = {'value': pwic_size2str(pwic_int(value)),
                                                 'global': global_}

        # Dynamic settings
        if (name == 'page') and ('no_index_rev' in pwic['env']) and not pwic['latest']:
            robots = pwic_list(pwic['env'].get('robots', {'value': ''})['value'].lower().replace(',', ' '))
            if 'archive' in robots:
                robots.remove('archive')
            if 'noarchive' not in robots:
                robots.append('noarchive')
            if 'index' in robots:
                robots.remove('index')
            if 'noindex' not in robots:
                robots.append('noindex')
            if 'snippet' in robots:
                robots.remove('snippet')
            if 'nosnippet' not in robots:
                robots.append('nosnippet')
            if 'robots' not in pwic['env']:
                pwic['env']['robots'] = {'value': '',
                                         'global': True}
            pwic['env']['robots']['value'] = ' '.join(robots)

        # Session
        session = await get_session(request)
        pwic['session'] = {'user_secret': session.get('user_secret', None)}

        # Render the template
        pwic['template'] = name
        pwic['args'] = request.rel_url.query
        pwic['language'] = session.get('language', PWIC_DEFAULTS['language'])
        PwicExtension.on_render_pre(app, sql, request, pwic)
        template_name = '%s/%s.html' % (pwic['language'], name)
        if (pwic['language'] != PWIC_DEFAULTS['language']) and not isfile(PWIC_TEMPLATES_PATH + template_name):
            template_name = '%s/%s.html' % (PWIC_DEFAULTS['language'], name)
        output = app['jinja'].get_template(template_name).render(pwic=pwic)
        output = PwicExtension.on_render_post(app, sql, pwic, output)
        return web.Response(text=output, content_type=pwic_mime('html'))

    async def page(self, request: web.Request) -> web.Response:
        ''' Serve the pages '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handle_logon(request)

        # Show the requested page
        project = pwic_safe_name(request.match_info.get('project', ''))
        page = pwic_safe_name(request.match_info.get('page', PWIC_DEFAULTS['page']))
        page_special = (page == 'special')
        revision = pwic_int(request.match_info.get('revision', '0'))
        action = request.match_info.get('action', 'view')
        pwic: Dict[str, Any] = {'project': project,
                                'page': page,
                                'revision': revision}
        dt = pwic_dt()

        # Fetch the name of the project...
        sql = self._connect()
        if project != '':
            # Verify if the project exists
            sql.execute(''' SELECT description
                            FROM projects
                            WHERE project = ?''',
                        (project, ))
            row = sql.fetchone()
            if row is None:
                raise web.HTTPTemporaryRedirect('/')  # Project not found
            pwic['project_description'] = row['description']
            pwic['title'] = row['description']

            # Grant the default rights as a reader
            if (user[:4] != 'pwic') and (pwic_option(sql, project, 'auto_join') is not None):
                if sql.execute(''' SELECT 1
                                   FROM roles
                                   WHERE project = ?
                                     AND user    = ?''',
                               (project, user)).fetchone() is None:
                    sql.execute(''' INSERT INTO roles (project, user, reader)
                                    VALUES (?, ?, 'X')''', (project, user))
                    if sql.rowcount > 0:
                        pwic_audit(sql, {'author': PWIC_USERS['system'],
                                         'event': 'grant-reader',
                                         'project': project,
                                         'user': user,
                                         'string': 'auto_join'},
                                   request)
                        self._commit()

            # Verify the access
            sql.execute(''' SELECT admin, manager, editor, validator, reader
                            FROM roles
                            WHERE project  = ?
                              AND user     = ?
                              AND disabled = '' ''',
                        (project, user))
            row = sql.fetchone()
            if row is None:
                return await self._handle_output(request, 'project-access', pwic)  # Unauthorized users can request an access
            pwic['admin'] = pwic_xb(row['admin'])
            pwic['manager'] = pwic_xb(row['manager'])
            pwic['editor'] = pwic_xb(row['editor'])
            pwic['validator'] = pwic_xb(row['validator'])
            pwic['reader'] = pwic_xb(row['reader'])
            pwic['pure_reader'] = pwic['reader'] and not pwic['admin'] and not pwic['manager'] and not pwic['editor'] and not pwic['validator']

        # ... or ask the user to pick a project
        else:
            sql.execute(''' SELECT a.project, a.description
                            FROM projects AS a
                                INNER JOIN roles AS b
                                    ON  b.project  = a.project
                                    AND b.user     = ?
                                    AND b.disabled = ''
                            ORDER BY a.description''',
                        (user, ))
            pwic['title'] = 'Select your project'
            pwic['projects'] = [row for row in sql.fetchall()]
            if len(pwic['projects']) == 1:
                raise web.HTTPTemporaryRedirect('/%s' % pwic['projects'][0]['project'])
            else:
                return await self._handle_output(request, 'project-select', pwic)

        # Fetch the links of the header line
        sql.execute(''' SELECT a.page, a.title
                        FROM pages AS a
                        WHERE a.project = ?
                          AND a.latest  = 'X'
                          AND a.header  = 'X'
                        ORDER BY a.title''',
                    (project, ))
        pwic['links'] = []
        for row in sql.fetchall():
            pwic['links'].append(row)
            if row['page'] == PWIC_DEFAULTS['page']:
                pwic['links'].insert(0, pwic['links'].pop())    # Move to the top because it is the home page

        # Verify that the page exists
        if not page_special:
            revision = self._redirect_revision(sql, project, user, page, revision)
            if revision == 0:
                return await self._handle_output(request, 'page-404', pwic)  # Page not found

        # Show the requested page
        if action == 'view':
            if not page_special:
                # Content of the page
                sql.execute(''' SELECT revision, latest, draft, final, protection,
                                       author, date, time, title, markdown,
                                       tags, valuser, valdate, valtime
                                FROM pages
                                WHERE project  = ?
                                  AND page     = ?
                                  AND revision = ?''',
                            (project, page, revision))
                row = sql.fetchone()
                for k in ['latest', 'draft', 'final', 'protection']:
                    row[k] = pwic_xb(row[k])
                row['tags'] = [] if row['tags'] == '' else row['tags'].split(' ')
                pwic.update(row)
                pwic['html'], pwic['tmap'] = self._md2html(sql, project, page, revision, row['markdown'])
                pwic['hash'] = pwic_sha256(row['markdown'], salt=False)
                pwic['removable'] = (pwic['admin'] and not pwic['final'] and (pwic['valuser'] == '')) or ((pwic['author'] == user) and pwic['draft'])

                # File gallery
                pwic['images'] = []
                pwic['documents'] = []
                sql.execute(''' SELECT id, filename, mime, size, author, date, time
                                FROM documents
                                WHERE project = ?
                                  AND page    = ?
                                ORDER BY filename''',
                            (project, page))
                for row in sql.fetchall():
                    row['size'] = pwic_size2str(row['size'])
                    category = 'images' if row['mime'][:6] == 'image/' else 'documents'
                    pwic[category].append(row)

            # Additional information for the special page
            else:
                # Fetch the recently updated pages
                sql.execute(''' SELECT page, author, date, time, title, comment, milestone
                                FROM pages
                                WHERE project = ?
                                  AND latest  = 'X'
                                  AND date   >= ?
                                ORDER BY date DESC, time DESC''',
                            (project, dt['date-30d']))
                pwic['recents'] = []
                for row in sql.fetchall():
                    pwic['recents'].append(row)

                # Fetch the team members of the project
                sql.execute(''' SELECT user, admin, manager, editor, validator, reader, disabled
                                FROM roles
                                WHERE project = ?
                                ORDER BY disabled DESC,
                                         user     ASC''',
                            (project, ))
                pwic['admins'] = []
                pwic['managers'] = []
                pwic['editors'] = []
                pwic['validators'] = []
                pwic['readers'] = []
                pwic['disableds'] = []
                for row in sql.fetchall():
                    for k in row:
                        if (k != 'user') and pwic_xb(row[k]):
                            pwic[k + 's'].append(row['user'])

                # Fetch the inactive users
                if pwic['admin']:
                    sql.execute(''' SELECT a.user
                                    FROM roles AS a
                                        LEFT JOIN (
                                            SELECT author, MAX(date) AS date
                                            FROM audit
                                            WHERE date >= ?
                                              AND ( project = ?
                                                 OR event IN ("logon", "logout")
                                              )
                                            GROUP BY author
                                        ) AS b
                                            ON b.author = a.user
                                    WHERE a.project  = ?
                                      AND a.disabled = ''
                                      AND b.date     IS NULL
                                    ORDER BY a.user''',
                                (dt['date-30d'], project, project))
                    pwic['inactive_users'] = []
                    for row in sql.fetchall():
                        pwic['inactive_users'].append(row['user'])

                # Fetch the pages of the project
                sql.execute(''' SELECT page, title, revision, final, author,
                                       date, time, milestone, valuser, valdate,
                                       valtime
                                FROM pages
                                WHERE project = ?
                                  AND latest  = 'X'
                                ORDER BY page ASC, revision DESC''',
                            (project, ))
                pwic['pages'] = []
                for row in sql.fetchall():
                    pwic['pages'].append(row)

                # Fetch the tags of the project
                sql.execute(''' SELECT tags
                                FROM pages
                                WHERE project = ?
                                  AND latest  = 'X'
                                  AND tags   <> '' ''',
                            (project, ))
                tags = ''
                for row in sql.fetchall():
                    tags += ' ' + row['tags']
                tags = tags.strip()
                pwic['tags'] = [] if tags == '' else sorted(pwic_list(tags))

                # Fetch the documents of the project
                sql.execute(''' SELECT b.id, b.project, b.page, b.filename, b.mime, b.size,
                                       b.hash, b.author, b.date, b.time, b.exturl, c.occurrence
                                FROM roles AS a
                                    INNER JOIN documents AS b
                                        ON b.project = a.project
                                    INNER JOIN (
                                        SELECT hash, COUNT(hash) AS occurrence
                                        FROM documents
                                        GROUP BY hash
                                        HAVING project = ?
                                    ) AS c
                                        ON c.hash = b.hash
                                WHERE a.project  = ?
                                  AND a.user     = ?
                                  AND a.disabled = ''
                                ORDER BY filename''',
                            (project, project, user))
                pwic['documents'] = []
                used_size = 0
                for row in sql.fetchall():
                    used_size += row['size']
                    row['mime_icon'] = pwic_mime2icon(row['mime'])
                    row['size'] = pwic_size2str(row['size'])
                    pwic['documents'].append(row)
                pmax = pwic_int(pwic_option(sql, project, 'max_project_size', '0'))
                pwic['disk_space'] = {'used': used_size,
                                      'used_str': pwic_size2str(used_size),
                                      'project_max': pmax,
                                      'project_max_str': pwic_size2str(pmax),
                                      'percentage': min(100, float('%.2f' % (0 if pmax == 0 else 100. * used_size / pmax)))}

            # Render the page in HTML or Markdown
            return await self._handle_output(request, 'page-special' if page_special else 'page', pwic)

        # Edit the requested page
        elif action == 'edit':
            sql.execute(''' SELECT revision, draft, final, header, protection,
                                   title, markdown, tags, milestone
                            FROM pages
                            WHERE project  = ?
                              AND page     = ?
                              AND revision = ?
                              AND latest   = 'X' ''',
                        (project, page, revision))
            row = sql.fetchone()
            if row is None:
                raise web.HTTPBadRequest()
            for k in ['draft', 'final', 'header', 'protection']:
                row[k] = pwic_xb(row[k])
            pwic.update(row)
            return await self._handle_output(request, 'page-edit', pwic)

        # Show the history of the page
        elif action == 'history':
            # Redirect the pure reader if the history is disabled
            if pwic['pure_reader'] and (pwic_option(sql, project, 'no_history') is not None):
                raise web.HTTPTemporaryRedirect('/%s/%s' % (project, page))

            # Extract the revisions
            sql.execute(''' SELECT revision, latest, draft, final, author,
                                   date, time, title, comment, milestone,
                                   valuser, valdate, valtime
                            FROM pages
                            WHERE project = ?
                              AND page    = ?
                            ORDER BY revision DESC''',
                        (project, page))
            pwic['revisions'] = []
            for row in sql.fetchall():
                if pwic_xb(row['latest']):
                    pwic['title'] = row['title']
                for k in ['latest', 'draft', 'final']:
                    row[k] = pwic_xb(row[k])
                pwic['revisions'].append(row)
            return await self._handle_output(request, 'page-history', pwic)

        # Default behavior
        else:
            raise web.HTTPNotFound()

    async def page_random(self, request: web.Request) -> web.Response:
        ''' Serve a random page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handle_logon(request)

        # Check the authorizations
        project = pwic_safe_name(request.match_info.get('project', ''))
        sql = self._connect()
        sql.execute(''' SELECT COUNT(*) AS total
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.latest  = 'X'
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.disabled = '' ''',
                    (project, user))
        n = sql.fetchone()['total']
        if n == 0:
            raise web.HTTPUnauthorized()

        # Show a random page
        n = randint(0, n - 1)
        sql.execute(''' SELECT page
                        FROM pages
                        WHERE project = ?
                          AND latest  = 'X'
                        LIMIT 1
                        OFFSET ?''',
                    (project, n))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPInternalServerError()
        else:
            raise web.HTTPTemporaryRedirect('/%s/%s' % (project, row['page']))

    async def page_audit(self, request: web.Request) -> web.Response:
        ''' Serve the page to monitor the settings and the activty '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handle_logon(request)

        # Fetch the parameters
        project = pwic_safe_name(request.match_info.get('project', ''))
        sql = self._connect()
        drange = max(-1, pwic_int(pwic_option(sql, project, 'audit_range', '30')))
        dt = pwic_dt(drange)

        # Fetch the name of the project
        sql.execute(''' SELECT b.description
                        FROM roles AS a
                            INNER JOIN projects AS b
                                ON b.project = a.project
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.admin    = 'X'
                          AND a.disabled = '' ''',
                    (project, user))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPTemporaryRedirect('/%s/special' % project)  # Project not found, or user not authorized to view it
        pwic = {'title': 'Audit',
                'project': project,
                'project_description': row['description'],
                'range': drange,
                'systime': pwic_dt(),
                'up': app['up']}

        # Read the audit data
        sql.execute(''' SELECT id, date, time, author, event, user,
                               project, page, revision, string
                        FROM audit
                        WHERE project = ?
                          AND date   >= ?
                        ORDER BY id DESC''',
                    (project, dt['date-nd']))
        pwic['audits'] = []
        for row in sql.fetchall():
            del(row['id'])
            pwic['audits'].append(row)
        return await self._handle_output(request, 'page-audit', pwic)

    async def page_help(self, request: web.Request) -> web.Response:
        ''' Serve the help page to any user '''
        pwic = {'project': 'special',
                'page': 'help',
                'title': 'Help for Pwic'}
        return await self._handle_output(request, 'help', pwic)

    async def page_create(self, request: web.Request) -> web.Response:
        ''' Serve the page to create a new page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handle_logon(request)

        # Fetch the projects where the user can add pages
        pwic: Dict[str, Any] = {'title': 'Create a page',
                                'default_project': pwic_safe_name(request.rel_url.query.get('project', '')),
                                'projects': []}
        sql = self._connect()
        sql.execute(''' SELECT a.project, b.description
                        FROM roles AS a
                            INNER JOIN projects AS b
                                ON b.project = a.project
                        WHERE a.user     = ?
                          AND a.manager  = 'X'
                          AND a.disabled = ''
                        ORDER BY b.description''',
                    (user, ))
        for row in sql.fetchall():
            pwic['projects'].append(row)

        # Show the page
        return await self._handle_output(request, 'page-create', pwic=pwic)

    async def user_create(self, request: web.Request) -> web.Response:
        ''' Serve the page to create a new user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handle_logon(request)

        # Fetch the projects where users can be created
        pwic: Dict[str, Any] = {'title': 'Create a user',
                                'default_project': request.rel_url.query.get('project', ''),
                                'projects': []}
        sql = self._connect()
        sql.execute(''' SELECT a.project, b.description
                        FROM roles AS a
                            INNER JOIN projects AS b
                                ON b.project = a.project
                        WHERE a.user     = ?
                          AND a.admin    = 'X'
                          AND a.disabled = ''
                        ORDER BY b.description''',
                    (user, ))
        for row in sql.fetchall():
            pwic['projects'].append(row)

        # Show the page
        return await self._handle_output(request, 'user-create', pwic=pwic)

    async def page_user(self, request: web.Request) -> web.Response:
        ''' Serve the page to view the profile of a user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handle_logon(request)

        # Fetch the information of the user
        sql = self._connect()
        userpage = pwic_safe_user_name(request.match_info.get('userpage', ''))
        row = sql.execute(''' SELECT password, initial FROM users WHERE user = ?''', (userpage, )).fetchone()
        if row is None:
            raise web.HTTPNotFound()
        pwic = {'title': 'User profile',
                'user': user,
                'userpage': userpage,
                'password_oauth': row['password'] == PWIC_MAGIC_OAUTH,
                'password_initial': pwic_xb(row['initial']),
                'projects': [],
                'documents': [],
                'pages': []}

        # Fetch the commonly-accessible projects assigned to the user
        sql.execute(''' SELECT a.project, c.description
                        FROM roles AS a
                            INNER JOIN roles AS b
                                ON  b.project  = a.project
                                AND b.user     = ?
                                AND b.disabled = ''
                            INNER JOIN projects AS c
                                ON c.project = a.project
                        WHERE a.user     = ?
                          AND a.disabled = ''
                        ORDER BY c.description''',
                    (user, userpage))
        for row in sql.fetchall():
            pwic['projects'].append(row)

        # Fetch the own documents
        sql.execute(''' SELECT b.id, b.project, b.page, b.filename, b.mime, b.size,
                               b.hash, b.author, b.date, b.time, b.exturl, c.occurrence
                        FROM roles AS a
                            INNER JOIN documents AS b
                                ON  b.project = a.project
                                AND b.author  = ?
                            INNER JOIN (
                                SELECT project, hash, COUNT(*) AS occurrence
                                FROM documents
                                GROUP BY project, hash
                            ) AS c
                                ON  c.project = a.project
                                AND c.hash    = b.hash
                        WHERE a.user     = ?
                          AND a.disabled = ''
                        ORDER BY date DESC,
                                 time DESC''',
                    (userpage, user))
        for row in sql.fetchall():
            row['mime_icon'] = pwic_mime2icon(row['mime'])
            row['size'] = pwic_size2str(row['size'])
            pwic['documents'].append(row)

        # Fetch the latest pages updated by the selected user
        dt = pwic_dt()
        sql.execute(''' SELECT u.project, u.page, p.revision, p.final,
                               p.date, p.time, p.title, p.milestone,
                               p.valuser, p.valdate, p.valtime
                        FROM (
                            SELECT DISTINCT project, page
                            FROM (
                                SELECT project, page
                                FROM pages
                                WHERE latest   = 'X'
                                  AND author   = ?
                                  AND date    >= ?
                            UNION
                                SELECT project, page
                                FROM pages
                                WHERE valuser  = ?
                                  AND valdate >= ?
                            )
                        ) AS u
                            INNER JOIN roles AS r
                                ON  r.project  = u.project
                                AND r.user     = ?
                                AND r.disabled = ''
                            INNER JOIN pages AS p
                                ON  p.project  = u.project
                                AND p.page     = u.page
                                AND p.latest   = 'X'
                        ORDER BY date DESC,
                                 time DESC''',
                    (userpage, dt['date-90d'], userpage, dt['date-90d'], user))
        for row in sql.fetchall():
            pwic['pages'].append(row)

        # Show the page
        return await self._handle_output(request, 'user', pwic=pwic)

    async def page_search(self, request: web.Request) -> web.Response:
        ''' Serve the search engine '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handle_logon(request)

        # Parse the query
        sql = self._connect()
        project = pwic_safe_name(request.match_info.get('project', ''))
        if pwic_option(sql, project, 'no_search') is not None:
            query = None
        else:
            query = pwic_search_parse(request.rel_url.query.get('q', ''))
        if query is None:
            raise web.HTTPTemporaryRedirect('/%s' % project)

        # Restrict the parameters
        pure_reader = self._is_pure_reader(sql, project, user)
        if pure_reader is None:
            raise web.HTTPUnauthorized()
        if pure_reader and (pwic_option(sql, project, 'no_history') is not None):
            with_rev = False
        else:
            with_rev = 'rev' in request.rel_url.query
        PwicExtension.on_search_terms(sql, project, user, query, with_rev)

        # Fetch the description of the project
        sql.execute(''' SELECT description
                        FROM projects
                        WHERE project = ?''',
                    (project, ))
        pwic = {'title': 'Search',
                'project': project,
                'project_description': sql.fetchone()['description'],
                'terms': pwic_search2string(query),
                'pages': [],
                'documents': [],
                'with_rev': with_rev,
                'pure_reader': pure_reader}

        # Search for a page
        if not PwicExtension.on_search_pages(sql, user, pwic, query):
            sql.execute(''' SELECT a.project, a.page, a.revision, a.latest, a.draft, a.final,
                                   a.author, a.date, a.time, a.title, LOWER(a.markdown) AS markdown,
                                   a.tags, a.valuser, a.valdate, a.valtime, b.document_count
                            FROM pages AS a
                                LEFT JOIN (
                                    SELECT project, page, COUNT(id) AS document_count
                                    FROM documents
                                    GROUP BY project, page
                                    HAVING project = ?
                                ) AS b
                                    ON  b.project = a.project
                                    AND b.page    = a.page
                            WHERE a.project = ?
                              AND a.latest IN ('%sX')
                            ORDER BY a.date DESC,
                                     a.time DESC''' % ("','" if with_rev else ''),
                        (project, project))
            for row in sql.fetchall():
                tagList = row['tags'].split(' ')

                # Apply the filters
                ok = True
                score = 0
                for q in query['excluded']:         # The first occurrence of an excluded term excludes the whole page
                    if (q == ':latest' and pwic_xb(row['latest']))                          \
                       or (q == ':draft' and pwic_xb(row['draft']))                         \
                       or (q == ':final' and pwic_xb(row['final']))                         \
                       or (q[:7] == 'author:' and q[7:] in row['author'].lower())           \
                       or (q[:6] == 'title:' and q[6:] in row['title'].lower())             \
                       or (q == ':validated' and row['valuser'] != '')                      \
                       or (q[:10] == 'validator:' and q[10:] in row['valuser'].lower())     \
                       or (q == ':document' and pwic_int(row['document_count']) > 0)        \
                       or (q[1:] in tagList if q[:1] == '#' else False)                     \
                       or (q == row['page'].lower())                                        \
                       or (q in row['markdown']):
                        ok = False
                        break
                if ok:
                    for q in query['included']:     # The first non-occurrence of an included term excludes the whole page
                        if q == ':latest':
                            count = pwic_int(pwic_xb(row['latest']))
                        elif q == ':draft':
                            count = pwic_int(pwic_xb(row['draft']))
                        elif q == ':final':
                            count = pwic_int(pwic_xb(row['final']))
                        elif q[:7] == 'author:':
                            count = row['author'].lower().count(q[7:])
                        elif q[:6] == 'title:':
                            count = row['title'].lower().count(q[6:])
                        elif q == ':validated':
                            count = pwic_int(row['valuser'] != '')
                        elif q[:10] == 'validator:':
                            count = pwic_int(q[10:] in row['valuser'].lower())
                        elif q == ':document':
                            count = pwic_int(pwic_int(row['document_count']) > 0)
                        elif (q[1:] in tagList if q[:1] == '#' else False):
                            count = 5               # A tag counts more
                        else:
                            count = 5 * pwic_int(q == row['page'].lower()) + row['markdown'].count(q)
                        if count == 0:
                            ok = False
                            break
                        else:
                            score += count
                if not ok:
                    continue

                # Save the found result
                pwic['pages'].append({'project': row['project'],
                                      'page': row['page'],
                                      'revision': row['revision'],
                                      'latest': pwic_xb(row['latest']),
                                      'draft': pwic_xb(row['draft']),
                                      'final': pwic_xb(row['final']),
                                      'author': row['author'],
                                      'date': row['date'],
                                      'time': row['time'],
                                      'title': row['title'],
                                      'valuser': row['valuser'],
                                      'valdate': row['valdate'],
                                      'valtime': row['valtime'],
                                      'score': score})

        # Search for documents
        if not PwicExtension.on_search_documents(sql, user, pwic, query):
            sql.execute(''' SELECT id, project, page, filename, mime, size, author, date, time
                            FROM documents
                            WHERE project = ?
                            ORDER BY filename''',
                        (project, ))
            for row in sql.fetchall():
                # Apply the filters
                ok = True
                for q in query['excluded']:
                    if ':' in q:
                        continue
                    if (q in row['page']) \
                       or (q in row['filename']) \
                       or (q in row['mime']):
                        ok = False
                        break
                if ok:
                    for q in query['included']:
                        if ':' in q:
                            continue
                        if (q not in row['page']) \
                           and (q not in row['filename']) \
                           and (q not in row['mime']):
                            ok = False
                            break
                if not ok:
                    continue

                # Save the found document
                row['mime_icon'] = pwic_mime2icon(row['mime'])
                row['size'] = pwic_size2str(row['size'])
                pwic['documents'].append(row)

        # Show the pages by score desc, date desc and time desc
        pwic['pages'].sort(key=lambda x: x['score'], reverse=True)
        return await self._handle_output(request, 'search', pwic=pwic)

    async def page_env(self, request: web.Request) -> web.Response:
        ''' Serve the project-dependent settings that can be modified online
            without critical, technical or legal impact on the server '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handle_logon(request)

        # Fetch the parameters
        project = pwic_safe_name(request.match_info.get('project', ''))

        # Verify that the user is an administrator
        sql = self._connect()
        if sql.execute(''' SELECT user
                           FROM roles
                           WHERE project  = ?
                             AND user     = ?
                             AND admin    = 'X'
                             AND disabled = '' ''',
                       (project, user)).fetchone() is None:
            raise web.HTTPUnauthorized()

        # Show the page
        sql.execute(''' SELECT description
                        FROM projects
                        WHERE project = ?''',
                    (project, ))
        pwic = {'title': 'Project-dependent environment variables',
                'project': project,
                'project_description': sql.fetchone()['description']}
        return await self._handle_output(request, 'page-env', pwic=pwic)

    async def page_roles(self, request: web.Request) -> web.Response:
        ''' Serve the form to change the authorizations of the users '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handle_logon(request)

        # Fetch the name of the project
        project = pwic_safe_name(request.match_info.get('project', ''))
        sql = self._connect()
        pwic: Dict[str, Any] = {'title': 'Roles',
                                'project': project,
                                'roles': []}

        # Fetch the roles
        sql.execute(''' SELECT a.user, c.initial, c.password == '%s' AS oauth,
                               a.admin, a.manager, a.editor, a.validator, a.reader, a.disabled
                        FROM roles AS a
                            INNER JOIN roles AS b
                                ON  b.project  = a.project
                                AND b.user     = ?
                                AND b.admin    = 'X'
                                AND b.disabled = ''
                            INNER JOIN users AS c
                                ON  c.user = a.user
                        WHERE a.project = ?
                        ORDER BY a.admin     DESC,
                                 a.manager   DESC,
                                 a.editor    DESC,
                                 a.validator DESC,
                                 a.reader    DESC,
                                 a.user      ASC''' % pwic_apostrophe(PWIC_MAGIC_OAUTH),
                    (user, project))
        for row in sql.fetchall():
            pwic['roles'].append({'user': row['user'],
                                  'initial': pwic_xb(row['initial']),
                                  'oauth': row['oauth'] == 1,
                                  'admin': pwic_xb(row['admin']),
                                  'manager': pwic_xb(row['manager']),
                                  'editor': pwic_xb(row['editor']),
                                  'validator': pwic_xb(row['validator']),
                                  'reader': pwic_xb(row['reader']),
                                  'disabled': pwic_xb(row['disabled'])})

        # Display the page
        if len(pwic['roles']) == 0:
            raise web.HTTPUnauthorized()        # Or project not found
        sql.execute(''' SELECT description
                        FROM projects
                        WHERE project = ?''',
                    (project, ))
        pwic['project_description'] = sql.fetchone()['description']
        return await self._handle_output(request, 'user-roles', pwic=pwic)

    async def page_links(self, request: web.Request) -> web.Response:
        ''' Serve the check of the links '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handle_logon(request)

        # Fetch the parameters
        project = pwic_safe_name(request.match_info.get('project', ''))
        sql = self._connect()

        # Fetch the documents of the project
        sql.execute(''' SELECT id
                        FROM documents
                        ORDER BY id''')
        docids = []
        for row in sql.fetchall():
            docids.append(str(row['id']))

        # Fetch the pages
        sql.execute(''' SELECT b.page, b.header, b.markdown
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.latest  = 'X'
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.manager  = 'X'
                          AND a.disabled = ''
                        ORDER BY b.page''',
                    (project, user))

        # Extract the links between the pages
        ok = False
        linkmap: Dict[str, List[str]] = {PWIC_DEFAULTS['page']: []}
        broken_docs: Dict[str, List[int]] = {}
        for row in sql.fetchall():
            ok = True
            page = row['page']
            if page not in linkmap:
                linkmap[page] = []

            # Generate a fake link at the home page for all the bookmarked pages
            if pwic_xb(row['header']) and page not in linkmap[PWIC_DEFAULTS['page']]:
                linkmap[PWIC_DEFAULTS['page']].append(page)

            # Find the links to the other pages
            subpages = PWIC_REGEXES['page'].findall(row['markdown'])
            if subpages is not None:
                for sp in subpages:
                    if (sp[0] == project) and (sp[1] not in linkmap[page]):
                        linkmap[page].append(sp[1])

            # Looks for the linked documents
            subdocs = PWIC_REGEXES['document'].findall(row['markdown'])
            if subdocs is not None:
                for sd in subdocs:
                    if sd[0] not in docids:
                        if page not in broken_docs:
                            broken_docs[page] = []
                        broken_docs[page].append(pwic_int(sd[0]))
        if not ok:
            raise web.HTTPUnauthorized()

        # Find the orphaned and broken links
        allpages = [key for key in linkmap]
        orphans = allpages.copy()
        orphans.remove(PWIC_DEFAULTS['page'])
        broken = []
        for link in linkmap:
            for page in linkmap[link]:
                if page in orphans:
                    orphans.remove(page)
                if page not in allpages:
                    broken.append({'source': link,
                                   'destination': page})

        # Show the values
        sql.execute(''' SELECT description
                        FROM projects
                        WHERE project = ?''',
                    (project, ))
        pwic = {'title': 'Report of the links',
                'project': project,
                'project_description': sql.fetchone()['description'],
                'orphans': orphans,
                'broken': broken,
                'broken_docs': broken_docs}
        return await self._handle_output(request, 'page-links', pwic=pwic)

    async def page_graph(self, request: web.Request) -> web.Response:
        ''' Serve the visual representation of the links '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handle_logon(request)

        # Fetch the parameters
        project = pwic_safe_name(request.match_info.get('project', ''))
        sql = self._connect()

        # Check the authorizations
        sql.execute(''' SELECT user
                        FROM roles
                        WHERE project  = ?
                          AND user     = ?
                          AND manager  = 'X'
                          AND disabled = '' ''',
                    (project, user))
        if (sql.fetchone() is None) or \
           (pwic_option(sql, project, 'no_graph') is not None):
            raise web.HTTPUnauthorized()

        # Show the page
        sql.execute(''' SELECT description
                        FROM projects
                        WHERE project = ?''',
                    (project, ))
        pwic = {'title': 'Graph of the project',
                'project': project,
                'project_description': sql.fetchone()['description']}
        return await self._handle_output(request, 'page-graph', pwic=pwic)

    async def page_compare(self, request: web.Request) -> web.Response:
        ''' Serve the page that compares two revisions '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handle_logon(request)

        # Fetch the pages
        sql = self._connect()
        project = pwic_safe_name(request.match_info.get('project', ''))
        page = pwic_safe_name(request.match_info.get('page', ''))
        new_revision = pwic_int(request.match_info.get('new_revision', ''))
        old_revision = pwic_int(request.match_info.get('old_revision', ''))
        sql.execute(''' SELECT d.description,
                               b.title,
                               b.markdown AS new_markdown,
                               c.markdown AS old_markdown
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project  = a.project
                                AND b.page     = ?
                                AND b.revision = ?
                            INNER JOIN pages AS c
                                ON  c.project  = b.project
                                AND c.page     = b.page
                                AND c.revision = ?
                            INNER JOIN projects AS d
                                ON  d.project  = a.project
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.disabled = '' ''',
                    (page, new_revision, old_revision, project, user))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPUnauthorized()

        # Show the page
        def _diff(tfrom: str, tto: str) -> str:
            diff = HtmlDiff()
            tfrom2 = tfrom.replace('\r', '').split('\n')
            tto2 = tto.replace('\r', '').split('\n')
            return diff.make_table(tfrom2, tto2)            \
                       .replace('&nbsp;', ' ')              \
                       .replace(' nowrap="nowrap"', '')     \
                       .replace(' cellpadding="0"', '')

        pwic = {'title': row['title'],
                'project': project,
                'project_description': row['description'],
                'page': page,
                'new_revision': new_revision,
                'old_revision': old_revision,
                'diff': _diff(row['old_markdown'], row['new_markdown'])}
        return await self._handle_output(request, 'page-compare', pwic=pwic)

    async def document_get(self, request: web.Request) -> web.Response:
        ''' Download a document '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return web.HTTPUnauthorized()

        # Read the properties of the requested document
        id = pwic_int(request.match_info.get('id', 0))
        sql = self._connect()
        sql.execute(''' SELECT a.project, a.filename, a.mime, a.size, a.exturl
                        FROM documents AS a
                            INNER JOIN roles AS b
                                ON  b.project  = a.project
                                AND b.user     = ?
                                AND b.disabled = ''
                        WHERE a.id = ?''',
                    (user, id))
        row = sql.fetchone()
        if row is None:
            return web.HTTPNotFound()

        # Remote file
        if row['exturl'] != '':
            if PWIC_REGEXES['protocol'].match(row['exturl']) is not None:
                return web.HTTPFound(row['exturl'])
            else:
                raise web.HTTPNotFound()

        # Transfer the file
        filename = join(PWIC_DOCUMENTS_PATH % row['project'], row['filename'])
        try:
            if getsize(filename) != row['size']:
                raise web.HTTPConflict()  # Size mismatch causes an infinite download time
            if not PwicExtension.on_document_get(sql, row['project'], user, row['filename'], row['mime'], row['size']):
                raise web.HTTPUnauthorized()
            with open(filename, 'rb') as f:
                content = f.read()
        except FileNotFoundError:
            raise web.HTTPNotFound()
        headers = {'Content-Type': row['mime'],
                   'Content-Length': str(row['size'])}
        if request.rel_url.query.get('attachment', None) is not None:
            headers['Content-Disposition'] = 'attachment; filename="%s"' % pwic_attachment_name(row['filename'])
        return web.Response(body=content, headers=MultiDict(headers))

    async def api_logon(self, request: web.Request) -> web.Response:
        ''' API to log on people '''
        # Checks
        self._check_ip(request)

        # Fetch the submitted data
        post = await self._handle_post(request)
        user = pwic_safe_user_name(post.get('user', ''))
        pwd = '' if user == PWIC_USERS['anonymous'] else pwic_sha256(post.get('password', ''))
        lang = post.get('language', PWIC_DEFAULTS['language'])
        if lang not in app['langs']:
            lang = PWIC_DEFAULTS['language']

        # Logon with the credentials
        ok = False
        sql = self._connect()
        sql.execute(''' SELECT COUNT(a.user) AS total
                        FROM users AS a
                            INNER JOIN roles AS b
                                ON  b.user     = a.user
                                AND b.disabled = ''
                        WHERE a.user     = ?
                          AND a.password = ?''',
                    (user, pwd))
        if sql.fetchone()['total'] > 0:
            ok = PwicExtension.on_logon(sql, user, lang)
            if ok:
                session = await new_session(request)
                session['user'] = user
                session['language'] = lang
                if user != PWIC_USERS['anonymous']:
                    pwic_audit(sql, {'author': user,
                                     'event': 'logon'},
                               request)
                    self._commit()

        # Final redirection (do not use "raise")
        if request.rel_url.query.get('redirect', None) is not None:
            return web.HTTPFound('/' if ok else '/?failed')
        else:
            return web.HTTPOk() if ok else web.HTTPUnauthorized()

    async def api_logout(self, request: web.Request) -> web.Response:
        ''' API to log out '''
        # Logging the disconnection (not visible online) aims to not report a reader as inactive.
        # Knowing that the session is encrypted in the cookie, the event does NOT guarantee that
        # it is effectively destroyed by the user (his web browser generally does it). The session
        # is fully lost upon server restart because a new key is generated.
        user = await self._suser(request)
        if user not in ['', PWIC_USERS['anonymous']]:
            pwic_audit(self._connect(), {'author': user,
                                         'event': 'logout'},
                       request)
            self._commit()

        # Destroy the session
        session = await get_session(request)
        session.invalidate()
        return await self._handle_output(request, 'logout', {'title': 'Disconnected from Pwic'})

    async def api_oauth(self, request: web.Request) -> web.Response:
        ''' Manage the federated authentication '''

        def _oauth_failed():
            raise web.HTTPTemporaryRedirect('/?failed')

        def _fetch_token(url, query):
            try:
                response = urlopen(Request(url,
                                           urlencode(query).encode(),
                                           method='POST',
                                           headers={'Accept': 'application/json'}))
                data = response.read()
                data = data.decode(response.info().get_content_charset())
                data = json.loads(data)
                token = data.get('access_token', None)
                if token is None:
                    raise Exception()
                return data.get('token_type', 'Bearer'), token
            except Exception:
                _oauth_failed()

        def _call_api(url, token_type, token):
            try:
                response = urlopen(Request(url, headers={'Authorization': '%s %s' % (token_type, token)}))
                data = response.read()
                data = data.decode(response.info().get_content_charset())
                data = json.loads(data)
                if data is None:
                    raise Exception()
                return data
            except Exception:
                _oauth_failed()

        # Checks
        self._check_ip(request)

        # Get the callback parameters
        error = request.rel_url.query.get('error', '')
        code = request.rel_url.query.get('code', None)
        state = request.rel_url.query.get('state', None)
        if (error != '') or (None in [code, state]):
            _oauth_failed()

        # Check the state
        session = await get_session(request)
        state_current = session.get('user_secret', '')
        if state != state_current:
            session['user_secret'] = pwic_random_hash()
            _oauth_failed()

        # Call the provider
        sql = self._connect()
        oauth = app['oauth']
        no_domain = (len(oauth['domains']) == 0)
        emails = []
        if oauth['provider'] == 'github':
            # Fetch an authentication token
            query = {'client_id': oauth['identifier'],
                     'client_secret': oauth['server_secret'],
                     'code': code,
                     'state': state}
            _, token = _fetch_token('https://github.com/login/oauth/access_token', query)

            # Fetch the emails of the user
            data = _call_api('https://api.github.com/user/emails', 'token', token)
            for entry in data:
                if entry.get('verified', False) is True:
                    if no_domain and not entry.get('primary', False):   # If the domain is not verified, only the primary email is targeted
                        continue
                    item = entry.get('email', '')
                    if '@' in item:
                        emails.append(item.strip().lower())
                        if no_domain:                                   # If the domain is not verified, the primary email is found
                            break

        elif oauth['provider'] == 'google':
            # Fetch an authentication token
            query = {'client_id': oauth['identifier'],
                     'grant_type': 'authorization_code',
                     'code': code,
                     'redirect_uri': str(pwic_option(sql, '', 'base_url', '')) + '/api/oauth',
                     'client_secret': oauth['server_secret']}
            token_type, token = _fetch_token('https://oauth2.googleapis.com/token', query)

            # Fetch the email of the user
            data = _call_api('https://www.googleapis.com/userinfo/v2/me', token_type, token)
            if data.get('verified_email', False) is True:
                item = data.get('email', '').strip().lower()
                if '@' in item and '+' not in item:
                    emails.append(item)

        elif oauth['provider'] == 'microsoft':
            # Fetch an authentication token
            query = {'client_id': oauth['identifier'],
                     'grant_type': 'authorization_code',
                     'scope': 'https://graph.microsoft.com/user.read',
                     'code': code,
                     'redirect_uri': str(pwic_option(sql, '', 'base_url', '')) + '/api/oauth',
                     'client_secret': oauth['server_secret']}
            token_type, token = _fetch_token('https://login.microsoftonline.com/%s/oauth2/v2.0/token' % oauth['tenant'], query)

            # Fetch the email of the user
            data = _call_api('https://graph.microsoft.com/v1.0/me/', token_type, token)
            item = data.get('mail', '').strip().lower()
            if '@' in item:
                emails.append(item)

        else:
            raise web.HTTPNotImplemented()

        # Select the authorized email
        PwicExtension.on_oauth(sql, emails)
        if len(emails) == 0:
            _oauth_failed()
        if no_domain:
            user = emails[0]
        else:
            user = ''
            cursor = len(oauth['domains'])
            for item in emails:
                domain = item[item.find('@') + 1:]
                try:
                    index = oauth['domains'].index(domain)
                except ValueError:
                    continue
                if index < cursor:
                    user = item
                    cursor = index
        user = pwic_safe_user_name(user)
        if (user[:4] in ['', 'pwic']) or ('@' not in user):
            _oauth_failed()

        # Create the default user account
        if not self._lock(sql):
            raise web.HTTPServiceUnavailable()
        if sql.execute(''' SELECT 1 FROM users WHERE user = ?''', (user, )).fetchone() is None:
            sql.execute(''' INSERT INTO users (user, password, initial) VALUES (?, ?, '')''', (user, PWIC_MAGIC_OAUTH))
            # Remarks:
            # - PWIC_DEFAULTS['password'] is not set because the user will forget to change it
            # - The user cannot change the internal password because the current password will not be hashed correctly
            # - The password can be reset from the administration console only
            # - Then the two authentications methods can coexist
            pwic_audit(sql, {'author': PWIC_USERS['system'],
                             'event': 'create-user',
                             'user': user,
                             'string': PWIC_MAGIC_OAUTH},
                       request)

        # Register the session
        session = await new_session(request)
        session['user'] = user
        session['language'] = PWIC_DEFAULTS['language']     # TODO The language is not selectable
        session['user_secret'] = pwic_random_hash()
        pwic_audit(sql, {'author': user,
                         'event': 'logon',
                         'string': PWIC_MAGIC_OAUTH},
                   request)
        self._commit()

        # Final redirection (do not use "raise")
        return web.HTTPFound('/')

    async def api_server_env_get(self, request: web.Request) -> web.Response:
        ''' API to return the defined environment variables '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user in ['', PWIC_USERS['anonymous']]:
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))

        # Verify that the user is an administrator of the project
        sql = self._connect()
        if project != '':
            sql.execute(''' SELECT user
                            FROM roles
                            WHERE project  = ?
                              AND user     = ?
                              AND admin    = 'X'
                              AND disabled = '' ''',
                        (project, user))
            if sql.fetchone() is None:
                project = ''

        # Fetch the environment variables
        sql.execute(''' SELECT project, key, value
                        FROM env
                        WHERE ( project = ?
                             OR project = '' )
                          AND   value  <> ''
                        ORDER BY key ASC,
                                 project DESC''',
                    (project, ))
        data = {}
        for row in sql.fetchall():
            (global_, key, value) = (row['project'] == '', row['key'], row['value'])
            if key in PWIC_ENV_PRIVATE:
                value = None
            if key not in data:
                data[key] = {'value': value,
                             'global': global_,
                             'project_dependent': key in PWIC_ENV_PROJECT_DEPENDENT,
                             'changeable': (project != '') and (key in PWIC_ENV_PROJECT_DEPENDENT_ONLINE)}

        # Final result
        return web.Response(text=json.dumps(data), content_type=pwic_mime('json'))

    async def api_server_ping(self, request: web.Request) -> web.Response:
        ''' Notify if the session is still alive '''
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()
        else:
            return web.Response(text='OK', content_type=pwic_mime('txt'))

    async def api_project_info_get(self, request: web.Request) -> web.Response:
        ''' API to fetch the metadata of the project '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        if project == '':
            raise web.HTTPBadRequest()
        page = pwic_safe_name(post.get('page', ''))                                     # Optional
        all = post.get('all', None) is not None
        data: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

        # Restriction of the API
        sql = self._connect()
        pure_reader = self._is_pure_reader(sql, project, user)
        if pure_reader is None:
            raise web.HTTPUnauthorized()                                                # No access to the project
        if pure_reader and (pwic_option(sql, project, 'no_history') is not None):
            all = False

        # Fetch the pages
        exposeMD = pwic_option(sql, project, 'api_expose_markdown', None) is not None
        sql.execute(''' SELECT page, revision, latest, draft, final,
                               header, protection, author, date, time,
                               title, markdown, tags, comment, milestone,
                               valuser, valdate, valtime
                        FROM pages
                        WHERE project = ?
                          AND (page = ? OR '' = ?)
                          AND latest IN ('%sX')
                        ORDER BY page ASC,
                                 revision DESC''' % ("','" if all else '', ),
                    (project, page, page))
        for row in sql.fetchall():
            if row['page'] not in data:
                data[row['page']] = {'revisions': [],
                                     'documents': []}
            item = {}
            for k in row:
                if k == 'markdown':
                    if exposeMD:
                        item[k] = row[k]
                    item['hash'] = pwic_sha256(row[k], salt=False)
                elif k == 'tags':
                    if row[k] != '':
                        item[k] = row[k].split(' ')
                elif k != 'page':
                    if not isinstance(row[k], str) or row[k] != '':
                        item[k] = row[k]
            item['url'] = '/%s/%s/rev%d' % (quote(project), quote(row['page']), row['revision'])
            data[row['page']]['revisions'].append(item)

        # Fetch the documents
        sql.execute(''' SELECT id, page, filename, mime, size, hash, author, date, time
                        FROM documents
                        WHERE project = ?
                          AND (page = ? OR '' = ?)
                        ORDER BY page, filename''',
                    (project, page, page))
        for row in sql.fetchall():
            row['url'] = '/special/document/%d/%s?attachment' % (row['id'], quote(row['filename']))
            k = row['page']
            del(row['page'])
            data[k]['documents'].append(row)

        # Final result
        PwicExtension.on_api_project_info_get(sql, project, user, page, data)
        return web.Response(text=json.dumps(data), content_type=pwic_mime('json'))

    async def api_project_env_set(self, request: web.Request) -> web.Response:
        ''' API to modify some of the project-dependent settings '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        key = pwic_safe_name(post.get('key', ''))
        value = post.get('value', '')
        if (project == '') or (key not in PWIC_ENV_PROJECT_DEPENDENT_ONLINE):
            raise web.HTTPBadRequest()

        # Verify that the user is administrator of the project
        sql = self._connect()
        if sql.execute(''' SELECT user
                           FROM roles
                           WHERE project  = ?
                             AND user     = ?
                             AND admin    = 'X'
                             AND disabled = '' ''',
                       (project, user)).fetchone() is None:
            raise web.HTTPUnauthorized()

        # Update the variable
        value = PwicExtension.on_api_project_env_set(sql, project, user, key, value)
        if value in [None, '']:
            sql.execute(''' DELETE FROM env WHERE project = ? AND key = ?''', (project, key))
        else:
            sql.execute(''' INSERT OR REPLACE INTO env (project, key, value) VALUES (?, ?, ?)''', (project, key, value))
        pwic_audit(sql, {'author': user,
                         'event': '%sset-%s' % ('un' if value == '' else '', key),
                         'project': project,
                         'string': value},
                   request)
        self._commit()
        raise web.HTTPOk()

    async def api_project_progress_get(self, request: web.Request) -> web.Response:
        ''' API to analyze the progress of the project '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        tags = post.get('tags', '').strip()
        if '' in [project, tags]:
            raise web.HTTPBadRequest()

        # Verify that the user is authorized for the project
        sql = self._connect()
        if sql.execute(''' SELECT user
                           FROM roles
                           WHERE project  = ?
                             AND user     = ?
                             AND disabled = '' ''',
                       (project, user)).fetchone() is None:
            return web.HTTPUnauthorized()

        # Check each tag
        tags = sorted(tags.split(' '))
        data = {}
        for tag in tags:
            if tag == '':
                continue
            item = {'draft': 0,
                    'step': 0,
                    'final': 0,
                    'validated': 0,
                    'total': 0}

            # Select the pages
            sql.execute(''' SELECT draft, final, valuser
                            FROM pages
                            WHERE project = ?
                              AND latest = 'X'
                              AND ' '||tags||' ' LIKE ? ''',
                        (project, '%% %s %%' % tag))
            for row in sql.fetchall():
                if row['valuser'] != '':
                    item['validated'] += 1
                elif pwic_xb(row['final']):
                    item['final'] += 1
                elif pwic_xb(row['draft']):
                    item['draft'] += 1
                else:
                    item['step'] += 1
                item['total'] += 1
            data[tag] = item

        # Final result
        return web.Response(text=json.dumps(data), content_type=pwic_mime('json'))

    async def api_project_graph_get(self, request: web.Request) -> web.Response:
        ''' Draw the directed graph of the project
            http://graphviz.org/pdf/dotguide.pdf
            http://graphviz.org/Gallery/directed/go-package.html
            http://viz-js.com
        '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the posted values
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        if project == '':
            raise web.HTTPBadRequest()

        # Verify the feature
        sql = self._connect()
        if pwic_option(sql, project, 'no_graph') is not None:
            raise web.HTTPUnauthorized()

        # Fetch the pages
        sql.execute(''' SELECT b.project, b.page, b.header, b.markdown
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.latest  = 'X'
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.manager  = 'X'
                          AND a.disabled = ''
                        ORDER BY b.project,
                                 b.page''',
                    (project, user))

        # Map the pages
        pages: List[Tuple[str, str]] = []
        maps: List[Tuple[str, str, str, str]] = []

        def _make_link(fromProject: str, fromPage: str, toProject: str, toPage: str) -> None:
            if (fromProject, fromPage) != (toProject, toPage):
                tuple = (toProject, toPage, fromProject, fromPage)
                pos = bisect_left(maps, tuple)
                if pos >= len(maps) or maps[pos] != tuple:
                    insort(maps, tuple)

        def _get_node_id(project: str, page: str) -> str:
            tuple = (project, page)
            pos = bisect_left(pages, tuple)
            if (pos >= len(pages)) or (pages[pos] != tuple):
                insort(pages, tuple)
                return _get_node_id(project, page)
            else:
                return 'n%d' % (pos + 1)

        def _get_node_title(sql: sqlite3.Cursor, project: str, page: str) -> str:
            # TODO Possible technical improvement here to avoid selects in loops
            sql.execute(''' SELECT title
                            FROM pages
                            WHERE project = ?
                              AND page    = ?
                              AND latest  = 'X' ''',
                        (project, page))
            row = sql.fetchone()
            return '' if row is None else row['title']

        for row in sql.fetchall():
            # Reference the processed page
            _get_node_id(row['project'], row['page'])
            _make_link('', '', row['project'], row['page'])

            # Assign the bookmarks to the home page
            if pwic_xb(row['header']):
                _make_link(row['project'], PWIC_DEFAULTS['page'], row['project'], row['page'])

            # Find the links to the other pages
            subpages = PWIC_REGEXES['page'].findall(row['markdown'])
            if subpages is not None:
                for sp in subpages:
                    _get_node_id(sp[0], sp[1])
                    _make_link(row['project'], row['page'], sp[0], sp[1])
        if len(maps) == 0:
            raise web.HTTPUnauthorized()

        # Authorized projects of the user
        sql.execute(''' SELECT project
                        FROM roles
                        WHERE user     = ?
                          AND disabled = '' ''',
                    (user, ))
        authorized_projects = []
        for row in sql.fetchall():
            authorized_projects.append(row['project'])

        # Build the file for GraphViz
        viz = 'digraph PWIC {\n'
        lastProject = ''
        for toProject, toPage, fromProject, fromPage in maps:
            # Detection of a new project
            changedProject = (toProject != lastProject)
            if changedProject:
                if lastProject != '':
                    viz += '}\n'
                lastProject = toProject
                viz += 'subgraph cluster_%s {\n' % toProject
                viz += 'label="%s";\n' % toProject.replace('"', '\\"')
                if toProject in authorized_projects:
                    viz += 'URL="/%s";\n' % toProject.replace('"', '\\"')

                # Define all the nodes of the cluster
                for project, page in pages:
                    if project == toProject:
                        title = _get_node_title(sql, project, page)
                        if title != '' and project not in authorized_projects:
                            title = '[No authorization]'
                        viz += '%s [label="%s"; tooltip="%s"%s%s];\n' % \
                               (_get_node_id(project, page),
                                page.replace('"', '\\"'),
                                title.replace('"', '\\"') if title != '' else '[The page does not exist]',
                                ('; URL="/%s/%s"' % (project, page) if project in authorized_projects and title != '' else ''),
                                ('; color=red' if title == '' else ''))

            # Create the links in the cluster of the targeted node (else there is no box)
            if '' not in [fromProject, fromPage]:
                viz += '%s -> %s;\n' % (_get_node_id(fromProject, fromPage),
                                        _get_node_id(toProject, toPage))

        # Final output
        if len(maps) > 0:
            viz += '}\n'
        viz += '}'
        return web.Response(text=viz, content_type='text/vnd.graphviz')

    async def api_project_export(self, request: web.Request) -> web.Response:
        ''' Download the project as a ZIP file '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the posted values
        project = pwic_safe_name(request.rel_url.query.get('project', ''))
        if project == '':
            raise web.HTTPBadRequest()

        # Verify that the export is authorized
        sql = self._connect()
        if pwic_option(sql, project, 'no_export_project') is not None:
            raise web.HTTPForbidden()
        with_revisions = pwic_option(sql, project, 'export_project_revisions') is not None

        # Fetch the pages
        sql.execute(''' SELECT b.page, b.revision, b.latest, b.author, b.date, b.time, b.title, b.markdown
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON b.project = a.project
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.admin    = 'X'
                          AND a.disabled = ''
                        ORDER BY b.page''',
                    (project, user))
        pages = []
        for row in sql.fetchall():
            if not with_revisions and not pwic_xb(row['latest']):
                continue
            pages.append(row)
        if len(pages) == 0:
            raise web.HTTPNotFound()

        # Fetch the attached documents
        sql.execute(''' SELECT id, filename, mime, exturl
                        FROM documents
                        WHERE project = ?''',
                    (project, ))
        documents = []
        for row in sql.fetchall():
            documents.append({'id': row['id'],
                              'filename': row['filename'],
                              'image': row['mime'][:6] == 'image/',
                              'exturl': row['exturl']})

        # Build the ZIP file
        folder_rev = 'revisions/'
        htmlStyles = pwic_styles_html()
        try:
            inmemory = BytesIO()
            zip = zipfile.ZipFile(inmemory, mode='w', compression=zipfile.ZIP_DEFLATED)

            # Pages of the project
            for page in pages:
                # Raw markdown
                if with_revisions:
                    zip.writestr('%s%s.rev%d.md' % (folder_rev, page['page'], page['revision']), page['markdown'])
                if pwic_xb(page['latest']):
                    zip.writestr('%s.md' % page['page'], page['markdown'])

                # HTML
                html = htmlStyles.html % (page['author'].replace('"', '&quote;'),
                                          page['date'],
                                          page['time'],
                                          page['page'].replace('<', '&lt;').replace('>', '&gt;'),
                                          page['title'].replace('<', '&lt;').replace('>', '&gt;'),
                                          htmlStyles.getCss(rel=True),
                                          '',
                                          self._md2html(sql, project, page['page'], page['revision'], page['markdown'])[0])
                for doc in documents:
                    if doc['exturl'] == '':
                        if doc['image']:
                            html = html.replace('<img src="/special/document/%d"' % doc['id'], '<img src="documents/%s"' % doc['filename'])
                        html = html.replace('<a href="/special/document/%d"' % doc['id'], '<a href="documents/%s"' % doc['filename'])
                        html = html.replace('<a href="/special/document/%d/' % doc['id'], '<a href="documents/%s' % doc['filename'])
                    else:
                        if doc['image']:
                            html = html.replace('<img src="/special/document/%d"' % doc['id'], '<img src="%s"' % doc['exturl'])
                        html = html.replace('<a href="/special/document/%d"' % doc['id'], '<a href="%s"' % doc['exturl'])
                        html = html.replace('<a href="/special/document/%d/' % doc['id'], '<a href="%s' % doc['exturl'])
                if with_revisions:
                    zip.writestr('%s%s.rev%d.html' % (folder_rev, page['page'], page['revision']), html)
                if pwic_xb(page['latest']):
                    zip.writestr('%s.html' % page['page'], html)

            # Dependent files for the pages
            content = b''
            with open(htmlStyles.css, 'rb') as f:
                content = f.read()
            zip.writestr(htmlStyles.css, content)
            if with_revisions:
                zip.writestr(folder_rev + htmlStyles.css, content)
            del content

            # Attached documents
            PwicExtension.on_project_export_documents(sql, project, user, documents)
            for doc in documents:
                if doc['exturl'] == '':
                    fn = join(PWIC_DOCUMENTS_PATH % project, doc['filename'])
                    if isfile(fn):
                        content = b''
                        with open(fn, 'rb') as f:
                            content = f.read()
                        zip.writestr('documents/%s' % doc['filename'], content)
                        del content

            # Close the archive
            zip.close()
        except Exception:
            raise web.HTTPInternalServerError()

        # Audit the action
        pwic_audit(sql, {'author': user,
                         'event': 'export-project',
                         'project': project,
                         'string': 'full' if with_revisions else 'latest'},
                   request)
        self._commit()

        # Return the file
        content = inmemory.getvalue()
        inmemory.close()
        return web.Response(body=content,
                            headers=MultiDict({'Content-Type': 'application/x-zip-compressed',
                                               'Content-Disposition': 'attachment; filename="%s"' % pwic_attachment_name(project + '.zip')}))

    async def api_page_create(self, request: web.Request) -> web.Response:
        ''' API to create a new page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        kb = pwic_xb(pwic_x(post.get('kb', '')))
        page = '' if kb else pwic_safe_name(post.get('page', ''))
        milestone = post.get('milestone', '').strip()
        tags = post.get('tags', '')
        ref_project = pwic_safe_name(post.get('ref_project', ''))
        ref_page = pwic_safe_name(post.get('ref_page', ''))
        ref_tags = pwic_xb(pwic_x(post.get('ref_tags', '')))
        if project in ['', 'api', 'special'] or (not kb and page in ['', 'special']):
            raise web.HTTPBadRequest()

        # Consume a KBid
        sql = self._connect()
        if not self._lock(sql):
            raise web.HTTPServiceUnavailable()
        if kb:
            kbid = pwic_int(pwic_option(sql, project, 'kbid', '0')) + 1
            sql.execute(''' INSERT OR REPLACE INTO env (project, key, value) VALUES (?, ?, ?)''',
                        (project, 'kbid', kbid))
            page = PWIC_DEFAULTS['kb_mask'] % kbid
            # No commit because the creation of the page can fail below
        else:
            if PWIC_REGEXES['kb_mask'].match(page) is not None:
                self._rollback()
                raise web.HTTPBadRequest()

        # Verify that the user is manager of the provided project, and that the page doesn't exist yet
        sql.execute(''' SELECT b.page
                        FROM roles AS a
                            LEFT OUTER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.page    = ?
                                AND b.latest  = 'X'
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.manager  = 'X'
                          AND a.disabled = '' ''',
                    (page, project, user))
        row = sql.fetchone()
        if row is None or row['page'] is not None:
            self._rollback()
            raise web.HTTPUnauthorized()

        # Fetch the default markdown if the page is created in reference to another one
        default_markdown = '# %s' % page
        default_tags = ''
        if (ref_project != '') and (ref_page != ''):
            sql.execute(''' SELECT b.markdown, b.tags
                            FROM roles AS a
                                INNER JOIN pages AS b
                                    ON  b.project = a.project
                                    AND b.page    = ?
                                    AND b.latest  = 'X'
                            WHERE a.project  = ?
                              AND a.user     = ?
                              AND a.disabled = '' ''',
                        (ref_page, ref_project, user))
            row = sql.fetchone()
            if row is None:
                self._rollback()
                raise web.HTTPBadRequest()
            default_markdown = row['markdown']
            if ref_tags:
                default_tags = row['tags']

        # Handle the creation of the page
        dt = pwic_dt()
        revision = 1
        sql.execute(''' INSERT INTO pages (project, page, revision, latest, author, date, time, title, markdown, tags, comment, milestone)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (project, page, revision, 'X', user, dt['date'], dt['time'], page, default_markdown,
                     self._sanitize_tags(tags + ' ' + default_tags), 'Initial', milestone))
        pwic_audit(sql, {'author': user,
                         'event': 'create-page',
                         'project': project,
                         'page': page,
                         'revision': revision},
                   request)
        self._commit()

        # Result
        data = {'project': project,
                'page': page,
                'url': '/%s/%s' % (project, page)}
        return web.Response(text=json.dumps(data), content_type=pwic_mime('json'))

    async def api_page_edit(self, request: web.Request) -> None:
        ''' API to update an existing page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        page = pwic_safe_name(post.get('page', ''))
        title = post.get('title', '').strip()
        markdown = post.get('markdown', '')
        tags = self._sanitize_tags(post.get('tags', ''))
        comment = post.get('comment', '').strip()
        milestone = post.get('milestone', '').strip()
        draft = pwic_xb(pwic_x(post.get('draft', '')))
        final = pwic_xb(pwic_x(post.get('final', '')))
        protection = pwic_x(post.get('protection', ''))
        header = pwic_x(post.get('header', ''))
        dt = pwic_dt()
        if '' in [user, project, page, title, comment]:
            raise web.HTTPBadRequest()
        if final:
            draft = False

        # Fetch the last revision of the page and the profile of the user
        sql = self._connect()
        if not self._lock(sql):
            raise web.HTTPServiceUnavailable()
        sql.execute(''' SELECT b.revision, b.header, b.protection, a.manager
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.page    = ?
                                AND b.latest  = 'X'
                        WHERE a.project   = ?
                          AND a.user      = ?
                          AND ( a.manager = 'X'
                             OR a.editor  = 'X' )
                          AND a.disabled  = '' ''',
                    (page, project, user))
        row = sql.fetchone()
        if row is None:
            self._rollback()
            raise web.HTTPUnauthorized()        # Or not found which is normally unlikely
        revision = row['revision']
        manager = pwic_xb(row['manager'])
        if not manager:
            if pwic_xb(row['protection']):      # The protected pages can be updated by the managers only
                self._rollback()
                raise web.HTTPUnauthorized()
            protection = ''                     # This field cannot be set by the non-managers
            header = row['header']              # This field is reserved to the managers, so we keep the existing value

        # Create the new entry
        sql.execute(''' INSERT INTO pages
                            (project, page, revision, draft, final, header,
                             protection, author, date, time, title,
                             markdown, tags, comment, milestone)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (project, page, revision + 1, pwic_x(draft), pwic_x(final), header,
                     protection, user, dt['date'], dt['time'], title,
                     markdown, tags, comment, milestone))
        if sql.rowcount > 0:
            pwic_audit(sql, {'author': user,
                             'event': 'update-page',
                             'project': project,
                             'page': page,
                             'revision': revision + 1},
                       request)

            # Remove the own drafts
            if final and (pwic_option(sql, project, 'keep_drafts') is None):
                sql.execute(''' SELECT revision
                                FROM pages
                                WHERE project   = ?
                                  AND page      = ?
                                  AND revision <= ?
                                  AND author    = ?
                                  AND draft     = 'X'
                                  AND final     = ''
                                  AND valuser   = '' ''',
                            (project, page, revision, user))
                for row in sql.fetchall():
                    sql.execute(''' DELETE FROM cache
                                    WHERE project  = ?
                                      AND page     = ?
                                      AND revision = ?''',
                                (project, page, row['revision']))
                    sql.execute(''' DELETE FROM pages
                                    WHERE project  = ?
                                      AND page     = ?
                                      AND revision = ?''',
                                (project, page, row['revision']))
                    pwic_audit(sql, {'author': user,
                                     'event': 'delete-draft',
                                     'project': project,
                                     'page': page,
                                     'revision': row['revision']},
                               request)

            # Purge the old flags
            sql.execute(''' UPDATE pages
                            SET header = '',
                                latest = ''
                            WHERE project   = ?
                              AND page      = ?
                              AND revision <= ?''',
                        (project, page, revision))
        self._commit()
        raise web.HTTPOk()

    async def api_page_validate(self, request: web.Request) -> None:
        ''' Validate the revision of a page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the revision to validate
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        page = pwic_safe_name(post.get('page', ''))
        revision = pwic_int(post.get('revision', 0))
        if '' in [project, page] or revision == 0:
            raise web.HTTPBadRequest()

        # Verify that it is possible to validate the page
        sql = self._connect()
        if not PwicExtension.on_api_page_validate(sql, project, user, page, revision):
            raise web.HTTPUnauthorized()
        if not self._lock(sql):
            raise web.HTTPServiceUnavailable()
        sql.execute(''' SELECT b.page
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project  = a.project
                                AND b.page     = ?
                                AND b.revision = ?
                                AND b.final    = 'X'
                                AND b.valuser  = ''
                            INNER JOIN users AS c
                                ON  c.user     = a.user
                                AND c.initial  = ''
                        WHERE a.project   = ?
                          AND a.user      = ?
                          AND a.validator = 'X'
                          AND a.disabled  = '' ''',
                    (page, revision, project, user))
        if sql.fetchone() is None:
            self._rollback()
            raise web.HTTPUnauthorized()

        # Update the page
        dt = pwic_dt()
        sql.execute(''' UPDATE pages
                        SET valuser = ?,
                            valdate = ?,
                            valtime = ?
                        WHERE project  = ?
                          AND page     = ?
                          AND revision = ?''',
                    (user, dt['date'], dt['time'], project, page, revision))
        pwic_audit(sql, {'author': user,
                         'event': 'validate-page',
                         'project': project,
                         'page': page,
                         'revision': revision},
                   request)
        self._commit()
        raise web.HTTPOk()

    async def api_page_delete(self, request: web.Request) -> None:
        ''' Delete a revision of a page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the revision to delete
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        page = pwic_safe_name(post.get('page', ''))
        revision = pwic_int(post.get('revision', 0))
        if ('' in [project, page]) or (revision == 0):
            raise web.HTTPBadRequest()

        # Verify that the deletion is possible
        sql = self._connect()
        if not self._lock(sql):
            raise web.HTTPServiceUnavailable()
        sql.execute(''' SELECT COUNT(revision) AS total
                        FROM pages
                        WHERE project = ?
                          AND page    = ?''',
                    (project, page))
        num_revs = sql.fetchone()['total']
        if (num_revs == 1) and (pwic_option(sql, '', 'maintenance') is not None):
            self._rollback()
            raise web.HTTPServiceUnavailable()      # During a maintenance, the last revision can't be deleted because the all the files would be deleted
        sql.execute(''' SELECT a.header
                        FROM pages AS a
                            INNER JOIN roles AS b
                                ON  b.project  = a.project
                                AND b.user     = ?
                                AND b.disabled = ''
                        WHERE a.project  = ?
                          AND a.page     = ?
                          AND a.revision = ?
                          AND ((    b.admin   = 'X'
                                AND a.final   = ''
                                AND a.valuser = ''
                            ) OR (  b.user    = a.author
                                AND a.draft   = 'X'
                            ))''',
                    (user, project, page, revision))
        row = sql.fetchone()
        if row is None:
            self._rollback()
            raise web.HTTPUnauthorized()
        if not PwicExtension.on_api_page_delete(sql, project, user, page, revision):
            self._rollback()
            raise web.HTTPUnauthorized()
        header = row['header']

        # Delete the revision
        sql.execute(''' DELETE FROM cache
                        WHERE project  = ?
                          AND page     = ?
                          AND revision = ?''',
                    (project, page, revision))
        sql.execute(''' DELETE FROM pages
                        WHERE project  = ?
                          AND page     = ?
                          AND revision = ?''',
                    (project, page, revision))
        num_revs -= 1
        pwic_audit(sql, {'author': user,
                         'event': 'delete-revision',
                         'project': project,
                         'page': page,
                         'revision': revision},
                   request)
        if revision > 1:
            # Find the latest revision that is not necessarily "revision - 1"
            sql.execute(''' SELECT MAX(revision) AS revision
                            FROM pages
                            WHERE project   = ?
                              AND page      = ?
                              AND revision <> ?''',
                        (project, page, revision))
            row = sql.fetchone()
            if row['revision'] is not None:
                if row['revision'] < revision:      # If we have already deleted the latest revision
                    sql.execute(''' UPDATE pages
                                    SET latest = 'X',
                                        header = ?
                                    WHERE project  = ?
                                      AND page     = ?
                                      AND revision = ?''',
                                (header, project, page, row['revision']))

        # Delete the attached documents when the page doesn't exist anymore
        docKO = 0
        if num_revs == 0:
            sql.execute(''' SELECT id, filename, exturl
                            FROM documents
                            WHERE project = ?
                              AND page    = ?''',
                        (project, page))
            for row in sql.fetchall():
                ko = False

                # Attempt to delete the file
                if not PwicExtension.on_api_document_delete(sql, project, user, page, row['id'], row['filename']):
                    ko = True
                else:
                    if row['exturl'] == '':
                        fn = join(PWIC_DOCUMENTS_PATH % project, row['filename'])
                        try:
                            os.remove(fn)
                        except (OSError, FileNotFoundError):
                            if isfile(fn):
                                ko = True

                # Handle the result of the deletion
                if ko:
                    docKO += 1
                else:
                    sql.execute(''' DELETE FROM documents
                                    WHERE id = ?''',
                                (row['id'], ))
                    pwic_audit(sql, {'author': user,
                                     'event': 'delete-document',
                                     'project': project,
                                     'page': page,
                                     'string': row['filename']},
                               request)

        # Final
        if docKO > 0:
            self._rollback()    # Possible partial deletion
            raise web.HTTPInternalServerError()
        else:
            self._commit()
            raise web.HTTPOk()

    async def api_page_export(self, request: web.Request) -> web.Response:
        ''' API to export a page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Read the parameters
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        page = pwic_safe_name(post.get('page', ''))
        revision = pwic_int(post.get('revision', 0))
        format = post.get('format', '').lower()
        if '' in [project, page, format]:
            raise web.HTTPBadRequest()

        # Apply the options on the parameters
        sql = self._connect()
        revision = self._redirect_revision(sql, project, user, page, revision)
        if revision == 0:
            raise web.HTTPForbidden()
        file_formats_disabled = str(pwic_option(sql, project, 'file_formats_disabled', '')).split(' ')
        if (format in file_formats_disabled) or ('*' in file_formats_disabled):
            raise web.HTTPForbidden()

        # Read the selected revision
        sql.execute(''' SELECT latest, author, date, time, title, markdown, tags
                        FROM pages
                        WHERE project  = ?
                          AND page     = ?
                          AND revision = ?''',
                    (project, page, revision))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPNotFound()

        # Initialization
        dt = pwic_dt()
        baseUrl = str(pwic_option(sql, '', 'base_url', ''))
        pageUrl = '%s/%s/%s/rev%d' % (baseUrl, project, page, revision)
        endname = pwic_attachment_name('%s_%s_rev%d.%s' % (project, page, revision, format))

        # Fetch the legal notice
        legal_notice = str(pwic_option(sql, project, 'legal_notice', '')).strip()
        legal_notice = re.sub(r'\<[^\>]+\>', '', legal_notice)
        legal_notice = legal_notice.replace('\r', '')

        # Handle the own file formats
        done, newbody, newheaders = PwicExtension.on_api_page_export(sql, project, user, page, revision, format, endname)
        if done:
            if newbody is None:
                raise web.HTTPNotFound()
            else:
                return web.Response(body=newbody, headers=MultiDict(newheaders))

        # Format MD
        if format == 'md':
            return web.Response(body=row['markdown'],
                                headers=MultiDict({'Content-Type': 'text/markdown',
                                                   'Content-Disposition': 'attachment; filename="%s"' % endname}))

        # Format HTML
        elif format == 'html':
            htmlStyles = pwic_styles_html()
            html = htmlStyles.html % (row['author'].replace('"', '&quote;'),
                                      row['date'],
                                      row['time'],
                                      page.replace('<', '&lt;').replace('>', '&gt;'),
                                      row['title'].replace('<', '&lt;').replace('>', '&gt;'),
                                      htmlStyles.getCss(rel=False),
                                      '' if legal_notice == '' else ('<!--\n%s\n-->' % legal_notice),
                                      self._md2html(sql, project, page, revision, row['markdown'])[0])
            html = html.replace('<a href="/special/document/', '<a href="%s/special/document/' % baseUrl)
            html = html.replace('<img src="/special/document/', '<img src="%s/special/document/' % baseUrl)
            return web.Response(body=html, headers=MultiDict({'Content-Type': htmlStyles.mime,
                                                              'Content-Disposition': 'attachment; filename="%s"' % endname}))

        # Format ODT
        elif format == 'odt':
            # MarkDown --> HTML --> ODT
            html = self._md2html(sql, project, page, revision, row['markdown'],
                                 cache=False,    # No cache to recalculate the headers through the styles
                                 headerNumbering=False)[0]
            html = html.replace('<div class="codehilite"><pre><span></span><code>', '<blockcode>')
            html = html.replace('</code></pre></div>', '</blockcode>')
            html = html.replace('<pre><code>', '<blockcode>')
            html = html.replace('</code></pre>', '</blockcode>')

            # Extract the meta-informations of the embedded pictures
            docids = ['0']
            subdocs = PWIC_REGEXES['document'].findall(row['markdown'])
            if subdocs is not None:
                for sd in subdocs:
                    sd = str(pwic_int(sd[0]))
                    if sd not in docids:
                        docids.append(sd)
            query = ''' SELECT a.id, a.project, a.page, a.filename, a.mime, a.exturl
                        FROM documents AS a
                            INNER JOIN roles AS b
                                ON  b.project  = a.project
                                AND b.user     = ?
                                AND b.disabled = ''
                        WHERE a.id   IN (%s)
                          AND a.mime LIKE 'image/%%' '''
            sql.execute(query % ','.join(docids), (user, ))
            pictMeta = {}
            for rowdoc in sql.fetchall():
                fn = join(PWIC_DOCUMENTS_PATH % project, rowdoc['filename'])
                w, h = 50., 50.                             # Default area
                if rowdoc['exturl'] == '':                  # Can't guess the remote size
                    if isfile(fn):
                        try:
                            # Optimize the maximal size
                            w, h = imagesize.get(fn)
                            MAX_W = 600.    # px
                            MAX_H = 900.    # px
                            if w > MAX_W:
                                h *= MAX_W / w
                                w = MAX_W
                            if h > MAX_H:
                                w *= MAX_H / h
                                h = MAX_H
                        except ValueError:
                            pass
                pictMeta[rowdoc['id']] = {'filename': fn,
                                          'link': 'special/document/%d' % rowdoc['id'] if rowdoc['exturl'] == '' else rowdoc['exturl'],
                                          'link_odt_img': 'special/document_%d' % rowdoc['id'] if rowdoc['exturl'] == '' else rowdoc['exturl'],     # LibreOffice does not support the paths with multiple folders
                                          'uncompressed': rowdoc['mime'] in [pwic_mime('bmp'), pwic_mime('svg')],
                                          'manifest': '<manifest:file-entry manifest:full-path="special/document_%d" manifest:media-type="%s" />' % (rowdoc['id'], rowdoc['mime']) if rowdoc['exturl'] == '' else '',
                                          'width': pwic_int(w),
                                          'height': pwic_int(h),
                                          'remote': rowdoc['exturl'] != ''}

            # Convert to ODT
            odtStyles = pwic_styles_odt()
            try:
                odtGenerator = pwic_html2odt(baseUrl, project, page, pictMeta=pictMeta)
                odtGenerator.feed(html)
            except Exception:
                raise web.HTTPInternalServerError()

            # Prepare the ODT file in the memory
            inmemory = BytesIO()
            odt = zipfile.ZipFile(inmemory, mode='w', compression=zipfile.ZIP_DEFLATED)
            odt.writestr('mimetype', odtStyles.mime, compress_type=zipfile.ZIP_STORED, compresslevel=0)  # Must be the first file of the ZIP and not compressed

            # Manifest
            attachments = ''
            for meta in pictMeta:
                meta = pictMeta[meta]
                if not meta['remote']:
                    content = b''
                    with open(meta['filename'], 'rb') as f:
                        content = f.read()
                    if meta['uncompressed']:
                        odt.writestr(meta['link_odt_img'], content)
                    else:
                        odt.writestr(meta['link_odt_img'], content, compress_type=zipfile.ZIP_STORED, compresslevel=0)
                    del content
                    attachments += '%s\n' % meta['manifest']
            odt.writestr('META-INF/manifest.xml', odtStyles.manifest.replace('<!-- attachments -->', attachments))

            # Content-related ODT data
            odt.writestr('meta.xml', odtStyles.meta % (PWIC_VERSION,
                                                       escape(row['title']),
                                                       escape(project), escape(page),
                                                       ('<meta:keyword>%s</meta:keyword>' % escape(row['tags'])) if row['tags'] != '' else '',
                                                       escape(row['author']),
                                                       escape(row['date']), escape(row['time']),
                                                       escape(user),
                                                       escape(dt['date']), escape(dt['time']),
                                                       revision))
            xml = odtStyles.styles
            xml = xml.replace('<!-- styles-code -->', odtStyles.getOptimizedCodeStyles(html) if odtGenerator.has_code else '')
            xml = xml.replace('<!-- styles-heading-format -->', odtStyles.getHeadingStyles(pwic_option(sql, project, 'heading_mask')))
            if legal_notice != '':
                legal_notice = ''.join(['<text:p text:style-name="Footer">%s</text:p>' % line for line in legal_notice.split('\n')])
            xml = xml.replace('<!-- styles-footer -->', legal_notice)
            xml = xml.replace('fo:page-width=""', 'fo:page-width="%s"' % str(pwic_option(sql, project, 'odt_page_width', '21cm')).strip().replace(' ', '').replace(',', '.').replace('"', '\\"'))
            xml = xml.replace('fo:page-height=""', 'fo:page-height="%s"' % str(pwic_option(sql, project, 'odt_page_height', '29.7cm')).strip().replace(' ', '').replace(',', '.').replace('"', '\\"'))
            odt.writestr('styles.xml', xml)
            xml = odtStyles.content
            xml = xml.replace('<!-- content-url -->', '<text:p text:style-name="Reference"><text:a xlink:href="%s" xlink:type="simple"><text:span text:style-name="Link">%s</text:span></text:a></text:p>' % (pageUrl, pageUrl))  # Trick to connect the master layout to the page
            xml = xml.replace('<!-- content-page -->', odtGenerator.odt)
            odt.writestr('content.xml', xml)
            odt.close()

            # Return the file
            buffer = inmemory.getvalue()
            inmemory.close()
            return web.Response(body=buffer, headers=MultiDict({'Content-Type': odtStyles.mime,
                                                                'Content-Disposition': 'attachment; filename="%s"' % endname}))

        # Other format
        else:
            raise web.HTTPUnsupportedMediaType()

    async def api_markdown(self, request: web.Request) -> web.Response:
        ''' Return the HTML corresponding to the posted Markdown '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the parameters
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        content = post.get('content', '')
        if project == '':
            raise web.HTTPBadRequest()

        # Verify that the user is able to write
        sql = self._connect()
        sql.execute(''' SELECT user
                        FROM roles
                        WHERE   project  = ?
                          AND   user     = ?
                          AND ( manager  = 'X'
                            OR  editor   = 'X' )
                          AND   disabled = '' ''',
                    (project, user))
        if sql.fetchone() is None:
            raise web.HTTPUnauthorized()

        # Return the converted output
        html = self._md2html(sql, project, None, 0, content, cache=False)[0]
        html = PwicExtension.on_html(sql, project, None, 0, html)
        return web.Response(text=html, content_type=pwic_mime('txt'))

    async def api_user_create(self, request: web.Request) -> Optional[web.Response]:
        ''' API to create a new user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        wisheduser = post.get('user', '').strip().lower()
        newuser = pwic_safe_user_name(post.get('user', ''))
        if (wisheduser != newuser) or ('' in [project, newuser]) or (newuser[:4] == 'pwic'):
            raise web.HTTPBadRequest()

        # Verify that the user is administrator and has changed his password
        sql = self._connect()
        if not self._lock(sql):
            raise web.HTTPServiceUnavailable()
        sql.execute(''' SELECT 1
                        FROM roles AS a
                            INNER JOIN users AS b
                                ON b.user = a.user
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.admin    = 'X'
                          AND a.disabled = ''
                          AND b.initial  = '' ''',
                    (project, user))
        if (sql.fetchone() is None) or not PwicExtension.on_api_user_create(sql, project, user, newuser):
            self._rollback()
            raise web.HTTPUnauthorized()

        # Create the new user
        if pwic_option(sql, project, 'no_new_user_online') is not None:
            sql.execute(''' SELECT user
                            FROM users
                            WHERE user = ?''',
                        (newuser, ))
            if sql.fetchone() is None:
                self._rollback()
                raise web.HTTPForbidden()
        else:
            sql.execute(''' INSERT INTO users (user, password)
                            SELECT ?, ?
                            WHERE NOT EXISTS ( SELECT 1 FROM users WHERE user = ? )''',
                        (newuser, pwic_sha256(PWIC_DEFAULTS['password']), newuser))
            if sql.rowcount > 0:
                pwic_audit(sql, {'author': user,
                                 'event': 'create-user',
                                 'user': newuser},
                           request)

        # Grant the default rights as reader
        sql.execute(''' INSERT INTO roles (project, user, reader)
                        SELECT ?, ?, 'X'
                        WHERE NOT EXISTS ( SELECT 1 FROM roles WHERE project = ? AND user = ? )''',
                    (project, newuser, project, newuser))
        if sql.rowcount > 0:
            pwic_audit(sql, {'author': user,
                             'event': 'grant-reader',
                             'project': project,
                             'user': newuser},
                       request)
        self._commit()
        raise web.HTTPOk()

    async def api_user_password_change(self, request: web.Request) -> None:
        ''' Change the password of the current user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user[:4] in ['', 'pwic']:
            raise web.HTTPUnauthorized()

        # Get the posted values
        post = await self._handle_post(request)
        current = post.get('password_current', '')
        new1 = post.get('password_new1', '')
        new2 = post.get('password_new2', '')
        if ('' in [current, new1, new2]) or (new1 != new2) or (new1 in [current, PWIC_DEFAULTS['password']]):
            raise web.HTTPBadRequest()

        # Verify the format of the new password
        sql = self._connect()
        mask = str(pwic_option(sql, '', 'password_regex', ''))
        if mask != '':
            try:
                if re.compile(mask).match(new1) is None:
                    raise web.HTTPBadRequest()
            except Exception:
                raise web.HTTPInternalServerError()
        if not PwicExtension.on_api_user_password_change(sql, user, new1):
            raise web.HTTPUnauthorized()

        # Verify the current password
        ok = False
        if not self._lock(sql):
            raise web.HTTPServiceUnavailable()
        sql.execute(''' SELECT user FROM users
                        WHERE user     = ?
                          AND password = ?''',
                    (user, pwic_sha256(current)))
        if sql.fetchone() is not None:
            # Update the password
            sql.execute(''' UPDATE users
                            SET initial  = '',
                                password = ?
                            WHERE user   = ?''',
                        (pwic_sha256(new1), user))
            if sql.rowcount > 0:
                pwic_audit(sql, {'author': user,
                                 'event': 'change-password',
                                 'user': user},
                           request)
                ok = True
        self._commit()
        raise web.HTTPOk() if ok else web.HTTPBadRequest()

    async def api_user_roles_set(self, request: web.Request) -> web.Response:
        ''' Change the roles of a user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the posted values
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        userpost = pwic_safe_user_name(post.get('name', ''))
        roles = ['admin', 'manager', 'editor', 'validator', 'reader', 'disabled', 'delete']
        try:
            roleid = roles.index(post.get('role', ''))
            delete = (roles[roleid] == 'delete')
        except ValueError:
            raise web.HTTPBadRequest()
        if '' in [project, userpost] or (userpost[:4] == 'pwic' and roles in ['admin', 'delete']):
            raise web.HTTPBadRequest()

        # Select the current rights of the user
        sql = self._connect()
        if not self._lock(sql):
            raise web.HTTPServiceUnavailable()
        sql.execute(''' SELECT a.user, a.admin, a.manager, a.editor,
                               a.validator, a.reader, a.disabled, c.initial
                        FROM roles AS a
                            INNER JOIN roles AS b
                                ON  b.project  = a.project
                                AND b.user     = ?
                                AND b.admin    = 'X'
                                AND b.disabled = ''
                            INNER JOIN users AS c           -- The modified user
                                ON  c.user     = a.user
                            INNER JOIN users AS d           -- The administrator must have changed its password already
                                ON  d.user     = b.user
                                AND d.initial  = ''
                        WHERE a.project = ?
                          AND a.user    = ?''',
                    (user, project, userpost))
        row = sql.fetchone()
        if row is None or (not delete and pwic_xb(row['initial'])):
            self._rollback()
            raise web.HTTPUnauthorized()

        # Delete a user
        if delete:
            if not PwicExtension.on_api_user_roles_set(sql, project, user, userpost, 'delete', None):
                self._rollback()
                raise web.HTTPUnauthorized()
            sql.execute(''' DELETE FROM roles
                            WHERE project = ?
                              AND user    = ?
                              AND user   <> ?''',
                        (project, userpost, user))
            if sql.rowcount > 0:
                pwic_audit(sql, {'author': user,
                                 'event': 'delete-user',
                                 'project': project,
                                 'user': userpost},
                           request)
                self._commit()
                return web.Response(text='OK', content_type=pwic_mime('txt'))
            else:
                self._rollback()
                raise web.HTTPBadRequest()

        # New role
        else:
            newvalue = {'X': '', '': 'X'}[row[roles[roleid]]]
            if (roles[roleid] == 'admin') and (newvalue != 'X') and (user == userpost):
                self._rollback()
                raise web.HTTPUnauthorized()      # Cannot self-ungrant admin, so there is always at least one admin on the project
            if not PwicExtension.on_api_user_roles_set(sql, project, user, userpost, roles[roleid], newvalue):
                self._rollback()
                raise web.HTTPUnauthorized()
            try:
                sql.execute(''' UPDATE roles
                                SET %s = ?
                                WHERE project = ?
                                  AND user    = ?''' % roles[roleid],
                            (newvalue, project, userpost))
            except sqlite3.IntegrityError:
                self._rollback()
                raise web.HTTPUnauthorized()
            if sql.rowcount == 0:
                self._rollback()
                raise web.HTTPBadRequest()
            else:
                pwic_audit(sql, {'author': user,
                                 'event': '%s-%s' % ('grant' if pwic_xb(newvalue) else 'ungrant', roles[roleid]),
                                 'project': project,
                                 'user': userpost},
                           request)
                self._commit()
                return web.Response(text=newvalue, content_type=pwic_mime('txt'))

    async def api_document_create(self, request: web.Request) -> None:
        ''' API to create a new document '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Verify that there is no maintenance message that may prevent the file from being saved
        sql = self._connect()
        if pwic_option(sql, '', 'maintenance') is not None:
            raise web.HTTPServiceUnavailable()

        # Parse the submitted multipart/form-data
        try:
            regex_name = re.compile(r'[^file]name="([^"]+)"')
            regex_filename = re.compile(r'filename="([^"]+)"')
            doc: Dict[str, Any] = {'project': '',
                                   'page': '',
                                   'filename': '',
                                   'mime': '',
                                   'content': None}
            multipart = MultipartReader.from_response(request)
            while True:
                part = await multipart.next()
                if part is None:
                    break

                # Read the type of entry
                disposition = part.headers.get(hdrs.CONTENT_DISPOSITION, '')
                if disposition[:10] != 'form-data;':
                    continue

                # Read the name of the field
                name_re = regex_name.search(disposition)
                if name_re is None:
                    continue
                name = name_re.group(1)

                # Assign the value
                if name in ['project', 'page']:
                    doc[name] = pwic_safe_name(await part.text())
                elif name == 'content':
                    fn_re = regex_filename.search(disposition)
                    if fn_re is None:
                        continue
                    fn = pwic_safe_file_name(fn_re.group(1))
                    if fn == '':
                        continue
                    doc['filename'] = fn
                    doc['mime'] = part.headers.get(hdrs.CONTENT_TYPE, '')
                    doc[name] = await part.read(decode=False)
        except Exception:
            raise web.HTTPBadRequest()
        if not PwicExtension.on_api_document_create_start(sql, doc):
            raise web.HTTPUnauthorized()
        doc['project'] = pwic_safe_name(doc['project'])
        doc['page'] = pwic_safe_name(doc['page'])
        doc['filename'] = pwic_safe_file_name(doc['filename'])
        if doc['content'] in [None, '', b''] or '' in [doc['project'], doc['page'], doc['filename']]:   # The mime is checked later
            raise web.HTTPBadRequest()

        # Verify that the project and folder exist
        if not self._lock(sql):
            raise web.HTTPServiceUnavailable()
        sql.execute(''' SELECT project
                        FROM projects
                        WHERE project = ?''', (doc['project'], ))
        if sql.fetchone() is None:
            self._rollback()
            raise web.HTTPBadRequest()
        if not isdir(PWIC_DOCUMENTS_PATH % doc['project']):
            self._rollback()
            raise web.HTTPInternalServerError()

        # Verify the authorizations
        sql.execute(''' SELECT b.revision
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.page    = ?
                                AND b.latest  = 'X'
                        WHERE   a.project  = ?
                          AND   a.user     = ?
                          AND ( a.manager  = 'X'
                             OR a.editor   = 'X' )
                          AND   a.disabled = '' ''',
                    (doc['page'], doc['project'], user))
        row = sql.fetchone()
        if row is None:
            self._rollback()
            raise web.HTTPUnauthorized()
        current_revision = row['revision']

        # Verify the consistency of the filename
        row = pwic_option(sql, doc['project'], 'document_name_regex')
        if row is not None:
            try:
                regex_doc = re.compile(row, re.VERBOSE)
            except Exception:
                self._rollback()
                raise web.HTTPInternalServerError()
            if regex_doc.search(doc['filename']) is None:
                self._rollback()
                raise web.HTTPBadRequest()

        # Verify the file type
        if pwic_option(sql, '', 'magic_bytes') is not None:
            if not self._check_mime(doc):
                self._rollback()
                raise web.HTTPUnsupportedMediaType()
        if PWIC_REGEXES['mime'].match(doc['mime']) is None:
            self._rollback()
            raise web.HTTPBadRequest()

        # Verify the maximal document size
        maxsize = pwic_int(pwic_option(sql, doc['project'], 'max_document_size'))
        if maxsize != 0 and len(doc['content']) > maxsize:
            self._rollback()
            raise web.HTTPRequestEntityTooLarge(maxsize, len(doc['content']))

        # Verify the maximal project size
        # ... is there a check ?
        max_project_size_opt = pwic_option(sql, doc['project'], 'max_project_size')
        if max_project_size_opt is not None:
            max_project_size = pwic_int(max_project_size_opt)
            # ... current size of the project
            current_project_size = pwic_int(sql.execute(''' SELECT SUM(size) AS total
                                                            FROM documents
                                                            WHERE project = ?''',
                                                        (doc['project'], )).fetchone()['total'])
            # ... current size of the file if it exists already
            current_file_size = pwic_int(sql.execute(''' SELECT SUM(size) AS total
                                                         FROM documents
                                                         WHERE project  = ?
                                                           AND filename = ?''',
                                                     (doc['project'], doc['filename'])).fetchone()['total'])
            # ... verify the size
            if current_project_size - current_file_size + len(doc['content']) > max_project_size:
                self._rollback()
                raise web.HTTPRequestEntityTooLarge(max_project_size - current_project_size + current_file_size, len(doc['content']))  # HTTPInsufficientStorage has no hint

        # At last, verify that the document doesn't exist yet (not related to a given page)
        forcedId = None
        sql.execute(''' SELECT id, page, exturl
                        FROM documents
                        WHERE project  = ?
                          AND filename = ?''',
                    (doc['project'], doc['filename']))
        row = sql.fetchone()
        if row is None:
            pass                                # New document = Create it
        else:
            if row['page'] == doc['page']:      # Existing document = Delete + Keep same ID (replace it)
                if row['exturl'] == '':
                    # Local file
                    try:
                        fn = join(PWIC_DOCUMENTS_PATH % doc['project'], doc['filename'])
                        os.remove(fn)
                    except (OSError, FileNotFoundError):
                        if isfile(fn):
                            self._rollback()
                            raise web.HTTPInternalServerError()
                else:
                    # External file
                    if not PwicExtension.on_api_document_delete(sql, doc['project'], user, doc['page'], row['id'], doc['filename']):
                        self._rollback()
                        raise web.HTTPInternalServerError()
                sql.execute(''' DELETE FROM documents
                                WHERE id = ?''',
                            (row['id'], ))
                forcedId = row['id']
            else:
                self._rollback()
                raise web.HTTPBadRequest()      # Existing document on another page = do nothing

        # Upload the file on the server
        try:
            f = open(join(PWIC_DOCUMENTS_PATH % doc['project'], doc['filename']), 'wb')     # Rewrite any existing file
            f.write(doc['content'])
            f.close()
        except Exception:
            self._rollback()
            raise web.HTTPInternalServerError()

        # Create the document in the database
        dt = pwic_dt()
        sql.execute(''' INSERT INTO documents (id, project, page, filename, mime,
                                               size, hash, author, date, time, exturl)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')''',
                    (forcedId, doc['project'], doc['page'], doc['filename'],
                     doc['mime'], len(doc['content']), pwic_sha256(doc['content'], salt=False),
                     user, dt['date'], dt['time']))
        pwic_audit(sql, {'author': user,
                         'event': '%s-document' % ('create' if forcedId is None else 'replace'),
                         'project': doc['project'],
                         'page': doc['page'],
                         'revision': current_revision,
                         'string': doc['filename']},
                   request)
        self._commit()

        # Forward the notification of the created file
        sql.execute(''' SELECT *
                        FROM documents
                        WHERE id = ?''',
                    (forcedId, ))
        row = sql.fetchone()
        if row is not None:
            row['path'] = join(PWIC_DOCUMENTS_PATH % row['project'], row['filename'])
            PwicExtension.on_api_document_create_end(sql, row)
        raise web.HTTPOk()

    async def api_document_list(self, request: web.Request) -> web.Response:
        ''' Return the list of the attached documents '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Read the parameters
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        page = pwic_safe_name(post.get('page', ''))
        if '' in [project, page]:
            raise web.HTTPBadRequest()

        # Read the documents
        sql = self._connect()
        sql.execute(''' SELECT markdown
                        FROM pages
                        WHERE project = ?
                          AND page    = ?
                          AND latest  = 'X' ''',
                    (project, page))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPNotFound()
        markdown = row['markdown']
        sql.execute(''' SELECT b.id, b.filename, b.mime, b.size, b.hash, b.author, b.date, b.time, b.exturl
                        FROM roles AS a
                            INNER JOIN documents AS b
                                ON  b.project = a.project
                                AND b.page    = ?
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.disabled = ''
                        ORDER BY b.filename''',
                    (page, project, user))
        documents = []
        for row in sql.fetchall():
            row['mime_icon'] = pwic_mime2icon(row['mime'])
            row['size'] = pwic_size2str(row['size'])
            row['used'] = ('(/special/document/%d)' % row['id']) in markdown or \
                          ('(/special/document/%d "' % row['id']) in markdown
            documents.append(row)
        PwicExtension.on_api_document_list(sql, project, page, documents)
        return web.Response(text=json.dumps(documents), content_type=pwic_mime('json'))

    async def api_document_delete(self, request: web.Request) -> None:
        ''' Delete a document '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the file to delete
        post = await self._handle_post(request)
        project = pwic_safe_name(post.get('project', ''))
        page = pwic_safe_name(post.get('page', ''))
        id = pwic_int(post.get('id', 0))
        filename = pwic_safe_file_name(post.get('filename', ''))
        if ('' in [project, page, filename]) or (id == 0):
            raise web.HTTPBadRequest()

        # Verify that the deletion is possible
        sql = self._connect()
        if pwic_option(sql, '', 'maintenance') is not None:
            raise web.HTTPServiceUnavailable()
        if not self._lock(sql):
            raise web.HTTPServiceUnavailable()
        sql.execute(''' SELECT b.id, b.exturl
                        FROM roles AS a
                            INNER JOIN documents AS b
                                ON  b.id       = ?
                                AND b.project  = a.project
                                AND b.page     = ?
                                AND b.filename = ?
                        WHERE   a.project  = ?
                          AND   a.user     = ?
                          AND ( a.manager  = 'X'
                             OR a.editor   = 'X' )
                          AND   a.disabled = '' ''',
                    (id, page, filename, project, user))
        row = sql.fetchone()
        if row is None:
            self._rollback()
            raise web.HTTPUnauthorized()  # Or not found
        if not PwicExtension.on_api_document_delete(sql, project, user, page, id, filename):
            self._rollback()
            raise web.HTTPUnauthorized() if row['exturl'] == '' else web.HTTPInternalServerError()

        # Delete the local file
        if row['exturl'] == '':
            fn = join(PWIC_DOCUMENTS_PATH % project, filename)
            try:
                os.remove(fn)
            except (OSError, FileNotFoundError):
                if isfile(fn):
                    self._rollback()
                    raise web.HTTPInternalServerError()

        # Delete the index
        sql.execute(''' DELETE FROM documents WHERE id = ?''', (id, ))
        pwic_audit(sql, {'author': user,
                         'event': 'delete-document',
                         'project': project,
                         'page': page,
                         'string': filename},
                   request)
        self._commit()
        raise web.HTTPOk()

    async def api_swagger(self, request: web.Request) -> web.Response:
        ''' Display the features of the API '''
        return await self._handle_output(request, 'page-swagger', {'title': 'API specification'})


# ====================
#  Server entry point
# ====================

app = web.Application()


def main() -> bool:
    # Command-line
    parser = argparse.ArgumentParser(description='Pwic Server version %s' % PWIC_VERSION)
    parser.add_argument('--host', default='127.0.0.1', help='Listening host')
    parser.add_argument('--port', type=int, default=8080, help='Listening port')
    parser.add_argument('--sql-trace', action='store_true', help='Display the SQL queries in the console for debugging purposes')
    args = parser.parse_args()

    # Modules
    # ... launch time
    app['up'] = pwic_dt()
    # ... languages
    app['langs'] = sorted([f for f in listdir(PWIC_TEMPLATES_PATH) if isdir(join(PWIC_TEMPLATES_PATH, f))])
    if PWIC_DEFAULTS['language'] not in app['langs']:
        print('Error: English template is missing')
        return False
    # ... templates
    app['jinja'] = Environment(loader=FileSystemLoader(PWIC_TEMPLATES_PATH), trim_blocks=True, lstrip_blocks=True)
    # ... SQLite
    app['sql'] = sqlite3.connect(PWIC_DB_SQLITE)
    app['sql'].row_factory = pwic_row_factory
    if args.sql_trace:
        app['sql'].set_trace_callback(pwic_sql_print)
    sql = app['sql'].cursor()
    sql.execute('PRAGMA optimize')
    # ... PWIC
    app['pwic'] = PwicServer()
    setup(app, EncryptedCookieStorage(urandom(32)))  # Storage for cookies
    # ... Markdown parser
    app['markdown'] = Markdown(extras=['tables', 'footnotes', 'fenced-code-blocks', 'strike', 'underline'],
                               safe_mode=pwic_option(sql, '', 'safe_mode') is not None)

    # Routes
    app.router.add_static('/static/', path='./static/', append_version=False)
    app.add_routes([web.post('/api/logon', app['pwic'].api_logon),
                    web.get('/api/logon', app['pwic']._handle_logon),
                    web.get('/api/logout', app['pwic'].api_logout),
                    web.get('/api/oauth', app['pwic'].api_oauth),
                    web.post('/api/server/env/get', app['pwic'].api_server_env_get),
                    web.post('/api/server/ping', app['pwic'].api_server_ping),
                    web.post('/api/project/info/get', app['pwic'].api_project_info_get),
                    web.post('/api/project/env/set', app['pwic'].api_project_env_set),
                    web.post('/api/project/progress/get', app['pwic'].api_project_progress_get),
                    web.post('/api/project/graph/get', app['pwic'].api_project_graph_get),
                    web.get('/api/project/export', app['pwic'].api_project_export),
                    web.post('/api/page/create', app['pwic'].api_page_create),
                    web.post('/api/page/edit', app['pwic'].api_page_edit),
                    web.post('/api/page/validate', app['pwic'].api_page_validate),
                    web.post('/api/page/delete', app['pwic'].api_page_delete),
                    web.post('/api/page/export', app['pwic'].api_page_export),
                    web.post('/api/markdown/convert', app['pwic'].api_markdown),
                    web.post('/api/user/create', app['pwic'].api_user_create),
                    web.post('/api/user/password/change', app['pwic'].api_user_password_change),
                    web.post('/api/user/roles/set', app['pwic'].api_user_roles_set),
                    web.post('/api/document/create', app['pwic'].api_document_create),
                    web.post('/api/document/list', app['pwic'].api_document_list),
                    web.post('/api/document/delete', app['pwic'].api_document_delete),
                    web.get('/api', app['pwic'].api_swagger),
                    web.get('/special/logon', app['pwic']._handle_logon),
                    web.get('/special/help', app['pwic'].page_help),
                    web.get('/special/create-project', app['pwic'].page_help),
                    web.get('/special/create-page', app['pwic'].page_create),
                    web.get('/special/create-user', app['pwic'].user_create),
                    web.get('/special/user/{userpage}', app['pwic'].page_user),
                    web.get(r'/{project:[^\/]+}/special/search', app['pwic'].page_search),
                    web.get(r'/{project:[^\/]+}/special/audit', app['pwic'].page_audit),
                    web.get(r'/{project:[^\/]+}/special/env', app['pwic'].page_env),
                    web.get(r'/{project:[^\/]+}/special/roles', app['pwic'].page_roles),
                    web.get(r'/{project:[^\/]+}/special/links', app['pwic'].page_links),
                    web.get(r'/{project:[^\/]+}/special/graph', app['pwic'].page_graph),
                    web.get(r'/{project:[^\/]+}/special/random', app['pwic'].page_random),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}/rev{new_revision:[0-9]+}/compare/rev{old_revision:[0-9]+}', app['pwic'].page_compare),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}/rev{revision:[0-9]+}', app['pwic'].page),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}/{action:view|edit|history}', app['pwic'].page),
                    web.get(r'/special/document/{id:[0-9]+}/{dummy:[^\/]+}', app['pwic'].document_get),
                    web.get(r'/special/document/{id:[0-9]+}', app['pwic'].document_get),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}', app['pwic'].page),
                    web.get(r'/{project:[^\/]+}', app['pwic'].page),
                    web.get('/', app['pwic'].page)])

    # SSL
    if pwic_option(sql, '', 'ssl') is None:
        https = None
    else:
        try:
            import ssl
            https = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            https.load_cert_chain(PWIC_PUBLIC_KEY, PWIC_PRIVATE_KEY)
        except FileNotFoundError:
            print('Error: SSL certificates not found')
            return False
        except Exception as e:
            print('Error: %s' % str(e))
            return False

    # CORS
    if pwic_option(sql, '', 'cors') is None:
        app['cors'] = None
    else:
        import aiohttp_cors
        app['cors'] = aiohttp_cors.setup(app, defaults={'*': aiohttp_cors.ResourceOptions(allow_headers='*')})  # expose_headers='*'
        for route in list(app.router.routes()):
            app['cors'].add(route)

    # General options of the server
    app['no_logon'] = pwic_option(sql, '', 'no_logon') is not None
    app['oauth'] = {'provider': pwic_option(sql, '', 'oauth_provider', None),
                    'tenant': pwic_option(sql, '', 'oauth_tenant', ''),
                    'identifier': pwic_option(sql, '', 'oauth_identifier', ''),
                    'server_secret': pwic_option(sql, '', 'oauth_secret', ''),
                    'domains': pwic_list(pwic_option(sql, '', 'oauth_domains'))}

    # Compile the IP filters
    def _compile_ip():
        nonlocal sql
        app['ip_filter'] = []
        for mask in pwic_option(sql, '', 'ip_filter', '').split(' '):
            mask = mask.strip()
            if mask != '':
                item = [IPR_EQ, None, None]  # Type, Negated, Mask object

                # Negation flag
                item[1] = (mask[:1] == '-')
                if item[1]:
                    mask = mask[1:]

                # Condition types
                # ... networks
                if '/' in mask:
                    item[0] = IPR_NET
                    item[2] = ip_network(mask)
                # ... mask for IP
                elif '*' in mask or '?' in mask:
                    item[0] = IPR_REG
                    item[2] = re.compile(mask.replace('.', '\\.').replace('?', '.').replace('*', '.*'))
                # ... raw IP
                else:
                    item[2] = mask
                app['ip_filter'].append(item)

    _compile_ip()

    # Logging
    logfile = pwic_option(sql, '', 'http_log_file', '')
    logformat = str(pwic_option(sql, '', 'http_log_format', PWIC_DEFAULTS['logging_format']))
    if logfile != '':
        import logging
        logging.basicConfig(filename=logfile, datefmt='%d/%m/%Y %H:%M:%S', level=logging.INFO)

    # Launch the server
    if not PwicExtension.on_server_ready(app, sql):
        return False
    row = sql.execute(''' SELECT MAX(id) AS id
                          FROM audit
                          WHERE event = 'start-server' ''').fetchone()
    if row is not None:
        row = sql.execute(''' SELECT date, time
                              FROM audit
                              WHERE id = ?''',
                          (row['id'], )).fetchone()
        print('Last started on %s %s.' % (row['date'], row['time']))
    pwic_audit(sql, {'author': PWIC_USERS['system'],
                     'event': 'start-server'})
    app['sql'].commit()
    del sql
    web.run_app(app,
                host=args.host,
                port=args.port,
                ssl_context=https,
                access_log_format=logformat)
    return True


main()
