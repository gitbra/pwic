#!/usr/bin/env python

import argparse
import ssl
from cryptography import fernet
from aiohttp import web, MultipartReader, hdrs
from aiohttp_session import setup, get_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from urllib.parse import parse_qs
from jinja2 import Environment, FileSystemLoader
import sqlite3
from difflib import HtmlDiff
import zipfile
import os
import json
import re
import base64
from multidict import MultiDict
import time

from pwic_md import Markdown
from pwic_lib import PWIC_VERSION, PWIC_DB, PWIC_DOCUMENTS_PATH, PWIC_USER, \
    PWIC_USER_ANONYMOUS, PWIC_DEFAULT_PASSWORD, PWIC_PRIVATE_KEY, PWIC_PUBLIC_KEY, \
    PWIC_EMOJIS, PWIC_CHARS_UNSAFE, PWIC_MIMES, \
    _x, _xb, _int, _dt, _sha256, _safeName, _safeFileName, _size2str, \
    pwic_extended_syntax, pwic_audit, pwic_search_parse, pwic_search_tostring


# ===============
#  Documentation
#   - Jinja2 :          http://zetcode.com/python/jinja/
#   - Markdown :        https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet
#   - HTTP codes :      https://docs.aiohttp.org/en/latest/web_exceptions.html
#                       https://docs.pylonsproject.org/projects/pyramid/en/latest/api/httpexceptions.html
#   - SSL :             https://stackoverflow.com/questions/51645324/how-to-setup-a-aiohttp-https-server-and-client/51646535
#   - PyParsing :       https://github.com/pyparsing/pyparsing/blob/master/examples/searchparser.py
#   - Parsimonious :    https://github.com/erikrose/parsimonious
#                       http://zderadicka.eu/writing-simple-parser-in-python/
#   - HTML5 upload :    https://www.smashingmagazine.com/2018/01/drag-drop-file-uploader-vanilla-js/
#                       https://css-tricks.com/drag-and-drop-file-uploading/
#                       https://docs.aiohttp.org/en/stable/multipart.html
#   - Magic bytes :     https://en.wikipedia.org/wiki/List_of_file_signatures
# ===============


# ===========================================================
#  This class handles everything related to the HTTP session
# ===========================================================

class PwicSession():
    def __init__(self, request):
        ''' Constructor '''
        self.request = request

    async def destroy(self):
        ''' Destroy the content of the session '''
        session = await get_session(self.request)
        if session is not None and 'data' in session:
            del session['data']

    def getDefaultData(self):
        ''' Provide the default structure of the session '''
        return {'user': '',
                'stamp': time.time()}

    async def getSession(self):
        ''' Retrieve the data of the current session and initializes it by default if needed '''
        session = await get_session(self.request)
        assert(session is not None)
        if 'data' not in session:
            session['data'] = self.getDefaultData()
        return session

    async def getUser(self):
        ''' Retrieve the logged user '''
        session = await self.getSession()
        return session['data']['user'] if session is not None else ''


# ===================================================
#  This class handles the rendering of the web pages
# ===================================================

class PwicServer():
    def _md2html(self, markdown):
        return pwic_extended_syntax(app['markdown'].convert(markdown))

    def _mime2icon(self, mime):
        if mime[:6] == 'image/':
            return PWIC_EMOJIS['image']
        elif mime[:6] == 'video/':
            return PWIC_EMOJIS['camera']
        elif mime[:6] == 'audio/':
            return PWIC_EMOJIS['headphone']
        elif mime[:12] == 'application/':
            return PWIC_EMOJIS['server']
        else:
            return PWIC_EMOJIS['sheet']

    def _readEnv(self, sql, name):
        row = sql.execute("SELECT value FROM env WHERE key = ? AND value <> ''", (name, )).fetchone()
        return None if row is None else row[0]

    def _checkMime(self, obj):
        # Check the applicable extension
        if '.' in obj['filename']:
            extension = obj['filename'].split('.')[-1]
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
                            bytes = bytearray(bytes.encode())
                            if obj['content'][:len(bytes)] == bytes:
                                return True
                        return False
                    break
        return obj['mime'] != ''

    async def _handlePost(self, request):
        ''' Return the POST as a readable object.get() '''
        result = {}
        if request.body_exists:
            data = await request.text()
            result = parse_qs(data)
            for res in result:
                result[res] = result[res][0]
        return result

    async def _handleLogon(self, request):
        ''' Show the logon page '''
        return await self._handleOutput(request, 'logon', {'title': 'Connect to Pwic'})

    async def _handleOutput(self, request, name, pwic):
        ''' Serve the right template, in the right language, with the right PWIC structure and additional data '''
        session = PwicSession(request)
        pwic['user'] = await session.getUser()
        pwic['emojis'] = PWIC_EMOJIS
        pwic['constants'] = {'version': PWIC_VERSION,
                             'unsafe_chars': PWIC_CHARS_UNSAFE,
                             'anonymous_user': PWIC_USER_ANONYMOUS,
                             'language': 'en'}
        ua = request.headers.get('User-Agent', '')
        pwic['msie'] = 'Trident' in ua or 'MSIE' in ua  # Some JavaScript is not written for this obsolete web-browser

        # Environment variables
        sql = app['sql'].cursor()
        sql.execute(''' SELECT key, value
                        FROM env
                        WHERE value <> ''
                        ORDER BY key''')
        pwic['env'] = {}
        for row in sql.fetchall():
            pwic['env'][row[0]] = row[1]
        pwic['env']['ssl'] = app['ssl']

        # Rendered template
        template = app['jinja'].get_template('en/%s.html' % name)
        return web.Response(text=template.render(pwic=pwic), content_type='text/html')

    async def page(self, request):
        ''' Serve the pages '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon(request)

        # Show the requested page
        project = request.match_info.get('project', '')
        page = request.match_info.get('page', 'home')
        revision = request.match_info.get('revision', None)
        action = request.match_info.get('action', 'view')
        sql = app['sql'].cursor()
        pwic = {'title': 'Wiki',
                'project': project,
                'page': page,
                'revision': revision,
                'special': page == 'special'}
        dt = _dt()

        # Fetch the name of the project...
        if project != '':
            sql.execute(''' SELECT b.description, a.admin, a.manager, a.editor, a.validator, a.reader
                            FROM roles AS a
                                INNER JOIN projects AS b
                                    ON b.project = a.project
                            WHERE a.project = ?
                              AND a.user = ?
                            LIMIT 1''',
                        (project, user))
            row = sql.fetchone()
            if row is None:
                raise web.HTTPNotFound()  # Project not found, or user not authorized to view it
            pwic['project_description'] = row[0]
            pwic['admin'] = _xb(row[1])
            pwic['manager'] = _xb(row[2])
            pwic['editor'] = _xb(row[3])
            pwic['validator'] = _xb(row[4])
            pwic['reader'] = _xb(row[5])

        # ...or ask the user to pick a project
        else:
            sql.execute(''' SELECT a.project, a.description
                            FROM projects AS a
                                INNER JOIN roles AS b
                                    ON  b.project = a.project
                                    AND b.user = ?
                            ORDER BY a.description''',
                        (user, ))
            pwic['title'] = 'Select your project'
            pwic['projects'] = []
            for row in sql.fetchall():
                pwic['projects'].append({'project': row[0], 'description': row[1]})
            return await self._handleOutput(request, 'select-project', pwic)

        # Fetch the links of the header line
        sql.execute(''' SELECT a.page, a.title
                        FROM pages AS a
                        WHERE a.project = ?
                          AND a.header = "X"
                        ORDER BY a.title''',
                    (project, ))
        pwic['links'] = []
        for row in sql.fetchall():
            pwic['links'].append({'project': project,
                                  'page': row[0],
                                  'title': row[1]})
            if row[0] == 'home':
                pwic['links'].insert(0, pwic['links'].pop())    # Push to top of list because it is the home page

        # Fetch the name of the page
        if page != '':
            if page == 'special':
                row = ['Special']
            else:
                sql.execute(''' SELECT title
                                FROM pages
                                WHERE project = ?
                                  AND page    = ?
                                  AND latest  = "X"''',
                            (project, page))
                row = sql.fetchone()
                if row is None:
                    raise web.HTTPNotFound()  # Page not found
            pwic['page_title'] = row[0]

            # Show the requested page (not necessarily the latest one)
            if action == 'view':
                if page != 'special':
                    sql.execute(''' SELECT revision, latest, draft, final, protection,
                                           author, date, time, title, markdown,
                                           valuser, valdate, valtime
                                    FROM pages
                                    WHERE project = ?
                                      AND page    = ?
                                    ORDER BY revision DESC''',
                                (project, page))
                    found = False
                    for row in sql.fetchall():
                        if revision is None or _int(row[0]) == _int(revision):
                            found = True
                            break
                    if not found:
                        raise web.HTTPNotFound()  # Revision not found
                    pwic['revision'] = row[0]
                    pwic['latest'] = _xb(row[1])
                    pwic['draft'] = _xb(row[2])
                    pwic['final'] = _xb(row[3])
                    pwic['protection'] = _xb(row[4])
                    pwic['author'] = row[5]
                    pwic['date'] = row[6]
                    pwic['time'] = row[7]
                    pwic['title'] = row[8]
                    pwic['markdown'] = row[9]
                    pwic['html'], pwic['tmap'] = self._md2html(row[9])
                    pwic['hash'] = _sha256(row[9], salt=False)
                    pwic['valuser'] = row[10]
                    pwic['valdate'] = row[11]
                    pwic['valtime'] = row[12]
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
                        category = 'images' if row[2][:6] == 'image/' else 'documents'
                        pwic[category].append({'id': row[0],
                                               'filename': row[1],
                                               'mime': row[2],
                                               'size': _size2str(row[3]),
                                               'author': row[4],
                                               'date': row[5],
                                               'time': row[6]})

                # Additional information for the special page
                else:
                    # Fetch the recently updated pages
                    sql.execute(''' SELECT page, author, date, time, title, comment, milestone
                                    FROM pages
                                    WHERE project = ?
                                      AND latest  = "X"
                                      AND date   >= ?
                                    ORDER BY date DESC, time DESC''',
                                (project, dt['date-30d']))
                    pwic['recents'] = []
                    for row in sql.fetchall():
                        pwic['recents'].append({'page': row[0],
                                                'author': row[1],
                                                'date': row[2],
                                                'time': row[3],
                                                'title': row[4],
                                                'comment': row[5],
                                                'milestone': row[6]})

                    # Fetch the team members of the project
                    sql.execute(''' SELECT user, admin, manager, editor, validator, reader
                                    FROM roles
                                    WHERE project = ?
                                    ORDER BY admin     DESC,
                                             manager   DESC,
                                             editor    DESC,
                                             validator DESC,
                                             reader    DESC,
                                             user      ASC''',
                                (project, ))
                    pwic['admins'] = []
                    pwic['managers'] = []
                    pwic['editors'] = []
                    pwic['validators'] = []
                    pwic['readers'] = []
                    for row in sql.fetchall():
                        if _xb(row[1]):
                            pwic['admins'].append(row[0])
                        if _xb(row[2]):
                            pwic['managers'].append(row[0])
                        if _xb(row[3]):
                            pwic['editors'].append(row[0])
                        if _xb(row[4]):
                            pwic['validators'].append(row[0])
                        if _xb(row[5]):
                            pwic['readers'].append(row[0])

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
                                        WHERE a.project = ?
                                          AND b.date IS NULL
                                        ORDER BY a.user''',
                                    (dt['date-30d'], project, project))
                        pwic['inactive_users'] = []
                        for row in sql.fetchall():
                            pwic['inactive_users'].append(row[0])

                    # Fetch the pages of the project
                    sql.execute(''' SELECT page, title, revision, final, author,
                                           date, time, milestone, valuser, valdate,
                                           valtime
                                    FROM pages
                                    WHERE project = ?
                                      AND latest  = "X"
                                    ORDER BY page ASC, revision DESC''',
                                (project, ))
                    pwic['pages'] = []
                    for row in sql.fetchall():
                        pwic['pages'].append({'page': row[0],
                                              'title': row[1],
                                              'revision': row[2],
                                              'final': row[3],
                                              'author': row[4],
                                              'date': row[5],
                                              'time': row[6],
                                              'milestone': row[7],
                                              'valuser': row[8],
                                              'valdate': row[9],
                                              'valtime': row[10]})

                    # Fetch the documents of the project
                    sql.execute(''' SELECT b.id, b.project, b.page, b.filename, b.mime, b.size,
                                           b.hash, b.author, b.date, b.time, c.occurrence
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
                                    WHERE a.project = ?
                                      AND a.user    = ?
                                    ORDER BY filename''',
                                (project, project, user))
                    pwic['documents'] = []
                    for row in sql.fetchall():
                        pwic['documents'].append({'id': row[0],
                                                  'project': row[1],
                                                  'page': row[2],
                                                  'filename': row[3],
                                                  'mime': row[4],
                                                  'mime_icon': self._mime2icon(row[4]),
                                                  'size': _size2str(row[5]),
                                                  'hash': row[6],
                                                  'author': row[7],
                                                  'date': row[8],
                                                  'time': row[9],
                                                  'occurrence': row[10]})

                    # Audit log
                    if pwic['admin']:
                        sql.execute(''' SELECT id, date, time, author, event,
                                               user, project, page, revision,
                                               string
                                        FROM audit
                                        WHERE project = ?
                                          AND date   >= ?
                                        ORDER BY id DESC''',
                                    (project, dt['date-30d']))
                        pwic['audits'] = []
                        for row in sql.fetchall():
                            pwic['audits'].append({'date': row[1],
                                                   'time': row[2],
                                                   'author': row[3],
                                                   'event': row[4],
                                                   'user': row[5],
                                                   'project': row[6],
                                                   'page': row[7],
                                                   'revision': row[8],
                                                   'string': row[9]})

                # Render the page in HTML or Markdown
                if self._readEnv(sql, 'no_raw') is not None or request.rel_url.query.get('raw', None) is None:
                    return await self._handleOutput(request, 'page', pwic)
                else:
                    return web.Response(text=pwic['markdown'], content_type='text/plain')

            # Edit the requested page
            elif action == 'edit':
                sql.execute(''' SELECT draft, final, header, protection, title, markdown, milestone
                                FROM pages
                                WHERE project = ?
                                  AND page    = ?
                                  AND latest  = "X"''',
                            (project, page))
                row = sql.fetchone()
                if row is None:
                    raise web.HTTPNotFound()        # Page not found
                pwic['draft'] = _xb(row[0])
                pwic['final'] = _xb(row[1])
                pwic['header'] = _xb(row[2])
                pwic['protection'] = _xb(row[3])
                pwic['title'] = row[4]
                pwic['markdown'] = row[5]
                pwic['milestone'] = row[6]
                return await self._handleOutput(request, 'page-edit', pwic)

            # Show the history of the page
            elif action == 'history':
                sql.execute(''' SELECT revision, latest, draft, final, author, date, time,
                                       title, comment, milestone, valuser, valdate, valtime
                                FROM pages
                                WHERE project = ? AND page = ?
                                ORDER BY revision DESC''',
                            (project, page))
                pwic['revisions'] = []
                for row in sql.fetchall():
                    pwic['revisions'].append({'revision': row[0],
                                              'latest': _xb(row[1]),
                                              'draft': _xb(row[2]),
                                              'final': _xb(row[3]),
                                              'author': row[4],
                                              'date': row[5],
                                              'time': row[6],
                                              'title': row[7],
                                              'comment': row[8],
                                              'milestone': row[9],
                                              'valuser': row[10],
                                              'valdate': row[11],
                                              'valtime': row[12]})
                pwic['title'] = 'Revisions of the page'
                return await self._handleOutput(request, 'page-history', pwic)

        # Default output if nothing was done before
        raise web.HTTPNotFound()

    async def page_help(self, request):
        ''' Serve the help page to any user '''
        return await self._handleOutput(request, 'help', {'title': 'Help for Pwic'})

    async def page_create(self, request):
        ''' Serve the page to create a new page '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon(request)

        # Fetch the projects where the user can add pages
        pwic = {'title': 'Create a page',
                'default_project': request.rel_url.query.get('project', ''),
                'projects': []}
        sql = app['sql'].cursor()
        sql.execute(''' SELECT a.project, b.description
                        FROM roles AS a
                            INNER JOIN projects AS b
                                ON b.project = a.project
                        WHERE a.user    = ?
                          AND a.manager = "X"
                        ORDER BY b.description''',
                    (user, ))
        for row in sql.fetchall():
            pwic['projects'].append({'project': row[0],
                                     'description': row[1]})

        # Show the page
        return await self._handleOutput(request, 'page-create', pwic=pwic)

    async def user_create(self, request):
        ''' Serve the page to create a new user '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon(request)

        # Fetch the projects where users can be created
        pwic = {'title': 'Create a user',
                'default_project': request.rel_url.query.get('project', ''),
                'projects': []}
        sql = app['sql'].cursor()
        sql.execute(''' SELECT a.project, b.description
                        FROM roles AS a
                            INNER JOIN projects AS b
                                ON b.project = a.project
                        WHERE a.user  = ?
                          AND a.admin = "X"
                        ORDER BY b.description''',
                    (user, ))
        for row in sql.fetchall():
            pwic['projects'].append({'project': row[0],
                                     'description': row[1]})

        # Show the page
        return await self._handleOutput(request, 'user-create', pwic=pwic)

    async def page_user(self, request):
        ''' Serve the page to view the profile of a user '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon(request)

        # Fetch the information of the user
        sql = app['sql'].cursor()
        userpage = request.match_info.get('userpage', None)
        sql.execute('SELECT initial FROM users WHERE user = ?', (userpage, ))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPNotFound()    # User does not exist
        pwic = {'title': 'User profile',
                'user': user,
                'userpage': userpage,
                'initial_password': _xb(row[0]),
                'projects': [],
                'documents': [],
                'pages': []}

        # Fetch the commonly-accessible projects assigned to the user
        sql.execute(''' SELECT a.project, c.description
                        FROM roles AS a
                            INNER JOIN roles AS b
                                ON  b.project = a.project
                                AND b.user    = ?
                            INNER JOIN projects AS c
                                ON  c.project = a.project
                        WHERE a.user = ?
                        ORDER BY c.description''',
                    (user, userpage))
        for row in sql.fetchall():
            pwic['projects'].append({'project': row[0],
                                     'description': row[1]})

        # Fetch the own documents
        sql.execute(''' SELECT b.id, b.project, b.page, b.filename, b.mime, b.size,
                               b.hash, b.author, b.date, b.time, c.occurrence
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
                        WHERE a.user = ?
                        ORDER BY date DESC,
                                 time DESC''',
                    (userpage, user))
        for row in sql.fetchall():
            pwic['documents'].append({'id': row[0],
                                      'project': row[1],
                                      'page': row[2],
                                      'filename': row[3],
                                      'mime': row[4],
                                      'mime_icon': self._mime2icon(row[4]),
                                      'size': _size2str(row[5]),
                                      'hash': row[6],
                                      'author': row[7],
                                      'date': row[8],
                                      'time': row[9],
                                      'occurrence': row[10]})

        # Fetch the latest pages updated by the selected user
        dt = _dt()
        sql.execute(''' SELECT u.project, u.page, p.revision, p.final,
                               p.date, p.time, p.title, p.milestone,
                               p.valuser, p.valdate, p.valtime
                        FROM (
                            SELECT DISTINCT project, page
                            FROM (
                                SELECT project, page
                                FROM pages
                                WHERE latest   = "X"
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
                            INNER JOIN pages AS p
                                ON  p.project  = u.project
                                AND p.page     = u.page
                                AND p.latest   = "X"
                        ORDER BY date DESC,
                                 time DESC''',
                    (userpage, dt['date-90d'], userpage, dt['date-90d'], user))
        for row in sql.fetchall():
            pwic['pages'].append({'project': row[0],
                                  'page': row[1],
                                  'revision': row[2],
                                  'final': row[3],
                                  'date': row[4],
                                  'time': row[5],
                                  'title': row[6],
                                  'milestone': row[7],
                                  'valuser': row[8],
                                  'valdate': row[9],
                                  'valtime': row[10]})

        # Show the page
        return await self._handleOutput(request, 'user', pwic=pwic)

    async def page_search(self, request):
        ''' Serve the search engine '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon(request)

        # Parse the query
        project = request.match_info.get('project', '')
        terms = request.rel_url.query.get('q', '')
        query = pwic_search_parse(terms)
        if query is None:
            raise web.HTTPTemporaryRedirect('/%s' % project)

        # Fetch the pages
        sql = app['sql'].cursor()
        pwic = {'title': 'Search',
                'project': project,
                'terms': pwic_search_tostring(query),
                'results': []}

        # Fetch the description of the project if the user has access rights
        sql.execute(''' SELECT b.description
                        FROM roles AS a
                            INNER JOIN projects AS b
                                ON b.project = a.project
                        WHERE a.project = ?
                          AND a.user    = ?''',
                    (project, user))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPUnauthorized()
        pwic['project_description'] = row[0]

        # Search
        sql.execute(''' SELECT project, page, draft, final, author,
                               date, time, title,
                               LOWER(markdown) AS markdown, valuser
                        FROM pages
                        WHERE project = ?
                          AND latest  = "X"
                        ORDER BY date DESC,
                                 time DESC''',
                    (project, ))
        for row in sql.fetchall():
            # Apply the filters
            ok = True
            score = 0
            for q in query['excluded']:         # The first occurrence of an excluded term excludes the whole page
                if (q == ':draft' and row[2] == 'X')                        \
                   or (q == ':not-draft' and row[2] == '')                  \
                   or (q == ':final' and row[3] == 'X')                     \
                   or (q == ':not-final' and row[3] == '')                  \
                   or (q[:7] == 'author:' and q[7:] in row[4].lower())      \
                   or (q[:6] == 'title:' and q[6:] in row[7].lower())       \
                   or (q == ':not-validated' and row[9] == '')              \
                   or (q == ':validated' and row[9] != '')                  \
                   or (q[:10] == 'validator:' and q[10:] in row[9].lower()) \
                   or (q == row[1].lower())                                 \
                   or (q in row[8]):
                    ok = False
                    break
            if ok:
                for q in query['included']:     # The first non-occurrence of an included term excludes the whole page
                    if q == ':draft':
                        count = _int(row[2] == 'X')
                    elif q == ':not-draft':
                        count = _int(row[2] == '')
                    elif q == ':final':
                        count = _int(row[3] == 'X')
                    elif q == ':not-final':
                        count = _int(row[3] == '')
                    elif q[:7] == 'author:':
                        count = row[4].lower().count(q[7:])
                    elif q[:6] == 'title:':
                        count = row[7].lower().count(q[6:])
                    elif q == ':not-validated':
                        count = _int(row[9] == '')
                    elif q == ':validated':
                        count = _int(row[9] != '')
                    elif q[:10] == 'validator:':
                        count = _int(q[10:] in row[9].lower())
                    else:
                        count = _int(q == row[1].lower()) + row[8].count(q)
                    if count == 0:
                        ok = False
                        break
                    else:
                        score += count
            if not ok:
                continue

            # Save the found result
            pwic['results'].append({'project': row[0],
                                    'page': row[1],
                                    'author': row[4],
                                    'date': row[5],
                                    'time': row[6],
                                    'title': row[7],
                                    'score': score})

        # Show the page
        pwic['results'].sort(key=lambda x: x['score'], reverse=True)
        return await self._handleOutput(request, 'search', pwic=pwic)

    async def page_roles(self, request):
        ''' Serve the search engine '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon(request)

        # Fetch the roles
        sql = app['sql'].cursor()
        project = request.match_info.get('project', '')
        sql.execute(''' SELECT a.user, c.initial, a.admin, a.manager,
                               a.editor, a.validator, a.reader
                        FROM roles AS a
                            INNER JOIN roles AS b
                                ON  b.project = a.project
                                AND b.user    = ?
                                AND b.admin   = "X"
                            INNER JOIN users AS c
                                ON  c.user    = a.user
                        WHERE a.project = ?
                        ORDER BY a.user''',
                    (user, project))

        # Show the page
        pwic = {'title': 'Roles',
                'project': project,
                'roles': []}
        for row in sql.fetchall():
            pwic['roles'].append({'user': row[0],
                                  'initial': _xb(row[1]),
                                  'admin': _xb(row[2]),
                                  'manager': _xb(row[3]),
                                  'editor': _xb(row[4]),
                                  'validator': _xb(row[5]),
                                  'reader': _xb(row[6])})
        if len(pwic['roles']) == 0:
            raise web.HTTPUnauthorized()        # Or project not found
        else:
            return await self._handleOutput(request, 'user-roles', pwic=pwic)

    async def page_links(self, request):
        ''' Serve the check of the links '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon(request)

        # Fetch the pages
        sql = app['sql'].cursor()
        project = request.match_info.get('project', '')
        sql.execute(''' SELECT b.page, b.header, b.markdown
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.latest  = "X"
                        WHERE a.project = ?
                          AND a.user    = ?
                          AND a.manager = "X"
                        ORDER BY b.page''',
                    (project, user))

        # Extract the links between the pages
        ok = False
        regex_page = re.compile(r'\]\(\/([^\/#]+)\/([^\/#]+)(\/rev[0-9]+)?(\?.*)?(\#.*)?\)', re.IGNORECASE)
        linkmap = {'home': []}
        for row in sql.fetchall():
            ok = True
            page = row[0]
            if page not in linkmap:
                linkmap[page] = []

            # Generate a fake link at the home page for all the bookmarked pages
            if row[1] == "X" and page not in linkmap['home']:
                linkmap['home'].append(page)

            # Find the links to the other pages
            subpages = regex_page.findall(row[2])
            if subpages is not None:
                for sp in subpages:
                    if (sp[0] == project) and (sp[1] not in linkmap[page]):
                        linkmap[page].append(sp[1])
        if not ok:
            raise web.HTTPUnauthorized()

        # Find the orphaned and broken links
        allpages = [key for key in linkmap]
        orphans = allpages.copy()
        orphans.remove('home')
        broken = []
        for link in linkmap:
            for page in linkmap[link]:
                if page in orphans:
                    orphans.remove(page)
                if page not in allpages:
                    broken.append({'source': link,
                                   'destination': page})

        # Show the values
        sql.execute('SELECT description FROM projects WHERE project = ?', (project, ))
        pwic = {'title': 'Report of the links',
                'project': project,
                'project_description': sql.fetchone()[0],
                'orphans': orphans,
                'broken': broken}
        return await self._handleOutput(request, 'page-links', pwic=pwic)

    async def page_compare(self, request):
        ''' Serve the page that compare two revisions '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon(request)

        # Fetch the pages
        sql = app['sql'].cursor()
        project = request.match_info.get('project', '')
        page = request.match_info.get('page', '')
        new_revision = _int(request.match_info.get('new_revision', ''))
        old_revision = _int(request.match_info.get('old_revision', ''))
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
                        WHERE a.project = ?
                          AND a.user    = ?''',
                    (page, new_revision, old_revision, project, user))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPUnauthorized()

        # Show the page
        def _diff(tfrom, tto):
            diff = HtmlDiff()
            tfrom = tfrom.replace('\r', '').split('\n')
            tto = tto.replace('\r', '').split('\n')
            return diff.make_table(tfrom, tto).replace('&nbsp;', ' ').replace(' nowrap="nowrap"', '').replace(' cellpadding="0"', '')

        pwic = {'title': 'Comparison',
                'project': project,
                'project_description': row[0],
                'page': page,
                'page_title': row[1],
                'new_revision': new_revision,
                'old_revision': old_revision,
                'diff': _diff(row[3], row[2])}
        return await self._handleOutput(request, 'page-compare', pwic=pwic)

    async def project_export(self, request):
        ''' Download the project as a zip file '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon(request)

        # Verify that the export is authorized
        sql = app['sql'].cursor()
        if self._readEnv(sql, 'no_export') is not None:
            raise web.HTTPUnauthorized()

        # Fetch the pages
        project = request.match_info.get('project', '')
        sql.execute(''' SELECT b.page, b.author, b.date, b.time, b.title, b.markdown
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.latest  = "X"
                        WHERE a.project = ?
                          AND a.user    = ?
                          AND a.admin   = "X"
                        ORDER BY b.page''',
                    (project, user))
        pages = []
        for row in sql.fetchall():
            pages.append(row)

        # Build the zip file
        if len(pages) == 0:
            raise web.HTTPUnauthorized()
        try:
            zipname = PWIC_DB + '.zip'
            zip = zipfile.ZipFile(zipname, mode='w', compression=zipfile.ZIP_DEFLATED)

            # Pages of the project
            for page in pages:
                # Raw markdown
                zip.writestr('%s.md' % page[0], page[5])

                # HTML
                html = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="author" content="%s">
    <meta name="last-modified" content="%s %s">
    <title>%s %s</title>
    <link rel="stylesheet" type="text/css" href="static/styles.css" />
</head>
<body>
    <article>%s</article>
</body>
</html>'''
                html = html % (page[1].replace('"', '&quote;'),
                               page[2],
                               page[3],
                               page[0].replace('<', '&lt;').replace('>', '&gt;'),
                               page[4].replace('<', '&lt;').replace('>', '&gt;'),
                               self._md2html(page[5])[0])
                zip.writestr('%s.html' % page[0], html)

            # Dependent files for the pages
            fn = 'static/styles.css'
            with open(fn, 'rb') as f:
                content = f.read()
            zip.writestr(fn, content)

            # Attached documents
            sql.execute('SELECT filename FROM documents WHERE project = ?', (project, ))
            for row in sql.fetchall():
                fn = (PWIC_DOCUMENTS_PATH % project) + row[0]
                if os.path.isfile(fn):
                    with open(fn, 'rb') as f:
                        content = f.read()
                    zip.writestr('documents/%s' % row[0], content)

            # Close the archive
            zip.close()
        except Exception:
            raise web.HTTPInternalServerError()

        # Audit the action
        pwic_audit(sql, {'author': user,
                         'event': 'export-project',
                         'project': project},
                   request, commit=True)

        # Return the file
        with open(zipname, 'rb') as f:
            content = f.read()
        os.remove(zipname)
        return web.Response(body=content, headers=MultiDict({'Content-Disposition': 'Attachment;filename=%s.zip' % project}))

    async def document_get(self, request):
        ''' Download a document '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            return web.HTTPUnauthorized()

        # Read the properties of the requested document
        id = _int(request.match_info.get('id', 0))
        sql = app['sql'].cursor()
        sql.execute(''' SELECT a.project, a.filename, a.mime, a.size
                        FROM documents AS a
                            INNER JOIN roles AS b
                                ON  b.project = a.project
                                AND b.user    = ?
                        WHERE a.id = ?''',
                    (user, id))
        row = sql.fetchone()
        if row is None:
            return web.HTTPNotFound()

        # Transfer the file
        filename = (PWIC_DOCUMENTS_PATH % row[0]) + row[1]
        try:
            with open(filename, 'rb') as f:
                content = f.read()
        except FileNotFoundError:
            raise web.HTTPNotFound()
        headers = {'Content-Type': row[2],
                   'Content-Length': str(row[3])}
        if request.rel_url.query.get('attachment', None) is not None:
            headers['Content-Disposition'] = 'attachment; filename=%s' % row[1]
        return web.Response(body=content, headers=MultiDict(headers))

    async def api_logon(self, request):
        ''' API to log on people '''
        # Destroy the current session
        session = PwicSession(request)
        await session.destroy()

        # Fetch the submitted data
        sql = app['sql'].cursor()
        post = await self._handlePost(request)
        user = post.get('logon_user', '')
        pwd = '' if (self._readEnv(sql, 'anonymous') is not None) and (user == PWIC_USER_ANONYMOUS) else _sha256(post.get('logon_password', ''))

        # Logon with the credentials
        ok = False
        sql.execute(''' SELECT COUNT(user)
                        FROM users
                        WHERE user     = ?
                          AND password = ?''',
                    (user, pwd))
        if sql.fetchone()[0] == 1:
            ok = True
            data = session.getDefaultData()
            data['user'] = user
            session = await session.getSession()
            session['data'] = data
            if user != PWIC_USER_ANONYMOUS:
                pwic_audit(sql, {'author': user,
                                 'event': 'logon'},
                           request, commit=True)

        # Final redirection
        raise web.HTTPFound('/' if ok else '/?failed')

    async def api_logout(self, request):
        ''' API to log out '''
        session = PwicSession(request)
        user = await session.getUser()
        if user != '':
            await session.destroy()
            if user != PWIC_USER_ANONYMOUS:
                pwic_audit(app['sql'].cursor(), {'author': user,
                                                 'event': 'logout'},
                           request, commit=True)
        return await self._handleOutput(request, 'logout', {'title': 'Disconnected from Pwic'})

    async def api_page_create(self, request):
        ''' API to create a new page '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('create_project', ''))
        page = _safeName(post.get('create_page', ''))
        milestone = post.get('create_milestone', '').strip()
        ref_project = _safeName(post.get('create_ref_project', ''))
        ref_page = _safeName(post.get('create_ref_page', ''))
        if project in ['', 'api', 'special'] or page in ['', 'special']:
            raise web.HTTPBadRequest()

        # Verify that the user is manager of the provided project, and that the page doesn't exist yet
        sql = app['sql'].cursor()
        sql.execute(''' SELECT b.page
                        FROM roles AS a
                            LEFT OUTER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.page    = ?
                                AND b.latest  = "X"
                        WHERE a.project = ?
                          AND a.user    = ?
                          AND a.manager = "X"''',
                    (page, project, user))
        row = sql.fetchone()
        if row is None or row[0] is not None:
            raise web.HTTPNotModified('/special/create-page?failed')

        # Fetch the default markdown if the page is created in reference to another one
        default_markdown = '# %s' % page
        if ref_project != '' and ref_page != '':
            sql.execute(''' SELECT b.markdown
                            FROM roles AS a
                                INNER JOIN pages AS b
                                    ON  b.project = a.project
                                    AND b.page    = ?
                                    AND b.latest  = "X"
                            WHERE a.project = ?
                              AND a.user    = ?''',
                        (ref_page, ref_project, user))
            row = sql.fetchone()
            if row is None:
                raise web.HTTPNotModified('/special/create-page?failed')
            default_markdown = row[0]

        # Handle the creation of the page
        dt = _dt()
        revision = 1
        sql.execute(''' INSERT INTO pages (project, page, revision, author, date, time, title, markdown, comment, milestone)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (project, page, revision, user, dt['date'], dt['time'], page, default_markdown, 'Initial', milestone))
        assert(sql.rowcount > 0)
        pwic_audit(sql, {'author': user,
                         'event': 'create-page',
                         'project': project,
                         'page': page,
                         'revision': revision},
                   request, commit=True)
        raise web.HTTPFound('/%s/%s?success' % (project, page))

    async def api_page_update(self, request):
        ''' API to update an existing page '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('edit_project', ''))
        page = _safeName(post.get('edit_page', ''))
        title = post.get('edit_title', '').strip()
        markdown = post.get('edit_markdown', '')
        comment = post.get('edit_comment', '').strip()
        milestone = post.get('edit_milestone', '').strip()
        draft = _x('edit_draft' in post)
        final = _x('edit_final' in post)
        protection = _x('edit_protection' in post)
        header = _x('edit_header' in post)
        dt = _dt()
        if '' in [user, project, page, title]:
            raise web.HTTPBadRequest()
        if final:
            draft = ''

        # Fetch the last revision of the page and the profile of the user
        sql = app['sql'].cursor()
        sql.execute(''' SELECT b.revision, b.header, b.protection, a.manager
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.page    = ?
                                AND b.latest  = "X"
                        WHERE a.project = ?
                          AND a.user = ?
                          AND ( a.manager = "X"
                             OR a.editor  = "X" )''',
                    (page, project, user))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPUnauthorized()        # Or not found which is normally unlikely
        revision = row[0]
        manager = _xb(row[3])
        if not manager:
            if _xb(row[2]):                     # The protected pages can be updated by the managers only
                raise web.HTTPUnauthorized()
            protection = ''                     # This field cannot be set by the non-managers
            header = row[1]                     # This field is reserved to the managers, so we keep the existing value

        # Create the new entry
        sql.execute(''' INSERT INTO pages
                            (project, page, revision, draft, final, header,
                             protection, author, date, time, title,
                             markdown, comment, milestone)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (project, page, revision + 1, draft, final, header,
                     protection, user, dt['date'], dt['time'], title,
                     markdown, comment, milestone))
        if sql.rowcount > 0:
            pwic_audit(sql, {'author': user,
                             'event': 'update-page',
                             'project': project,
                             'page': page,
                             'revision': revision + 1},
                       request)

            # Remove the own drafts
            if final:
                sql.execute(''' DELETE FROM pages
                                WHERE project   = ?
                                  AND page      = ?
                                  AND revision <= ?
                                  AND author    = ?
                                  AND draft     = "X"
                                  AND final     = ""
                                  AND valuser   = ""''',
                            (project, page, revision, user))
                if sql.rowcount > 0:
                    pwic_audit(sql, {'author': user,
                                     'event': 'delete-drafts',
                                     'project': project,
                                     'page': page,
                                     'revision': revision + 1},
                               request)

            # Purge the old flags
            sql.execute(''' UPDATE pages
                            SET header = "",
                                latest = ""
                            WHERE project   = ?
                              AND page      = ?
                              AND revision <= ?''',
                        (project, page, revision))
            sql.execute('COMMIT')
        raise web.HTTPFound('/%s/%s?success' % (project, page))

    async def api_page_validate(self, request):
        ''' Validate the pages '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the revision to validate
        project = request.match_info.get('project', '')
        page = request.match_info.get('page', '')
        revision = _int(request.match_info.get('revision', 0))
        if '' in [project, page] or revision == 0:
            raise web.HTTPBadRequest()

        # Verify that it is possible to validate the page
        sql = app['sql'].cursor()
        sql.execute(''' SELECT b.page
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.page = ?
                                AND b.revision = ?
                                AND b.final = "X"
                                AND b.valuser = ""
                            INNER JOIN users AS c
                                ON  c.user = a.user
                                AND c.initial <> "X"
                        WHERE a.project = ?
                          AND a.user = ?
                          AND a.validator = "X"''',
                    (page, revision, project, user))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPUnauthorized()

        # Update the page
        dt = _dt()
        sql.execute(''' UPDATE pages
                        SET valuser = ?, valdate = ?, valtime = ?
                        WHERE project = ? AND page = ? AND revision = ?''',
                    (user, dt['date'], dt['time'], project, page, revision))
        pwic_audit(sql, {'author': user,
                         'event': 'validate-page',
                         'project': project,
                         'page': page,
                         'revision': revision},
                   request, commit=True)
        raise web.HTTPFound('/%s/%s/rev%d?success' % (project, page, revision))

    async def api_page_delete(self, request):
        ''' Delete a page upon administrative request '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the revision to delete
        project = request.match_info.get('project', '')
        page = request.match_info.get('page', '')
        revision = _int(request.match_info.get('revision', 0))
        if '' in [project, page] or revision == 0:
            raise web.HTTPBadRequest()

        # Verify that the deletion is possible
        sql = app['sql'].cursor()
        sql.execute(''' SELECT a.header
                        FROM pages AS a
                            INNER JOIN roles AS b
                                ON  b.project = a.project
                                AND b.user    = ?
                        WHERE a.project  = ?
                          AND a.page     = ?
                          AND a.revision = ?
                          AND ((    b.admin   = "X"
                                AND a.final   = ""
                                AND a.valuser = ""
                            ) OR (  b.user    = a.author
                                AND a.draft   = "X"
                            ))''',
                    (user, project, page, revision))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPUnauthorized()
        header = row[0]

        # Delete the page
        sql.execute(''' DELETE FROM pages
                        WHERE project  = ?
                          AND page     = ?
                          AND revision = ?''',
                    (project, page, revision))
        pwic_audit(sql, {'author': user,
                         'event': 'delete-revision',
                         'project': project,
                         'page': page,
                         'revision': revision},
                   request)
        if revision > 1:
            # Find the latest revision that is not necessarily "revision - 1"
            sql.execute(''' SELECT MAX(revision)
                            FROM pages
                            WHERE project   = ?
                              AND page      = ?
                              AND revision <> ?''',
                        (project, page, revision))
            row = sql.fetchone()
            if row[0] is not None:          # No revision available
                if row[0] < revision:       # If we have already deleted the latest revision
                    sql.execute(''' UPDATE pages
                                    SET latest = "X",
                                        header = ?
                                    WHERE project  = ?
                                      AND page     = ?
                                      AND revision = ?''',
                                (header, project, page, row[0]))

        # Delete the attached documents when the page doesn't exist anymore
        sql.execute(''' SELECT COUNT(revision)
                        FROM pages
                        WHERE project = ?
                          AND page    = ?''',
                    (project, page))
        fully_deleted = sql.fetchone()[0] == 0
        if fully_deleted:
            # Remove the attached documents
            docFound = False
            sql.execute(''' SELECT filename
                            FROM documents
                            WHERE project = ?
                              AND page    = ?''',
                        (project, page))
            for row in sql.fetchall():
                docFound = True
                fn = (PWIC_DOCUMENTS_PATH % project) + row[0]
                try:
                    os.remove(fn)
                except (OSError, FileNotFoundError):
                    if os.path.isfile(fn):
                        sql.execute('ROLLBACK')
                        raise web.HTTPNotModified('/%s/%s?failed' % (project, page))

            # Remove the index
            if docFound:
                sql.execute(''' DELETE FROM documents
                                WHERE project = ?
                                  AND page    = ?''',
                            (project, page))
                pwic_audit(sql, {'author': user,
                                 'event': 'delete-document',
                                 'project': project,
                                 'page': page,
                                 'string': '*'},
                           request)

        # Redirection
        sql.execute('COMMIT')
        if fully_deleted:
            raise web.HTTPFound('/%s?success' % project)  # The page itself is deleted
        else:
            raise web.HTTPFound('/%s/%s?success' % (project, page))

    async def api_user_create(self, request):
        ''' API to create a new user '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon(request)

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = post.get('create_project', '')
        newuser = _safeName(post.get('create_user', ''), extra='')
        if '' in [project, newuser] or (newuser[:4] == 'pwic'):
            raise web.HTTPBadRequest()

        # Verify that the user is administrator of the provided project
        ok = False
        sql = app['sql'].cursor()
        sql.execute(''' SELECT user FROM roles
                        WHERE project = ?
                          AND user    = ?
                          AND admin   = "X"''',
                    (project, user))
        if sql.fetchone() is None:
            raise web.HTTPUnauthorized()

        # Create the new user
        sql.execute(''' INSERT INTO users (user, password)
                        SELECT ?, ?
                        WHERE NOT EXISTS ( SELECT 1 FROM users WHERE user = ? )''',
                    (newuser, _sha256(PWIC_DEFAULT_PASSWORD), newuser))
        if sql.rowcount > 0:
            pwic_audit(sql, {'author': user,
                             'event': 'create-user',
                             'user': newuser},
                       request)

        # Grant the default rights as reader
        sql.execute(''' INSERT INTO roles (project, user, reader)
                        SELECT ?, ?, "X"
                        WHERE NOT EXISTS ( SELECT 1 FROM roles WHERE project = ? AND user = ? )''',
                    (project, newuser, project, newuser))
        if sql.rowcount > 0:
            ok = True
            pwic_audit(sql, {'author': user,
                             'event': 'grant-reader',
                             'project': project,
                             'user': newuser},
                       request)
        sql.execute('COMMIT')

        if ok:
            raise web.HTTPFound('/%s/special/roles?success' % project)
        else:
            raise web.HTTPNotModified('/%s/special/roles?failed' % project)

    async def api_user_change_password(self, request):
        ''' Change the password of the current user '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user[:4] in ['', 'pwic']:
            raise web.HTTPUnauthorized()

        # Get the posted values
        ok = False
        post = await self._handlePost(request)
        current = post.get('user_password_current', '')
        new1 = post.get('user_password_new1', '')
        new2 = post.get('user_password_new2', '')
        if '' not in [current, new1, new2] and (new1 == new2):

            # Verify the current password
            sql = app['sql'].cursor()
            sql.execute(''' SELECT user FROM users
                            WHERE user = ? AND password = ?''',
                        (user, _sha256(current)))
            if sql.fetchone() is not None:
                # Update the password
                sql.execute('UPDATE users SET initial = "", password = ? WHERE user = ?', (_sha256(new1), user))
                if sql.rowcount > 0:
                    pwic_audit(sql, {'author': user,
                                     'event': 'change-password',
                                     'user': user},
                               request)
                sql.execute('COMMIT')
                ok = True

        # Redirection
        if ok:
            raise web.HTTPFound('/special/user/%s?success' % user)
        else:
            raise web.HTTPNotModified('/special/user/%s?failed' % user)

    async def api_roles(self, request):
        ''' Change the roles of a user '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the posted values
        post = await self._handlePost(request)
        project = post.get('project', '')
        userpost = post.get('user', '')
        roles = ['admin', 'manager', 'editor', 'validator', 'reader', 'drop']
        try:
            roleid = roles.index(post.get('role', ''))
            drop = (roles[roleid] == 'drop')
        except ValueError:
            raise web.HTTPBadRequest()
        if '' in [project, userpost] or (userpost[:4] == 'pwic' and roles in ['admin', 'drop']):
            raise web.HTTPBadRequest()

        # Select the current rights of the user
        sql = app['sql'].cursor()
        sql.execute(''' SELECT a.user, a.admin, a.manager, a.editor,
                               a.validator, a.reader, c.initial
                        FROM roles AS a
                            INNER JOIN roles AS b
                                ON  b.project = a.project
                                AND b.user    = ?
                                AND b.admin   = "X"
                            INNER JOIN users AS c
                                ON  c.user    = a.user
                        WHERE a.project = ?
                          AND a.user    = ?''',
                    (user, project, userpost))
        row = sql.fetchone()
        if row is None or (not drop and row[6] == 'X'):
            raise web.HTTPUnauthorized()

        # Drop a user
        if drop:
            sql.execute(''' DELETE FROM roles
                            WHERE project = ?
                              AND user    = ?
                              AND user   <> ?''',
                        (project, userpost, user))
            if sql.rowcount > 0:
                pwic_audit(sql, {'author': user,
                                 'event': 'drop-user',
                                 'project': project,
                                 'user': userpost},
                           request, commit=True)
                return web.Response(text='OK', content_type='text/plain')
            else:
                raise web.HTTPBadRequest()

        # New role
        else:
            newvalue = {'X': '', '': 'X'}[row[roleid + 1]]
            if roleid == 0 and newvalue != 'X' and user == userpost:
                raise web.HTTPUnauthorized()      # Cannot self-ungrant admin, so there is always at least one admin on the project
            try:
                sql.execute(''' UPDATE roles
                                SET %s = ?
                                WHERE project = ?
                                  AND user    = ?''' % roles[roleid],
                            (newvalue, project, userpost))
            except sqlite3.IntegrityError:
                raise web.HTTPUnauthorized()
            if sql.rowcount == 0:
                raise web.HTTPBadRequest()
            else:
                pwic_audit(sql, {'author': user,
                                 'event': '%s-%s' % ('grant' if newvalue == 'X' else 'ungrant', roles[roleid]),
                                 'project': project,
                                 'user': userpost},
                           request, commit=True)
                return web.Response(text=newvalue, content_type='text/plain')

    async def api_markdown(self, request):
        ''' Return the HTML corresponding to the posted Markdown '''
        # Verify that the user is connected
        session = PwicSession(request)
        if await session.getUser() == '':
            raise web.HTTPUnauthorized()

        # Return the converted output
        post = await self._handlePost(request)
        html, _ = self._md2html(post.get('content', ''))
        return web.Response(text=html, content_type='text/plain')

    async def api_document_create(self, request):
        ''' API to create a new document '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            raise web.HTTPUnauthorized()

        # Parse the submitted multipart/form-data
        try:
            regex_name = re.compile(r'[^file]name="([^"]+)"')
            regex_filename = re.compile(r'filename="([^"]+)"')
            doc = {'project': '',
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
                name = regex_name.search(disposition)
                if name is None:
                    continue
                name = name.group(1)
                if name not in ['project', 'page', 'content']:
                    continue

                # Read file name and mime
                if name == 'content':
                    fn = regex_filename.search(disposition)
                    if fn is None:
                        continue
                    fn = _safeFileName(fn.group(1))
                    if fn[:1] == '.':  # Hidden file
                        continue
                    doc['filename'] = fn
                    doc['mime'] = part.headers.get(hdrs.CONTENT_TYPE, '')

                # Assign the value
                if name == 'content':
                    doc[name] = await part.read(decode=False)
                else:
                    doc[name] = await part.text()
        except Exception:
            raise web.HTTPBadRequest()
        if doc['content'] is None or '' in [doc['project'], doc['page'], doc['filename']]:  # The mime is checked later
            raise web.HTTPBadRequest()

        # Verify that the target folder exists
        if not os.path.isdir(PWIC_DOCUMENTS_PATH % doc['project']):
            raise web.HTTPInternalServerError()

        # Verify the authorizations
        sql = app['sql'].cursor()
        sql.execute(''' SELECT b.revision
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.page    = ?
                                AND b.latest  = 'X'
                        WHERE   a.project = ?
                          AND   a.user    = ?
                          AND ( a.manager = 'X'
                             OR a.editor  = 'X' )''',
                    (doc['page'], doc['project'], user))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPUnauthorized()
        current_revision = row[0]

        # Verify the consistency of the filename
        row = self._readEnv(sql, 'document_name_regex')
        if row is not None:
            try:
                regex_doc = re.compile(row, re.VERBOSE)
            except Exception:
                raise web.HTTPInternalServerError()
            if regex_doc.search(doc['filename']) is None:
                raise web.HTTPBadRequest()

        # Verify the file type
        if self._readEnv(sql, 'enforce_mime') is not None:
            if not self._checkMime(doc):
                raise web.HTTPUnsupportedMediaType()

        # Verify the maximal document size
        maxsize = _int(self._readEnv(sql, 'max_document_size'))
        if len(doc['content']) > maxsize > 0:
            raise web.HTTPRequestEntityTooLarge(maxsize, len(doc['content']))

        # Verify the maximal project size
        # ... is there a check ?
        max_project_size = self._readEnv(sql, 'max_project_size')
        if max_project_size is not None:
            max_project_size = _int(max_project_size)
            # ... current size of the project
            current_project_size = _int(sql.execute('SELECT SUM(size) FROM documents WHERE project = ?', (doc['project'], )).fetchone()[0])
            # ... current size of the file if it exists already
            current_file_size = _int(sql.execute('SELECT SUM(size) FROM documents WHERE project = ? AND filename = ?', (doc['project'], doc['filename'])).fetchone()[0])
            # ... verify the size
            if current_project_size - current_file_size + len(doc['content']) > max_project_size:
                raise web.HTTPRequestEntityTooLarge(max_project_size - current_project_size + current_file_size, len(doc['content']))  # HTTPInsufficientStorage has no hint

        # Verify that there is no maintenance message that may prevent the file from being saved
        if self._readEnv(sql, 'maintenance') is not None:
            raise web.HTTPServiceUnavailable()

        # At last, verify that the document doesn't exist yet (not related to a given page)
        forcedId = None
        sql.execute(''' SELECT id, page
                        FROM documents
                        WHERE project  = ?
                          AND filename = ?''',
                    (doc['project'], doc['filename']))
        row = sql.fetchone()
        if row is None:
            pass                                # New document = Create it
        else:
            if row[1] == doc['page']:           # Existing document = Delete + Keep same ID (replace it)
                try:
                    fn = (PWIC_DOCUMENTS_PATH % doc['project']) + doc['filename']
                    os.remove(fn)
                except Exception:
                    if os.path.isfile(fn):
                        raise web.HTTPInternalServerError()
                sql.execute('DELETE FROM documents WHERE id = ?', (row[0], ))
                forcedId = row[0]
            else:
                raise web.HTTPBadRequest()      # Existing document on another page = do nothing

        # Upload the file on the server
        try:
            f = open((PWIC_DOCUMENTS_PATH % doc['project']) + doc['filename'], 'wb')
            f.write(doc['content'])
            f.close()
        except Exception:  # OSError mainly
            raise web.HTTPInternalServerError()

        # Create the document in the database
        dt = _dt()
        sql.execute(''' INSERT INTO documents (id, project, page, filename, mime,
                                               size, hash, author, date, time)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (forcedId, doc['project'], doc['page'], doc['filename'],
                     doc['mime'], len(doc['content']), _sha256(doc['content'], salt=False),
                     user, dt['date'], dt['time']))
        assert(sql.rowcount > 0)
        pwic_audit(sql, {'author': user,
                         'event': '%s-document' % ('create' if forcedId is None else 'replace'),
                         'project': doc['project'],
                         'page': doc['page'],
                         'revision': current_revision,
                         'string': doc['filename']},
                   request, commit=True)
        raise web.HTTPOk()

    async def api_document_list(self, request):
        ''' Return the list of the attached documents '''
        # Verify that the user is connected
        session = PwicSession(request)
        user = await session.getUser()
        if user == '':
            raise web.HTTPUnauthorized()

        # Read the parameters
        post = await self._handlePost(request)
        project = post.get('project', '')
        page = post.get('page', '')
        if '' in [project, page]:
            raise web.HTTPBadRequest()

        # Read the documents
        sql = app['sql'].cursor()
        sql.execute(''' SELECT b.id, b.filename, b.mime, b.size, b.hash, b.author, b.date, b.time
                        FROM roles AS a
                            INNER JOIN documents AS b
                                ON  b.project = a.project
                                AND b.page    = ?
                        WHERE a.project = ?
                          AND a.user    = ?
                        ORDER BY b.filename''',
                    (page, project, user))
        result = []
        for row in sql.fetchall():
            result.append({'id': row[0],
                           'filename': row[1],
                           'mime': row[2],
                           'mime_icon': self._mime2icon(row[2]),
                           'size': _size2str(row[3]),
                           'hash': row[4],
                           'author': row[5],
                           'date': row[6],
                           'time': row[7]})
        return web.Response(text=json.dumps(result), content_type='application/json')

    async def api_ping(self, request):
        ''' Notify if the session is still alive '''
        session = PwicSession(request)
        text = 'KO' if await session.getUser() == '' else 'OK'
        return web.Response(text=text, content_type='text/plain')


# ====================
#  Server entry point
# ====================

app = None


def main():
    global app

    # Command-line
    parser = argparse.ArgumentParser(description='Pwic Server')
    parser.add_argument('--host', default='127.0.0.1', help='Listening host')
    parser.add_argument('--port', type=int, default=1234, help='Listening port')
    parser.add_argument('--ssl', action='store_true', help='Enable HTTPS')
    args = parser.parse_args()

    # SSL binding
    if args.ssl:
        https = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            https.load_cert_chain(PWIC_PUBLIC_KEY, PWIC_PRIVATE_KEY)
        except FileNotFoundError:
            print('Warning: invalid certificates. Switching to the unsecure mode')
            https = None
    else:
        https = None

    # Modules
    app = web.Application()
    app['jinja'] = Environment(loader=FileSystemLoader('./templates/'))
    app['markdown'] = Markdown(extras=['tables', 'footnotes', 'fenced-code-blocks'], safe_mode=True)
    app['pwic'] = PwicServer()
    app['sql'] = sqlite3.connect('./db/pwic.sqlite')
    # app['sql'].set_trace_callback(print)
    app['ssl'] = https is not None
    setup(app, EncryptedCookieStorage(base64.urlsafe_b64decode(fernet.Fernet.generate_key())))  # Storage for cookies

    # Routes
    app.router.add_static('/static/', path='./static/')
    app.add_routes([web.post('/api/logon', app['pwic'].api_logon),
                    web.get('/api/logout', app['pwic'].api_logout),
                    web.post('/api/page/create', app['pwic'].api_page_create),
                    web.post('/api/page/update', app['pwic'].api_page_update),
                    web.post('/api/user/create', app['pwic'].api_user_create),
                    web.post('/api/user/change-password', app['pwic'].api_user_change_password),
                    web.post('/api/roles', app['pwic'].api_roles),
                    web.post('/api/markdown', app['pwic'].api_markdown),
                    web.post('/api/document/create', app['pwic'].api_document_create),
                    web.post('/api/document/list', app['pwic'].api_document_list),
                    web.post('/api/ping', app['pwic'].api_ping),
                    web.get('/special/help', app['pwic'].page_help),
                    web.get('/special/create-project', app['pwic'].page_help),
                    web.get('/special/create-page', app['pwic'].page_create),
                    web.get('/special/create-user', app['pwic'].user_create),
                    web.get('/special/user/{userpage}', app['pwic'].page_user),
                    web.get(r'/{project:[^\/]+}/special/search', app['pwic'].page_search),
                    web.get(r'/{project:[^\/]+}/special/roles', app['pwic'].page_roles),
                    web.get(r'/{project:[^\/]+}/special/links', app['pwic'].page_links),
                    web.get(r'/{project:[^\/]+}/special/export', app['pwic'].project_export),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}/rev{new_revision:[0-9]+}/compare/rev{old_revision:[0-9]+}', app['pwic'].page_compare),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}/rev{revision:[0-9]+}/validate', app['pwic'].api_page_validate),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}/rev{revision:[0-9]+}/delete', app['pwic'].api_page_delete),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}/rev{revision:[0-9]+}', app['pwic'].page),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}/{action:view|edit|history}', app['pwic'].page),
                    web.get(r'/special/document/{id:[0-9]+}/{dummy:[^\/]+}', app['pwic'].document_get),
                    web.get(r'/special/document/{id:[0-9]+}', app['pwic'].document_get),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}', app['pwic'].page),
                    web.get(r'/{project:[^\/]+}', app['pwic'].page),
                    web.get('/', app['pwic'].page)])

    # Initialization
    sql = app['sql'].cursor()
    sql.execute('PRAGMA optimize')
    pwic_audit(sql, {'author': PWIC_USER,
                     'event': 'start-server'},
               commit=True)
    del sql

    # Launch the server
    web.run_app(app, host=args.host, port=args.port, ssl_context=https)


main()
