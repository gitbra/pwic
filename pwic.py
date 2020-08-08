#!/usr/bin/env python

import argparse
import ssl
from aiohttp import web
from aiohttp_session import setup, get_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from jinja2 import Environment, FileSystemLoader
from markdown2 import Markdown
from difflib import HtmlDiff
import sqlite3
from cryptography import fernet
from urllib.parse import parse_qs
import re
import base64
import time

from pwic_lib import PWIC_USER, PWIC_DEFAULT_PASSWORD, PWIC_EMOJIS, \
    _, _x, _xb, _int, _dt, _sha256, \
    pwic_extended_syntax, pwic_audit, pwic_search_parse, pwic_search_tostring


# ===============
#  Documentation
#   - Jinja2 :          http://zetcode.com/python/jinja/
#   - Markdown :        https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet
#   - HTTP codes :      https://docs.pylonsproject.org/projects/pyramid/en/latest/api/httpexceptions.html
#   - SSL :             https://stackoverflow.com/questions/51645324/how-to-setup-a-aiohttp-https-server-and-client/51646535
#   - PyParsing :       https://github.com/pyparsing/pyparsing/blob/master/examples/searchparser.py
#   - Parsimonious :    https://github.com/erikrose/parsimonious
#                       http://zderadicka.eu/writing-simple-parser-in-python/
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
        if (session is not None) and ('data' in session):
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
    def __init__(self):
        self.request = None

    def _audit(self, sql, object, commit=False):
        return pwic_audit(sql, object, self.request, commit)

    def _md2html(self, markdown):
        return app['markdown'].convert(pwic_extended_syntax(markdown))

    async def _handlePost(self):
        ''' Return the POST as a readable object.get() '''
        result = {}
        if self.request.body_exists:
            data = await self.request.text()
            result = parse_qs(data)
            for res in result:
                result[res] = result[res][0]
        return result

    async def _handleOutput(self, name, pwic):
        ''' Serve the right template, in the right language, with the right PWIC structure and additional data '''
        template = app['jinja'].get_template('en/%s.html' % name)
        session = PwicSession(self.request)
        pwic['user'] = await session.getUser()
        pwic['ssl'] = app['ssl']
        pwic['emojis'] = PWIC_EMOJIS
        return web.Response(text=template.render(pwic=pwic), content_type='text/html')

    async def _handleLogon(self):
        ''' Show the logon page '''
        return await self._handleOutput('logon', {'title': _('Connect to Pwic')})

    async def page(self, request):
        ''' Serve the pages '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon()

        # Show the requested page
        project = self.request.match_info.get('project', '')
        page = self.request.match_info.get('page', 'home')
        revision = self.request.match_info.get('revision', None)
        action = self.request.match_info.get('action', 'view')
        sql = app['sql'].cursor()
        pwic = {'title': 'Wiki',
                'project': project,
                'page': page,
                'revision': revision,
                'special': page == 'special'}
        dt = _dt()

        # Fetch the name of the project...
        if project != '':
            sql.execute('   SELECT b.description, a.admin, a.manager, a.editor, a.validator, a.reader   \
                            FROM roles AS a                                                             \
                                INNER JOIN projects AS b                                                \
                                    ON b.project = a.project                                            \
                            WHERE a.project = ?                                                         \
                              AND a.user = ?                                                            \
                            LIMIT 1', (project, user))
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
            sql.execute('   SELECT a.project, a.description         \
                            FROM projects AS a                      \
                                INNER JOIN roles AS b               \
                                    ON  b.project = a.project       \
                                    AND b.user = ?                  \
                            ORDER BY a.description', (user, ))
            pwic['title'] = _('Select your project')
            pwic['projects'] = []
            for row in sql.fetchall():
                pwic['projects'].append({'project': row[0], 'description': row[1]})
            return await self._handleOutput('select-project', pwic)

        # Fetch the links of the header line
        sql.execute('   SELECT a.page, a.title          \
                        FROM pages AS a                 \
                        WHERE a.project = ?             \
                          AND a.header = "X"            \
                        ORDER BY a.title', (project, ))
        pwic['links'] = []
        for row in sql.fetchall():
            pwic['links'].append({'project': project,
                                  'page': row[0],
                                  'title': row[1]})
            if row[0] == 'home':
                pwic['links'].insert(0, pwic['links'].pop())    # Push to top of list because it is the home page !

        # Fetch the name of the page
        if page != '':
            if page == 'special':
                row = ['Special']
            else:
                sql.execute('   SELECT title            \
                                FROM pages              \
                                WHERE project = ?       \
                                  AND page    = ?       \
                                  AND latest  = "X"',
                            (project, page))
                row = sql.fetchone()
                if row is None:
                    raise web.HTTPNotFound()  # Page not found
            pwic['page_title'] = row[0]

        # Show the requested page (not necessarily the latest one)
        if page != '' and action == 'view':
            if page != 'special':
                sql.execute('   SELECT revision, latest, draft, final, protection,  \
                                       author, date, time, title, markdown,         \
                                       valuser, valdate, valtime                    \
                                FROM pages                                          \
                                WHERE project = ? AND page = ?                      \
                                ORDER BY revision DESC', (project, page))
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
                pwic['html'] = self._md2html(row[9])
                pwic['valuser'] = row[10]
                pwic['valdate'] = row[11]
                pwic['valtime'] = row[12]
                pwic['removable'] = (pwic['admin'] and not pwic['final'] and (pwic['valuser'] == '')) or ((pwic['author'] == user) and pwic['draft'])

            # Additional information for the special page
            else:
                # Fetch the recently updated pages
                sql.execute('   SELECT page, author, date, time, title, comment     \
                                FROM pages                                          \
                                WHERE project = ?                                   \
                                  AND latest  = "X"                                 \
                                  AND date   >= ?                                   \
                                ORDER BY date DESC, time DESC',
                            (project, dt['date-30d']))
                pwic['recents'] = []
                for row in sql.fetchall():
                    pwic['recents'].append({'page': row[0],
                                            'author': row[1],
                                            'date': row[2],
                                            'time': row[3],
                                            'title': row[4],
                                            'comment': row[5]})

                # Fetch the team members of the project
                sql.execute('SELECT user, admin, manager, editor, validator, reader     \
                             FROM roles                                                 \
                             WHERE project = ?                                          \
                             ORDER BY admin     DESC,                                   \
                                      manager   DESC,                                   \
                                      editor    DESC,                                   \
                                      validator DESC,                                   \
                                      reader    DESC,                                   \
                                      user      ASC', (project, ))
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
                    sql.execute('   SELECT a.user                                   \
                                    FROM roles AS a                                 \
                                        LEFT JOIN (                                 \
                                            SELECT author, MAX(date) AS date        \
                                            FROM audit                              \
                                            WHERE date >= ?                         \
                                              AND ( project = ?                     \
                                                 OR event IN ("logon", "logout")    \
                                              )                                     \
                                            GROUP BY author                         \
                                        ) AS b                                      \
                                            ON b.author = a.user                    \
                                    WHERE a.project = ?                             \
                                      AND b.date IS NULL                            \
                                    ORDER BY a.user',
                                (dt['date-30d'], project, project))
                    pwic['inactive_users'] = []
                    for row in sql.fetchall():
                        pwic['inactive_users'].append(row[0])

                # Fetch the pages of the project
                sql.execute('   SELECT page, title, revision, final, author,    \
                                       date, time, valuser, valdate, valtime    \
                                FROM pages                                      \
                                WHERE project = ?                               \
                                  AND latest  = "X"                             \
                                ORDER BY page ASC, revision DESC', (project, ))
                pwic['pages'] = []
                for row in sql.fetchall():
                    pwic['pages'].append({'page': row[0],
                                          'title': row[1],
                                          'revision': row[2],
                                          'final': row[3],
                                          'author': row[4],
                                          'date': row[5],
                                          'time': row[6],
                                          'valuser': row[7],
                                          'valdate': row[8],
                                          'valtime': row[9]})

                # Audit log
                if pwic['admin']:
                    sql.execute('   SELECT date, time, author, event,       \
                                           user, project, page, revision    \
                                    FROM audit                              \
                                    WHERE project = ?                       \
                                      AND date   >= ?                       \
                                    ORDER BY date DESC, time DESC',
                                (project, dt['date-30d']))
                    pwic['audits'] = []
                    for row in sql.fetchall():
                        pwic['audits'].append({'date': row[0],
                                               'time': row[1],
                                               'author': row[2],
                                               'event': row[3],
                                               'user': row[4],
                                               'project': row[5],
                                               'page': row[6],
                                               'revision': row[7]})

            # Output
            return await self._handleOutput('page', pwic)

        # Edit the requested page
        if page != '' and action == 'edit':
            sql.execute('   SELECT draft, final, header, protection, title, markdown    \
                            FROM pages                                                  \
                            WHERE project = ?                                           \
                              AND page    = ?                                           \
                              AND latest  = "X"', (project, page))
            row = sql.fetchone()
            if row is None:
                raise web.HTTPNotFound()        # Page not found
            pwic['draft'] = _xb(row[0])
            pwic['final'] = _xb(row[1])
            pwic['header'] = _xb(row[2])
            pwic['protection'] = _xb(row[3])
            pwic['title'] = row[4]
            pwic['markdown'] = row[5]
            return await self._handleOutput('page-edit', pwic)

        # Show the history of the page
        if page != '' and action == 'history':
            sql.execute('   SELECT revision, latest, draft, final, author, date, time,  \
                                   title, comment, valuser, valdate, valtime            \
                            FROM pages                                                  \
                            WHERE project = ? AND page = ?                              \
                            ORDER BY revision DESC', (project, page))
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
                                          'valuser': row[9],
                                          'valdate': row[10],
                                          'valtime': row[11]})
            pwic['title'] = _('Revisions of the page')
            return await self._handleOutput('page-history', pwic)

        # Default output if nothing was done before
        raise web.HTTPNotFound()

    async def page_help(self, request):
        ''' Serve the help page to any user '''
        self.request = request
        return await self._handleOutput('help', {'title': _('Help for Pwic')})

    async def page_create(self, request):
        ''' Serve the page to create a new page '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon()

        # Fetch the projects where the user can add pages
        pwic = {'title': _('Create a page'),
                'projects': []}
        sql = app['sql'].cursor()
        sql.execute('   SELECT a.project, b.description         \
                        FROM roles AS a                         \
                            INNER JOIN projects AS b            \
                                ON b.project = a.project        \
                        WHERE a.user    = ?                     \
                          AND a.manager = "X"', (user, ))
        for row in sql.fetchall():
            pwic['projects'].append({'project': row[0],
                                     'description': row[1]})

        # Show the page
        return await self._handleOutput('page-create', pwic=pwic)

    async def user_create(self, request):
        ''' Serve the page to create a new user '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon()

        # Fetch the projects where users can be created
        pwic = {'title': _('Create a user'),
                'projects': []}
        sql = app['sql'].cursor()
        sql.execute('   SELECT a.project, b.description         \
                        FROM roles AS a                         \
                            INNER JOIN projects AS b            \
                                ON b.project = a.project        \
                        WHERE a.user  = ?                       \
                          AND a.admin = "X"', (user, ))
        for row in sql.fetchall():
            pwic['projects'].append({'project': row[0],
                                     'description': row[1]})

        # Show the page
        return await self._handleOutput('user-create', pwic=pwic)

    async def page_user(self, request):
        ''' Serve the page to view the profile of a user '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon()

        # Fetch the information of the user
        sql = app['sql'].cursor()
        userpage = self.request.match_info.get('userpage', None)
        sql.execute('SELECT initial FROM users WHERE user = ?', (userpage, ))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPNotFound()    # User does not exist
        pwic = {'title': _('User profile'),
                'user': user,
                'userpage': userpage,
                'initial_password': _xb(row[0]),
                'projects': [],
                'pages': []}

        # Fetch the commonly-accessible projects assigned to the user
        sql.execute('   SELECT a.project                    \
                        FROM roles AS a                     \
                            INNER JOIN roles AS b           \
                                ON  b.project = a.project   \
                                AND b.user    = ?           \
                        WHERE a.user = ?                    \
                        ORDER BY a.project',
                    (user, userpage))
        for row in sql.fetchall():
            pwic['projects'].append(row[0])

        # Fetch the latest pages updated by the selected user
        sql.execute('   SELECT b.project, b.page, b.revision, b.final,  \
                               b.date, b.time, b.title, b.valuser       \
                        FROM roles AS a                                 \
                            INNER JOIN pages AS b                       \
                                ON  b.project = a.project               \
                                AND b.latest  = "X"                     \
                                AND b.author  = ?                       \
                        WHERE a.user = ?                                \
                        ORDER BY b.date DESC, b.time DESC', (userpage, user))
        for row in sql.fetchall():
            pwic['pages'].append({'project': row[0],
                                  'page': row[1],
                                  'revision': row[2],
                                  'final': row[3],
                                  'date': row[4],
                                  'time': row[5],
                                  'title': row[6],
                                  'valuser': row[7]})

        # Show the page
        return await self._handleOutput('user', pwic=pwic)

    async def page_search(self, request):
        ''' Serve the search engine '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon()

        # Parse the query
        project = self.request.match_info.get('project', '')
        terms = self.request.rel_url.query.get('q', '')
        query = pwic_search_parse(terms)
        if query is None:
            raise web.HTTPBadRequest()

        # Fetch the pages
        sql = app['sql'].cursor()
        pwic = {'title': _('Search'),
                'project': project,
                'terms': pwic_search_tostring(query),
                'results': []}

        # Description of the project
        sql.execute('   SELECT description FROM projects WHERE project = ?', (project, ))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPNotFound()
        pwic['project_description'] = row[0]

        # Search
        sql.execute('   SELECT b.project, b.page, b.draft, b.final, b.author,   \
                               b.date, b.time, b.title,                         \
                               LOWER(b.markdown) AS markdown, b.valuser         \
                        FROM roles AS a                                         \
                            INNER JOIN pages AS b                               \
                                ON  b.project = a.project                       \
                                AND b.latest  = "X"                             \
                            INNER JOIN projects AS c                            \
                                ON  c.project = a.project                       \
                        WHERE a.project = ?                                     \
                          AND a.user    = ?                                     \
                        ORDER BY b.date DESC,                                   \
                                 b.time DESC',
                    (project, user))
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
        return await self._handleOutput('search', pwic=pwic)

    async def page_roles(self, request):
        ''' Serve the search engine '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon()

        # Fetch the roles
        sql = app['sql'].cursor()
        project = self.request.match_info.get('project', '')
        sql.execute('   SELECT a.user, c.initial, a.admin, a.manager,   \
                               a.editor, a.validator, a.reader          \
                        FROM roles AS a                                 \
                            INNER JOIN roles AS b                       \
                                ON  b.project = a.project               \
                                AND b.user    = ?                       \
                                AND b.admin   = "X"                     \
                            INNER JOIN users AS c                       \
                                ON  c.user    = a.user                  \
                        WHERE a.project = ?                             \
                        ORDER BY a.user',
                    (user, project))

        # Show the page
        pwic = {'title': _('Roles'),
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
            return await self._handleOutput('user-roles', pwic=pwic)

    async def page_links(self, request):
        ''' Serve the check of the links '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon()

        # Fetch the pages
        sql = app['sql'].cursor()
        project = self.request.match_info.get('project', '')
        sql.execute('   SELECT b.page, b.header, b.markdown     \
                        FROM roles AS a                         \
                            INNER JOIN pages AS b               \
                                ON  b.project = a.project       \
                                AND b.latest  = "X"             \
                        WHERE   a.project = ?                   \
                          AND   a.user    = ?                   \
                          AND ( a.admin   = "X"                 \
                             OR a.manager = "X" )               \
                        ORDER BY b.page',
                    (project, user))

        # Extract the links between the pages
        ok = False
        reg_page = re.compile(r'\]\(\/([a-z0-9_\-\.]+)\/([a-z0-9_\-\.]+)\)', re.IGNORECASE)
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
            subpages = reg_page.findall(row[2])
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
        return await self._handleOutput('links', pwic=pwic)

    async def page_compare(self, request):
        ''' Serve the page that compare two revisions '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon()

        # Fetch the pages
        sql = app['sql'].cursor()
        project = self.request.match_info.get('project', '')
        page = self.request.match_info.get('page', '')
        new_revision = _int(self.request.match_info.get('new_revision', ''))
        old_revision = _int(self.request.match_info.get('old_revision', ''))
        sql.execute('   SELECT d.description,                   \
                               b.title,                         \
                               b.markdown AS new_markdown,      \
                               c.markdown AS old_markdown       \
                        FROM roles AS a                         \
                            INNER JOIN pages AS b               \
                                ON  b.project  = a.project      \
                                AND b.page     = ?              \
                                AND b.revision = ?              \
                            INNER JOIN pages AS c               \
                                ON  c.project  = b.project      \
                                AND c.page     = b.page         \
                                AND c.revision = ?              \
                            INNER JOIN projects AS d            \
                                ON  d.project  = a.project      \
                        WHERE a.project = ?                     \
                          AND a.user    = ?',
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

        pwic = {'title': _('Comparison'),
                'project': project,
                'project_description': row[0],
                'page': page,
                'page_title': row[1],
                'new_revision': new_revision,
                'old_revision': old_revision,
                'diff': _diff(row[3], row[2])}
        return await self._handleOutput('page-compare', pwic=pwic)

    async def api_logon(self, request):
        ''' API to log on people '''
        self.request = request

        # Destroy the current session
        session = PwicSession(self.request)
        await session.destroy()

        # Fetch the submitted data
        ok = False
        post = await self._handlePost()
        if ('logon_user' in post) and ('logon_password' in post):
            user = post.get('logon_user', 'anonymous').lower().strip()
            pwd = _sha256(post.get('logon_password', ''))
            if '' not in [user, pwd]:
                # Verify the credentials
                sql = app['sql'].cursor()
                sql.execute('   SELECT count(user) AS total         \
                                FROM users                          \
                                WHERE user     = ?                  \
                                  AND password = ?', (user, pwd))
                ok = sql.fetchone()[0] == 1

                # Update the session
                if ok:
                    data = session.getDefaultData()
                    data['user'] = user
                    session = await session.getSession()
                    session['data'] = data
                    self._audit(sql, {'author': user,
                                      'event': 'logon'},
                                commit=True)

        # Final redirection
        raise web.HTTPFound('/' if ok else '/?failed')

    async def api_logout(self, request):
        ''' API to log out '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user != '':
            await session.destroy()
            self._audit(app['sql'].cursor(), {'author': user,
                                              'event': 'logout'},
                        commit=True)
        return await self._handleOutput('logout', {'title': _('Disconnected from Pwic')})

    async def api_page_create(self, request):
        ''' API to create a new page '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon()

        # Fetch the submitted data
        reg_page = re.compile(r'^[a-z0-9_\-\.]+$', re.IGNORECASE)
        post = await self._handlePost()
        project = post.get('create_project', '').lower().strip()
        page = post.get('create_page', '').lower().strip()
        if '' in [project, page] or reg_page.match(page) is None or page in ['admin', 'special']:
            raise web.HTTPBadRequest()

        # Verify that the user is manager of the provided project, and that the page doesn't exist yet
        ok = False
        sql = app['sql'].cursor()
        sql.execute('   SELECT b.page                       \
                        FROM roles AS a                     \
                            LEFT OUTER JOIN pages AS b      \
                                ON  b.project = a.project   \
                                AND b.page = ?              \
                        WHERE a.project = ?                 \
                          AND a.user = ?                    \
                          AND a.manager = "X"',
                    (page, project, user))
        row = sql.fetchone()
        if row is not None and row[0] is None:
            ok = True

        # Handle the creation of the page
        if not ok:
            raise web.HTTPFound('/special/create-page?failed')
        else:
            dt = _dt()
            revision = 1
            sql.execute("   INSERT INTO pages (project, page, revision, author, date, time, title, markdown, comment)   \
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (project, page, revision, user, dt['date'], dt['time'], page, ('# ' + page), _('Initial')))
            if sql.rowcount > 0:
                self._audit(sql, {'author': user,
                                  'event': 'create-page',
                                  'project': project,
                                  'page': page,
                                  'revision': revision})
            sql.execute('COMMIT')
            raise web.HTTPFound('/%s/%s?success' % (project, page))

    async def api_page_update(self, request):
        ''' API to update an existing page '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost()
        project = post.get('edit_project', '')
        page = post.get('edit_page', '')
        title = post.get('edit_title', '')
        markdown = post.get('edit_markdown', '')
        comment = post.get('edit_comment', '')
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
        sql.execute('   SELECT b.revision, b.header, b.protection, a.manager    \
                        FROM roles AS a                                         \
                            INNER JOIN pages AS b                               \
                                ON  b.project = a.project                       \
                                AND b.page    = ?                               \
                                AND b.latest  = "X"                             \
                        WHERE a.project = ?                                     \
                          AND a.user = ?                                        \
                          AND ( a.manager = "X"                                 \
                             OR a.editor  = "X" )',
                    (page, project, user))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPUnauthorized()        # Or not found which is normally unlikely
        revision = row[0]
        manager = _xb(row[3])
        if not manager:
            if _xb(row[2]):                     # Protected pages can be updated by the managers only
                raise web.HTTPUnauthorized()
            protection = ''                     # This field cannot be set by the non-managers
            header = row[1]                     # This field is reserved to the managers, so we keep the existing value

        # Create the new entry
        sql.execute('   INSERT INTO pages                                       \
                            (project, page, revision, draft, final, header,     \
                             protection, author, date, time, title,             \
                             markdown, comment)                                 \
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    (project, page, revision + 1, draft, final, header,
                     protection, user, dt['date'], dt['time'], title,
                     markdown, comment))
        if sql.rowcount > 0:
            self._audit(sql, {'author': user,
                              'event': 'update-page',
                              'project': project,
                              'page': page,
                              'revision': revision + 1})

            # Remove the own drafts
            if final:
                sql.execute('   DELETE FROM pages       \
                                WHERE project   = ?     \
                                  AND page      = ?     \
                                  AND revision <= ?     \
                                  AND author    = ?     \
                                  AND draft     = "X"   \
                                  AND final     = ""    \
                                  AND valuser   = ""',
                            (project, page, revision, user))
                if sql.rowcount > 0:
                    self._audit(sql, {'author': user,
                                      'event': 'delete-drafts',
                                      'project': project,
                                      'page': page,
                                      'revision': revision + 1,
                                      'count': sql.rowcount})

            # Purge the old flags
            sql.execute('   UPDATE pages            \
                            SET header = "",        \
                                latest = ""         \
                            WHERE project   = ?     \
                              AND page      = ?     \
                              AND revision <= ?',
                        (project, page, revision))
            sql.execute('COMMIT')
        raise web.HTTPFound('/%s/%s?success' % (project, page))

    async def api_page_validate(self, request):
        ''' Validate the pages '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the revision to validate
        project = self.request.match_info.get('project', '')
        page = self.request.match_info.get('page', 'home')
        revision = _int(self.request.match_info.get('revision', 0))

        # Verify that it is possible to validate the page
        sql = app['sql'].cursor()
        sql.execute('   SELECT b.page                       \
                        FROM roles AS a                     \
                            INNER JOIN pages AS b           \
                                ON  b.project = a.project   \
                                AND b.page = ?              \
                                AND b.revision = ?          \
                                AND b.final = "X"           \
                                AND b.valuser = ""          \
                            INNER JOIN users AS c           \
                                ON  c.user = a.user         \
                                AND c.initial <> "X"        \
                        WHERE a.project = ?                 \
                          AND a.user = ?                    \
                          AND a.validator = "X"', (page, revision, project, user))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPUnauthorized()

        # Update the page
        dt = _dt()
        sql.execute('   UPDATE pages                                        \
                        SET valuser = ?, valdate = ?, valtime = ?           \
                        WHERE project = ? AND page = ? AND revision = ?',
                    (user, dt['date'], dt['time'], project, page, revision))
        self._audit(sql, {'author': user,
                          'event': 'validate-page',
                          'project': project,
                          'page': page,
                          'revision': revision})
        sql.execute('COMMIT')
        raise web.HTTPFound('/%s/%s/rev%d?success' % (project, page, revision))

    async def api_page_delete(self, request):
        ''' Delete a page upon administrative request '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the revision to delete
        project = self.request.match_info.get('project', '')
        page = self.request.match_info.get('page', '')
        revision = _int(self.request.match_info.get('revision', 0))

        # Verify the preconditions
        sql = app['sql'].cursor()
        sql.execute('   SELECT a.header                     \
                        FROM pages AS a                     \
                            INNER JOIN roles AS b           \
                                ON  b.project = a.project   \
                                AND b.user    = ?           \
                        WHERE a.project  = ?                \
                          AND a.page     = ?                \
                          AND a.revision = ?                \
                          AND ((    b.admin   = "X"         \
                                AND a.final   = ""          \
                                AND a.valuser = ""          \
                            ) OR (  b.user    = a.author    \
                                AND a.draft   = "X"         \
                            ))',
                    (user, project, page, revision))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPUnauthorized()
        header = row[0]

        # Delete the page
        sql.execute('   DELETE FROM pages           \
                        WHERE project = ?           \
                          AND page = ?              \
                          AND revision = ?',
                    (project, page, revision))
        self._audit(sql, {'author': user,
                          'event': 'delete-revision',
                          'project': project,
                          'page': page,
                          'revision': revision})
        if revision > 1:
            # Find the latest revision that is not necessarily "revision - 1"
            sql.execute('   SELECT MAX(revision)    \
                            FROM pages              \
                            WHERE project   = ?     \
                              AND page      = ?     \
                              AND revision <> ?',
                        (project, page, revision))
            row = sql.fetchone()
            assert(row is not None)
            if row[0] < revision:
                sql.execute('UPDATE pages SET latest = "X", header = ? WHERE project = ? AND page = ? AND revision = ?',
                            (header, project, page, row[0]))
        sql.execute('COMMIT')

        # Redirection
        if revision == 1:
            raise web.HTTPFound('/%s?success' % project)  # The page itself is deleted
        else:
            raise web.HTTPFound('/%s/%s?success' % (project, page))

    async def api_user_create(self, request):
        ''' API to create a new user '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            return await self._handleLogon()

        # Fetch the submitted data
        reg_user = re.compile(r'^[a-z0-9_\-\.@]+$', re.IGNORECASE)
        post = await self._handlePost()
        project = post.get('create_project', '').lower().strip()
        newuser = post.get('create_user', '').lower().strip()
        if '' in [project, newuser] or reg_user.match(newuser) is None or (newuser[:4] == 'pwic'):
            raise web.HTTPBadRequest()

        # Verify that the user is administrator of the provided project
        ok = False
        sql = app['sql'].cursor()
        sql.execute('   SELECT user FROM roles      \
                        WHERE project = ?           \
                          AND user    = ?           \
                          AND admin   = "X"',
                    (project, user))
        if sql.fetchone() is None:
            raise web.HTTPUnauthorized()

        # Create the new user
        sql.execute('   INSERT INTO users (user, password)      \
                        SELECT ?, ?                             \
                        WHERE NOT EXISTS ( SELECT 1 FROM users WHERE user = ? )',
                    (newuser, _sha256(PWIC_DEFAULT_PASSWORD), newuser))
        if sql.rowcount > 0:
            self._audit(sql, {'author': user,
                              'event': 'create-user',
                              'user': newuser})

        # Grant the default rights as reader
        sql.execute('   INSERT INTO roles (project, user, reader)   \
                        SELECT ?, ?, "X"                            \
                        WHERE NOT EXISTS ( SELECT 1 FROM roles WHERE project = ? AND user = ? )',
                    (project, newuser, project, newuser))
        if sql.rowcount > 0:
            ok = True
            self._audit(sql, {'author': user,
                              'event': 'grant-reader',
                              'project': project,
                              'user': newuser})
        sql.execute('COMMIT')
        raise web.HTTPFound('/%s/special/roles?%s' % (project, 'success' if ok else 'failed'))

    async def api_user_change_password(self, request):
        ''' Change the password of the current user '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the posted values
        ok = False
        post = await self._handlePost()
        current = post.get('user_password_current', '')
        new1 = post.get('user_password_new1', '')
        new2 = post.get('user_password_new2', '')
        if '' not in [current, new1, new2] and (new1 == new2):

            # Verify the current password
            sql = app['sql'].cursor()
            sql.execute('   SELECT user FROM users \
                            WHERE user = ? AND password = ?', (user, _sha256(current)))
            if sql.fetchone() is not None:
                # Update the password
                sql.execute('UPDATE users SET initial = "", password = ? WHERE user = ?', (_sha256(new1), user))
                if sql.rowcount > 0:
                    self._audit(sql, {'author': user,
                                      'event': 'change-password',
                                      'user': user})
                sql.execute('COMMIT')
                ok = True

        # Redirection
        ok = 'success' if ok else 'failed'
        raise web.HTTPFound('/special/user/%s?%s' % (user, ok))

    async def api_roles(self, request):
        ''' Change the roles of a user '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        user = await session.getUser()
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the posted values
        post = await self._handlePost()
        project = post.get('project', '')
        userpost = post.get('user', '')
        roles = ['admin', 'manager', 'editor', 'validator', 'reader', 'drop']
        try:
            roleid = roles.index(post.get('role', ''))
            drop = roles[roleid] == 'drop'
        except ValueError:
            raise web.HTTPBadRequest()

        # Select the current rights of the user
        sql = app['sql'].cursor()
        sql.execute('   SELECT a.user, a.admin, a.manager, a.editor,    \
                               a.validator, a.reader, c.initial         \
                        FROM roles AS a                                 \
                            INNER JOIN roles AS b                       \
                                ON  b.project = a.project               \
                                AND b.user    = ?                       \
                                AND b.admin   = "X"                     \
                            INNER JOIN users AS c                       \
                                ON  c.user    = a.user                  \
                        WHERE a.project = ?                             \
                          AND a.user    = ?',
                    (user, project, userpost))
        row = sql.fetchone()
        if row is None or (not drop and row[6] == 'X'):
            raise web.HTTPUnauthorized()

        # Drop a user
        if drop:
            sql.execute('   DELETE FROM roles       \
                            WHERE project = ?       \
                              AND user    = ?       \
                              AND user   <> ?',
                        (project, userpost, user))
            if sql.rowcount > 0:
                self._audit(sql, {'author': user,
                                  'event': 'drop-user',
                                  'project': project,
                                  'user': userpost})
                sql.execute('COMMIT')
                return web.Response(text='OK', content_type='text/plain')
            else:
                raise web.HTTPBadRequest()

        # New role
        else:
            newvalue = {'X': '', '': 'X'}[row[roleid + 1]]
            if roleid == 0 and newvalue != 'X' and user == userpost:
                raise web.HTTPBadRequest()      # Cannot self-ungrant admin, so there is always at least one admin on the project
            try:
                sql.execute('   UPDATE roles SET %s = ?     \
                                WHERE project = ? AND user = ?' % roles[roleid],
                            (newvalue, project, userpost))
            except sqlite3.IntegrityError:
                raise web.HTTPUnauthorized()
            if sql.rowcount == 0:
                raise web.HTTPBadRequest()
            else:
                self._audit(sql, {'author': user,
                                  'event': '%s-%s' % ('grant' if newvalue == 'X' else 'ungrant', roles[roleid]),
                                  'project': project,
                                  'user': userpost})
                sql.execute('COMMIT')
                return web.Response(text=newvalue, content_type='text/plain')

    async def api_markdown(self, request):
        ''' Return the HTML corresponding to the posted Markdown '''
        self.request = request

        # Verify that the user is connected
        session = PwicSession(self.request)
        if await session.getUser() == '':
            raise web.HTTPUnauthorized()

        # Return the converted output
        post = await self._handlePost()
        html = self._md2html(post.get('content', ''))
        return web.Response(text=html, content_type='text/plain')


# ====================
#  Server entry point
# ====================

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
        https.load_cert_chain('db/pwic_secure.crt', 'db/pwic_secure.key')
    except FileNotFoundError:
        print('Warning: invalid certificates. Generate self-signed certificates with `python pwic_genssl.py`')
        print('Switching to the unsecure mode')
        https = None
else:
    https = None

# Modules
app = web.Application()
app['jinja'] = Environment(loader=FileSystemLoader('./templates/'))
app['markdown'] = Markdown()
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
                web.get('/', app['pwic'].page),
                web.get('/special/help', app['pwic'].page_help),
                web.get('/special/create-project', app['pwic'].page_help),
                web.get('/special/create-page', app['pwic'].page_create),
                web.get('/special/create-user', app['pwic'].user_create),
                web.get(r'/special/user/{userpage:[a-z0-9_\-\.@]+}', app['pwic'].page_user),
                web.get(r'/{project:[a-z0-9_\-\.]+}/special/search', app['pwic'].page_search),
                web.get(r'/{project:[a-z0-9_\-\.]+}/special/roles', app['pwic'].page_roles),
                web.get(r'/{project:[a-z0-9_\-\.]+}/special/links', app['pwic'].page_links),
                web.get(r'/{project:[a-z0-9_\-\.]+}/{page:[a-z0-9_\-\.]+}/rev{new_revision:[0-9]+}/compare/rev{old_revision:[0-9]+}', app['pwic'].page_compare),
                web.get(r'/{project:[a-z0-9_\-\.]+}/{page:[a-z0-9_\-\.]+}/rev{revision:[0-9]+}/validate', app['pwic'].api_page_validate),
                web.get(r'/{project:[a-z0-9_\-\.]+}/{page:[a-z0-9_\-\.]+}/rev{revision:[0-9]+}/delete', app['pwic'].api_page_delete),
                web.get(r'/{project:[a-z0-9_\-\.]+}/{page:[a-z0-9_\-\.]+}/rev{revision:[0-9]+}', app['pwic'].page),
                web.get(r'/{project:[a-z0-9_\-\.]+}/{page:[a-z0-9_\-\.]+}/{action:view|edit|history}', app['pwic'].page),
                web.get(r'/{project:[a-z0-9_\-\.]+}/{page:[a-z0-9_\-\.]+}', app['pwic'].page),
                web.get(r'/{project:[a-z0-9_\-\.]+}', app['pwic'].page)])

# Initialization
sql = app['sql'].cursor()
sql.execute('PRAGMA optimize')
pwic_audit(sql, {'author': PWIC_USER,
                 'event': 'start-server'},
           commit=True)
del sql

# Launch the server
web.run_app(app, host=args.host, port=args.port, ssl_context=https)
