#!/usr/bin/env python

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
from os import listdir, urandom, remove
from os.path import getsize, isdir, isfile, join
import json
import re
import imagesize
from ipaddress import ip_network, ip_address
from bisect import insort, bisect_left
from multidict import MultiDict
from html import escape

from pwic_md import Markdown
from pwic_lib import PWIC_VERSION, PWIC_DB, PWIC_DB_SQLITE, PWIC_DOCUMENTS_PATH, PWIC_TEMPLATES_PATH, \
    PWIC_USER_ANONYMOUS, PWIC_USER_SYSTEM, PWIC_DEFAULT_PASSWORD, PWIC_DEFAULT_LANGUAGE, PWIC_DEFAULT_PAGE, \
    PWIC_DEFAULT_LOGGING_FORMAT, PWIC_PRIVATE_KEY, PWIC_PUBLIC_KEY, PWIC_ENV_PROJECT_DEPENDENT_ONLINE, \
    PWIC_ENV_PRIVATE, PWIC_EMOJIS, PWIC_CHARS_UNSAFE, PWIC_MAGIC_OAUTH, \
    PWIC_REGEX_PAGE, PWIC_REGEX_DOCUMENT, PWIC_REGEX_MIME, PWIC_REGEX_HTML_TAG, \
    MIME_BMP, MIME_JSON, MIME_GENERIC, MIME_SVG, MIME_TEXT, PWIC_MIMES, \
    _x, _xb, _attachmentName, _dt, _int, _list, _mime2icon, _randomHash, _sha256, _safeName, _safeFileName, _size2str, _sqlprint, \
    pwic_extended_syntax, pwic_audit, pwic_search_parse, pwic_search_tostring, pwic_html2odt
from pwic_styles import pwic_styles_html, pwic_styles_odt

IPR_EQ, IPR_NET, IPR_REG = range(3)


# ===============
#  Documentation
#   - Jinja2            http://zetcode.com/python/jinja/
#   - Markdown          https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet
#   - HTTP codes        https://docs.aiohttp.org/en/latest/web_exceptions.html
#                       https://docs.pylonsproject.org/projects/pyramid/en/latest/api/httpexceptions.html
#   - SSL               https://stackoverflow.com/questions/51645324/how-to-setup-a-aiohttp-https-server-and-client/51646535
#   - PyParsing         https://github.com/pyparsing/pyparsing/blob/master/examples/searchparser.py
#   - Parsimonious      https://github.com/erikrose/parsimonious
#                       http://zderadicka.eu/writing-simple-parser-in-python/
#   - HTML5 upload      https://www.smashingmagazine.com/2018/01/drag-drop-file-uploader-vanilla-js/
#                       https://css-tricks.com/drag-and-drop-file-uploading/
#                       https://docs.aiohttp.org/en/stable/multipart.html
#   - Magic bytes       https://en.wikipedia.org/wiki/List_of_file_signatures
#   - ODT               https://odfvalidator.org
#   - Colors            https://www.w3schools.com/colors/colors_picker.asp
# ===============


# ===================================================
#  This class handles the rendering of the web pages
# ===================================================

class PwicServer():
    def _commit(self: object) -> None:
        ''' Commit the current transactions '''
        app['sql'].commit()

    def _rollback(self: object) -> None:
        ''' Rollback the current transactions '''
        app['sql'].rollback()

    def _sanitizeTags(self: object, tags: str) -> str:
        ''' Reorder a list of tags written as a string '''
        return ' '.join(sorted(_list(tags.replace('#', ''))))

    def _md2html(self: object, sql: object, project: str, page: str, markdown: str, cache: bool = True, headerNumbering: bool = True) -> (str, object):
        ''' Convert the text from Markdown to HTML '''
        # Read the cache
        if page is None:
            cache = False
        if cache:
            row = sql.execute(''' SELECT html
                                  FROM cache
                                  WHERE project = ?
                                    AND page    = ?''',
                              (project, page)).fetchone()
        else:
            row = None

        # Update the cache
        if row is not None:
            html = row[0]
        else:
            html = app['markdown'].convert(markdown).replace('<span></span>', '')
            if cache:
                sql.execute('INSERT OR REPLACE INTO cache (project, page, html) VALUES (?, ?, ?)',
                            (project, page, html))
                self._commit()
        return pwic_extended_syntax(html,
                                    self._readEnv(sql, project, 'heading_mask'),
                                    headerNumbering=headerNumbering)

    def _readEnv(self: object, sql: object, project: str, name: str, default: str = None) -> str:
        ''' Read a variable from the table ENV '''
        if sql is None:
            return None
        query = "SELECT value FROM env WHERE project = ? AND key = ? AND value <> ''"
        row = None
        if project != '':
            row = sql.execute(query, (project, name)).fetchone()
        if row is None:
            row = sql.execute(query, ('', name)).fetchone()
        return default if row is None else row[0]

    def _checkMime(self: object, obj: object) -> bool:
        ''' Check the consistency of the MIME with the file signature'''
        # Check the applicable extension
        if '.' in obj['filename'] and obj['mime'] != MIME_GENERIC:
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
                            # Cast to bytearray
                            barr = bytearray()      # =bytearray(bytes.encode()) breaks the bytes sequence due to the encoding
                            for i in range(len(bytes)):
                                barr.append(ord(bytes[i]))
                            # Check the first bytes
                            if obj['content'][:len(bytes)] == barr:
                                return True
                        return False
                    break
        return obj['mime'] != ''

    def _getip(self: object, request: web.Request) -> str:
        if request is None:
            return ''
        else:
            return request.headers.get('X-Forwarded-For', request.remote) if app['xff'] else request.remote

    def _checkIP(self: object, request: web.Request) -> None:
        ''' Check if the IP address is authorized '''
        # Initialization
        okIncl = False
        hasIncl = False
        koExcl = False
        ip = self._getip(request)

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
        if koExcl or (hasIncl != okIncl):
            raise web.HTTPUnauthorized()

    async def _suser(self: object, request: web.Request) -> str:
        ''' Retrieve the logged user '''
        self._checkIP(request)
        if app['no_logon']:
            return PWIC_USER_ANONYMOUS
        else:
            session = await get_session(request)
            return session.get('user', '')

    async def _handlePost(self: object, request: web.Request) -> web.Response:
        ''' Return the POST as a readable object.get() '''
        result = {}
        if request.body_exists:
            data = await request.text()
            result = parse_qs(data)
            for res in result:
                result[res] = result[res][0]
        return result

    async def _handleLogon(self: object, request: web.Request) -> str:
        ''' Show the logon page '''
        session = await new_session(request)
        session['user_secret'] = _randomHash()
        return await self._handleOutput(request, 'logon', {'title': 'Connect to Pwic'})

    async def _handleOutput(self: object, request: web.Request, name: str, pwic: object) -> web.Response:
        ''' Serve the right template, in the right language, with the right PWIC structure and additional data '''
        pwic['user'] = await self._suser(request)
        pwic['emojis'] = PWIC_EMOJIS
        pwic['constants'] = {'anonymous_user': PWIC_USER_ANONYMOUS,
                             'db_path': PWIC_DB,
                             'default_language': PWIC_DEFAULT_LANGUAGE,
                             'changeable_env_variables': sorted(PWIC_ENV_PROJECT_DEPENDENT_ONLINE),
                             'languages': app['langs'],
                             'unsafe_chars': PWIC_CHARS_UNSAFE,
                             'version': PWIC_VERSION}

        # The project-dependent variables have the priority
        sql = app['sql'].cursor()
        sql.execute(''' SELECT project, key, value
                        FROM env
                        WHERE value <> ''
                          AND ( project = ?
                             OR project = '' )
                        ORDER BY key ASC,
                                 project DESC''',
                    (pwic.get('project', ''), ))
        pwic['env'] = {}
        for row in sql.fetchall():
            (global_, key, value) = (row[0] == '', row[1], row[2])
            if key in PWIC_ENV_PRIVATE:
                value = None
            if key not in pwic['env']:
                pwic['env'][key] = {'value': value,
                                    'global': global_}
                if key in ['max_document_size', 'max_project_size']:
                    pwic['env'][key + '_str'] = {'value': _size2str(_int(value)),
                                                 'global': global_}

        # Session
        session = await get_session(request)
        pwic['session'] = {'user_secret': session.get('user_secret', None)}

        # Render the template
        pwic['template'] = name
        pwic['args'] = request.rel_url.query
        pwic['language'] = session.get('language', PWIC_DEFAULT_LANGUAGE)
        template_name = '%s/%s.html' % (pwic['language'], name)
        if (pwic['language'] != PWIC_DEFAULT_LANGUAGE) and not isfile(PWIC_TEMPLATES_PATH + template_name):
            template_name = '%s/%s.html' % (PWIC_DEFAULT_LANGUAGE, name)
        return web.Response(text=app['jinja'].get_template(template_name).render(pwic=pwic), content_type='text/html')

    async def page(self: object, request: web.Request) -> web.Response:
        ''' Serve the pages '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Show the requested page
        project = _safeName(request.match_info.get('project', ''))
        page = _safeName(request.match_info.get('page', PWIC_DEFAULT_PAGE))
        page_special = (page == 'special')
        revision = _int(request.match_info.get('revision', 0))
        action = request.match_info.get('action', 'view')
        pwic = {'project': project,
                'page': page,
                'revision': revision}
        dt = _dt()

        # Fetch the name of the project...
        sql = app['sql'].cursor()
        if project != '':
            # Verify if the project exists
            sql.execute(''' SELECT description
                            FROM projects
                            WHERE project = ?''',
                        (project, ))
            row = sql.fetchone()
            if row is None:
                raise web.HTTPTemporaryRedirect('/')  # Project not found
            pwic['project_description'] = row[0]
            pwic['title'] = row[0]

            # Verify the access
            sql.execute(''' SELECT admin, manager, editor, validator, reader
                            FROM roles
                            WHERE project  = ?
                              AND user     = ?
                              AND disabled = '' ''',
                        (project, user))
            row = sql.fetchone()
            if row is None:
                return await self._handleOutput(request, 'project-access', pwic)  # Unauthorized users can request an access
            pwic['admin'] = _xb(row[0])
            pwic['manager'] = _xb(row[1])
            pwic['editor'] = _xb(row[2])
            pwic['validator'] = _xb(row[3])
            pwic['reader'] = _xb(row[4])
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
            pwic['projects'] = []
            for row in sql.fetchall():
                pwic['projects'].append({'project': row[0],
                                         'description': row[1]})
            if len(pwic['projects']) == 1:
                raise web.HTTPTemporaryRedirect('/%s' % pwic['projects'][0]['project'])
            else:
                return await self._handleOutput(request, 'project-select', pwic)

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
            pwic['links'].append({'page': row[0],
                                  'title': row[1]})
            if row[0] == PWIC_DEFAULT_PAGE:
                pwic['links'].insert(0, pwic['links'].pop())    # Push to top of list because it is the home page

        # Verify that the page exists
        if not page_special:
            sql.execute(''' SELECT page
                            FROM pages
                            WHERE project = ?
                              AND page    = ?
                              AND latest  = 'X' ''',
                        (project, page))
            if sql.fetchone() is None:
                return await self._handleOutput(request, 'page-404', pwic)  # Page not found

        # Handle some options
        option_nohist = self._readEnv(sql, project, 'no_history') is not None
        if option_nohist and pwic['pure_reader']:
            revision = 0
        option_valonly = self._readEnv(sql, project, 'validated_only') is not None

        # Show the requested page
        if action == 'view':
            if not page_special:
                # Redirect the reader to the latest validated revision
                if revision == 0 and pwic['pure_reader'] and option_valonly:
                    sql.execute(''' SELECT MAX(revision)
                                    FROM pages
                                    WHERE project  = ?
                                      AND page     = ?
                                      AND valuser <> '' ''',
                                (project, page))
                    row = sql.fetchone()
                    if row[0] is not None:
                        revision = row[0]

                # Content of the page
                sql.execute(''' SELECT revision, latest, draft, final, protection,
                                       author, date, time, title, markdown,
                                       tags, valuser, valdate, valtime
                                FROM pages
                                WHERE   project  = ?
                                  AND   page     = ?
                                  AND ( revision = ?
                                   OR ( 0 = ? AND latest = 'X' )
                                    )''',
                            (project, page, revision, revision))
                row = sql.fetchone()
                if row is None:
                    return await self._handleOutput(request, 'page-404', pwic)  # Revision not found
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
                pwic['html'], pwic['tmap'] = self._md2html(sql, project, page, row[9], cache=pwic['latest'])
                pwic['hash'] = _sha256(row[9], salt=False)
                pwic['tags'] = [] if row[10] == '' else row[10].split(' ')
                pwic['valuser'] = row[11]
                pwic['valdate'] = row[12]
                pwic['valtime'] = row[13]
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
                                  AND latest  = 'X'
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
                pwic['disabled_users'] = []
                for row in sql.fetchall():
                    if _xb(row[6]):
                        pwic['disabled_users'].append(row[0])
                    else:
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
                                    WHERE a.project  = ?
                                      AND a.disabled = ''
                                      AND b.date     IS NULL
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
                                  AND latest  = 'X'
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

                # Fetch the tags of the project
                sql.execute(''' SELECT tags
                                FROM pages
                                WHERE project = ?
                                  AND latest  = 'X'
                                  AND tags   <> '' ''',
                            (project, ))
                tags = ''
                for row in sql.fetchall():
                    tags += ' ' + row[0]
                pwic['tags'] = sorted(list(set(tags.strip().split(' '))))

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
                                WHERE a.project  = ?
                                  AND a.user     = ?
                                  AND a.disabled = ''
                                ORDER BY filename''',
                            (project, project, user))
                pwic['documents'] = []
                used_size = 0
                for row in sql.fetchall():
                    used_size += row[5]
                    pwic['documents'].append({'id': row[0],
                                              'project': row[1],
                                              'page': row[2],
                                              'filename': row[3],
                                              'mime': row[4],
                                              'mime_icon': _mime2icon(row[4]),
                                              'size': _size2str(row[5]),
                                              'hash': row[6],
                                              'author': row[7],
                                              'date': row[8],
                                              'time': row[9],
                                              'occurrence': row[10]})
                pmax = _int(self._readEnv(sql, project, 'max_project_size', 0))
                pwic['disk_space'] = {'used': used_size,
                                      'used_str': _size2str(used_size),
                                      'project_max': pmax,
                                      'project_max_str': _size2str(pmax),
                                      'percentage': min(100, float('%.2f' % (0 if pmax == 0 else 100. * used_size / pmax)))}

            # Render the page in HTML or Markdown
            return await self._handleOutput(request, 'page-special' if page_special else 'page', pwic)

        # Edit the requested page
        elif action == 'edit':
            assert(revision == 0)
            sql.execute(''' SELECT revision, draft, final, header, protection,
                                   title, markdown, tags, milestone
                            FROM pages
                            WHERE project = ?
                              AND page    = ?
                              AND latest  = 'X' ''',
                        (project, page))
            row = sql.fetchone()
            pwic['revision'] = row[0]
            pwic['draft'] = _xb(row[1])
            pwic['final'] = _xb(row[2])
            pwic['header'] = _xb(row[3])
            pwic['protection'] = _xb(row[4])
            pwic['title'] = row[5]
            pwic['markdown'] = row[6]
            pwic['tags'] = row[7]
            pwic['milestone'] = row[8]
            return await self._handleOutput(request, 'page-edit', pwic)

        # Show the history of the page
        elif action == 'history':
            # Redirect the pure reader if the history is disabled
            if pwic['pure_reader'] and option_nohist:
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
                if _xb(row[1]):
                    pwic['title'] = row[7]
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
            return await self._handleOutput(request, 'page-history', pwic)

        # Default behavior
        else:
            raise web.HTTPNotFound()

    async def page_audit(self: object, request: web.Request) -> web.Response:
        ''' Serve the page to monitor the settings and the activty '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Fetch the parameters
        project = _safeName(request.match_info.get('project', ''))
        sql = app['sql'].cursor()
        drange = max(-1, _int(self._readEnv(sql, project, 'audit_range', 30)))
        dt = _dt(drange)

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
                'project_description': row[0],
                'range': drange,
                'systime': _dt(),
                'up': app['up']}

        # Read the audit data
        sql.execute(''' SELECT id, date, time, author, event,
                               user, project, page, revision,
                               string
                        FROM audit
                        WHERE project = ?
                          AND date   >= ?
                        ORDER BY id DESC''',
                    (project, dt['date-nd']))
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
        return await self._handleOutput(request, 'page-audit', pwic)

    async def page_help(self: object, request: web.Request) -> web.Response:
        ''' Serve the help page to any user '''
        pwic = {'project': 'special',
                'page': 'help',
                'title': 'Help for Pwic'}
        return await self._handleOutput(request, 'help', pwic)

    async def page_create(self: object, request: web.Request) -> web.Response:
        ''' Serve the page to create a new page '''
        # Verify that the user is connected
        user = await self._suser(request)
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
                        WHERE a.user     = ?
                          AND a.manager  = 'X'
                          AND a.disabled = ''
                        ORDER BY b.description''',
                    (user, ))
        for row in sql.fetchall():
            pwic['projects'].append({'project': row[0],
                                     'description': row[1]})

        # Show the page
        return await self._handleOutput(request, 'page-create', pwic=pwic)

    async def user_create(self: object, request: web.Request) -> web.Response:
        ''' Serve the page to create a new user '''
        # Verify that the user is connected
        user = await self._suser(request)
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
                        WHERE a.user     = ?
                          AND a.admin    = 'X'
                          AND a.disabled = ''
                        ORDER BY b.description''',
                    (user, ))
        for row in sql.fetchall():
            pwic['projects'].append({'project': row[0],
                                     'description': row[1]})

        # Show the page
        return await self._handleOutput(request, 'user-create', pwic=pwic)

    async def page_user(self: object, request: web.Request) -> web.Response:
        ''' Serve the page to view the profile of a user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Fetch the information of the user
        sql = app['sql'].cursor()
        userpage = _safeName(request.match_info.get('userpage', None), extra='')
        row = sql.execute('SELECT password, initial FROM users WHERE user = ?', (userpage, )).fetchone()
        if row is None:
            raise web.HTTPNotFound()
        pwic = {'title': 'User profile',
                'user': user,
                'userpage': userpage,
                'password_oauth': row[0] == PWIC_MAGIC_OAUTH,
                'password_initial': _xb(row[1]),
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
                        WHERE a.user     = ?
                          AND a.disabled = ''
                        ORDER BY date DESC,
                                 time DESC''',
                    (userpage, user))
        for row in sql.fetchall():
            pwic['documents'].append({'id': row[0],
                                      'project': row[1],
                                      'page': row[2],
                                      'filename': row[3],
                                      'mime': row[4],
                                      'mime_icon': _mime2icon(row[4]),
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

    async def page_search(self: object, request: web.Request) -> web.Response:
        ''' Serve the search engine '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Parse the query
        sql = app['sql'].cursor()
        project = _safeName(request.match_info.get('project', ''))
        if self._readEnv(sql, project, 'no_search') is not None:
            query = None
        else:
            query = pwic_search_parse(request.rel_url.query.get('q', ''))
            with_rev = 'rev' in request.rel_url.query
        if query is None:
            raise web.HTTPTemporaryRedirect('/%s' % project)

        # Fetch the description of the project if the user has access rights
        sql.execute(''' SELECT b.description
                        FROM roles AS a
                            INNER JOIN projects AS b
                                ON b.project = a.project
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.disabled = '' ''',
                    (project, user))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPUnauthorized()
        pwic = {'title': 'Search',
                'project': project,
                'project_description': row[0],
                'terms': pwic_search_tostring(query),
                'pages': [],
                'documents': []}

        # Search for a page
        sql.execute(''' SELECT a.project, a.page, a.revision, a.latest, a.draft, a.final,
                               a.author, a.date, a.time, a.title, LOWER(a.markdown),
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
            tagList = row[11].split(' ')

            # Apply the filters
            ok = True
            score = 0
            for q in query['excluded']:         # The first occurrence of an excluded term excludes the whole page
                if (q == ':latest' and _xb(row[3]))                             \
                   or (q == ':draft' and _xb(row[4]))                           \
                   or (q == ':final' and _xb(row[5]))                           \
                   or (q[:7] == 'author:' and q[7:] in row[6].lower())          \
                   or (q[:6] == 'title:' and q[6:] in row[9].lower())           \
                   or (q == ':validated' and row[12] != '')                     \
                   or (q[:10] == 'validator:' and q[10:] in row[12].lower())    \
                   or (q == ':document' and _int(row[15]) > 0)                  \
                   or (q[1:] in tagList if q[:1] == '#' else False)             \
                   or (q == row[1].lower())                                     \
                   or (q in row[10]):
                    ok = False
                    break
            if ok:
                for q in query['included']:     # The first non-occurrence of an included term excludes the whole page
                    if q == ':latest':
                        count = _int(_xb(row[3]))
                    elif q == ':draft':
                        count = _int(_xb(row[4]))
                    elif q == ':final':
                        count = _int(_xb(row[5]))
                    elif q[:7] == 'author:':
                        count = row[6].lower().count(q[7:])
                    elif q[:6] == 'title:':
                        count = row[9].lower().count(q[6:])
                    elif q == ':validated':
                        count = _int(row[12] != '')
                    elif q[:10] == 'validator:':
                        count = _int(q[10:] in row[12].lower())
                    elif q == ':document':
                        count = _int(_int(row[15]) > 0)
                    elif (q[1:] in tagList if q[:1] == '#' else False):
                        count = 5               # A tag counts more
                    else:
                        count = 5 * _int(q == row[1].lower()) + row[10].count(q)
                    if count == 0:
                        ok = False
                        break
                    else:
                        score += count
            if not ok:
                continue

            # Save the found result
            pwic['pages'].append({'project': row[0],
                                  'page': row[1],
                                  'revision': row[2],
                                  'latest': _xb(row[3]),
                                  'draft': _xb(row[4]),
                                  'final': _xb(row[5]),
                                  'author': row[6],
                                  'date': row[7],
                                  'time': row[8],
                                  'title': row[9],
                                  'valuser': row[12],
                                  'valdate': row[13],
                                  'valtime': row[14],
                                  'score': score})

        # Search for documents
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
                if q in row[2] or q in row[3] or q in row[4]:
                    ok = False
                    break
            if ok:
                for q in query['included']:
                    if ':' in q:
                        continue
                    if q not in row[2] and q not in row[3] and q not in row[4]:
                        ok = False
                        break
            if not ok:
                continue

            # Save the found document
            pwic['documents'].append({'id': row[0],
                                      'project': row[1],
                                      'page': row[2],
                                      'filename': row[3],
                                      'mime': row[4],
                                      'mime_icon': _mime2icon(row[4]),
                                      'size': _size2str(row[5]),
                                      'author': row[6],
                                      'date': row[7],
                                      'time': row[8]})

        # Show the pages by score desc, date desc and time desc
        pwic['pages'].sort(key=lambda x: x['score'], reverse=True)
        return await self._handleOutput(request, 'search', pwic=pwic)

    async def page_env(self: object, request: web.Request) -> web.Response:
        ''' Serve the project-dependent settings that can be modified online
            without critical, technical or legal impact on the server '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Fetch the parameters
        project = _safeName(request.match_info.get('project', ''))

        # Verify that the user is an administrator
        sql = app['sql'].cursor()
        if sql.execute(''' SELECT user
                           FROM roles
                           WHERE project  = ?
                             AND user     = ?
                             AND admin    = 'X'
                             AND disabled = '' ''',
                       (project, user)).fetchone() is None:
            raise web.HTTPUnauthorized()

        # Show the page
        sql.execute('SELECT description FROM projects WHERE project = ?', (project, ))
        pwic = {'title': 'Project-dependent environment variables',
                'project': project,
                'project_description': sql.fetchone()[0]}
        return await self._handleOutput(request, 'page-env', pwic=pwic)

    async def page_roles(self: object, request: web.Request) -> web.Response:
        ''' Serve the form to change the authorizations of the users '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Fetch the name of the project
        project = _safeName(request.match_info.get('project', ''))
        sql = app['sql'].cursor()
        sql.execute('SELECT description FROM projects WHERE project = ?', (project, ))
        pwic = {'title': 'Roles',
                'project': project,
                'project_description': sql.fetchone()[0],
                'roles': []}

        # Fetch the roles
        sql.execute(''' SELECT a.user, c.initial, a.admin, a.manager,
                               a.editor, a.validator, a.reader, a.disabled
                        FROM roles AS a
                            INNER JOIN roles AS b
                                ON  b.project  = a.project
                                AND b.user     = ?
                                AND b.admin    = 'X'
                                AND b.disabled = ''
                            INNER JOIN users AS c
                                ON  c.user    = a.user
                        WHERE a.project = ?
                        ORDER BY a.user''',
                    (user, project))
        for row in sql.fetchall():
            pwic['roles'].append({'user': row[0],
                                  'initial': _xb(row[1]),
                                  'admin': _xb(row[2]),
                                  'manager': _xb(row[3]),
                                  'editor': _xb(row[4]),
                                  'validator': _xb(row[5]),
                                  'reader': _xb(row[6]),
                                  'disabled': _xb(row[7])})

        # Display the page
        if len(pwic['roles']) == 0:
            raise web.HTTPUnauthorized()        # Or project not found
        else:
            return await self._handleOutput(request, 'user-roles', pwic=pwic)

    async def page_links(self: object, request: web.Request) -> web.Response:
        ''' Serve the check of the links '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Fetch the parameters
        project = _safeName(request.match_info.get('project', ''))
        sql = app['sql'].cursor()

        # Fetch the documents of the project
        sql.execute('SELECT id FROM documents ORDER BY id')
        docids = []
        for row in sql.fetchall():
            docids.append(str(row[0]))

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
        regex_page = re.compile(PWIC_REGEX_PAGE)
        regex_document = re.compile(PWIC_REGEX_DOCUMENT)
        linkmap = {PWIC_DEFAULT_PAGE: []}
        broken_docs = {}
        for row in sql.fetchall():
            ok = True
            page = row[0]
            if page not in linkmap:
                linkmap[page] = []

            # Generate a fake link at the home page for all the bookmarked pages
            if _xb(row[1]) and page not in linkmap[PWIC_DEFAULT_PAGE]:
                linkmap[PWIC_DEFAULT_PAGE].append(page)

            # Find the links to the other pages
            subpages = regex_page.findall(row[2])
            if subpages is not None:
                for sp in subpages:
                    if (sp[0] == project) and (sp[1] not in linkmap[page]):
                        linkmap[page].append(sp[1])

            # Looks for the linked documents
            subdocs = regex_document.findall(row[2])
            if subdocs is not None:
                for sd in subdocs:
                    if sd[0] not in docids:
                        if page not in broken_docs:
                            broken_docs[page] = []
                        broken_docs[page].append(_int(sd[0]))
        if not ok:
            raise web.HTTPUnauthorized()

        # Find the orphaned and broken links
        allpages = [key for key in linkmap]
        orphans = allpages.copy()
        orphans.remove(PWIC_DEFAULT_PAGE)
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
                'broken': broken,
                'broken_docs': broken_docs}
        return await self._handleOutput(request, 'page-links', pwic=pwic)

    async def page_graph(self: object, request: web.Request) -> web.Response:
        ''' Serve the check of the links '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Check the authorizations
        project = _safeName(request.match_info.get('project', ''))
        sql = app['sql'].cursor()
        sql.execute(''' SELECT user
                        FROM roles
                        WHERE project  = ?
                          AND user     = ?
                          AND manager  = 'X'
                          AND disabled = '' ''',
                    (project, user))
        if sql.fetchone() is None:
            raise web.HTTPUnauthorized()

        # Show the page
        sql.execute('SELECT description FROM projects WHERE project = ?', (project, ))
        pwic = {'title': 'Graph of the project',
                'project': project,
                'project_description': sql.fetchone()[0]}
        return await self._handleOutput(request, 'page-graph', pwic=pwic)

    async def page_compare(self: object, request: web.Request) -> web.Response:
        ''' Serve the page that compares two revisions '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Fetch the pages
        sql = app['sql'].cursor()
        project = _safeName(request.match_info.get('project', ''))
        page = _safeName(request.match_info.get('page', ''))
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
            tfrom = tfrom.replace('\r', '').split('\n')
            tto = tto.replace('\r', '').split('\n')
            return diff.make_table(tfrom, tto).replace('&nbsp;', ' ').replace(' nowrap="nowrap"', '').replace(' cellpadding="0"', '')

        pwic = {'title': row[1],
                'project': project,
                'project_description': row[0],
                'page': page,
                'new_revision': new_revision,
                'old_revision': old_revision,
                'diff': _diff(row[3], row[2])}
        return await self._handleOutput(request, 'page-compare', pwic=pwic)

    async def project_export(self: object, request: web.Request) -> web.Response:
        ''' Download the project as a zip file '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Verify that the export is authorized
        sql = app['sql'].cursor()
        project = _safeName(request.match_info.get('project', ''))
        if self._readEnv(sql, project, 'no_export_project') is not None:
            raise web.HTTPUnauthorized()
        with_revisions = self._readEnv(sql, project, 'export_project_revisions') is not None

        # Fetch the pages
        sql.execute(''' SELECT b.page, b.revision, b.latest, b.author, b.date, b.time, b.title, b.markdown
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.admin    = 'X'
                          AND a.disabled = ''
                        ORDER BY b.page''',
                    (project, user))
        pages = []
        for row in sql.fetchall():
            if not with_revisions and not _xb(row[2]):
                continue
            pages.append(row)
        if len(pages) == 0:
            raise web.HTTPUnauthorized()

        # Fetch the attached documents
        sql.execute(''' SELECT id, filename, mime
                        FROM documents
                        WHERE project = ?''',
                    (project, ))
        documents = []
        for row in sql.fetchall():
            documents.append({'id': row[0],
                              'filename': row[1],
                              'image': row[2][:6] == 'image/'})

        # Build the zip file
        folder_rev = 'revisions/'
        htmlStyles = pwic_styles_html()
        try:
            inmemory = BytesIO()
            zip = zipfile.ZipFile(inmemory, mode='w', compression=zipfile.ZIP_DEFLATED)

            # Pages of the project
            for page in pages:
                # Raw markdown
                if with_revisions:
                    zip.writestr('%s%s.rev%d.md' % (folder_rev, page[0], page[1]), page[7])
                if _xb(page[2]):
                    zip.writestr('%s.md' % page[0], page[7])

                # HTML
                html = htmlStyles.html % (page[3].replace('"', '&quote;'),
                                          page[4],
                                          page[5],
                                          page[0].replace('<', '&lt;').replace('>', '&gt;'),
                                          page[6].replace('<', '&lt;').replace('>', '&gt;'),
                                          htmlStyles.getCss(rel=True),
                                          '',
                                          self._md2html(sql, project, page[0], page[7], cache=_xb(page[2]))[0])
                for doc in documents:
                    if doc['image']:
                        html = html.replace('<img src="/special/document/%d"' % doc['id'], '<img src="documents/%s"' % doc['filename'])
                    html = html.replace('<a href="/special/document/%d"' % doc['id'], '<a href="documents/%s"' % doc['filename'])
                    html = html.replace('<a href="/special/document/%d/' % doc['id'], '<a href="documents/%s' % doc['filename'])
                if with_revisions:
                    zip.writestr('%s%s.rev%d.html' % (folder_rev, page[0], page[1]), html)
                if _xb(page[2]):
                    zip.writestr('%s.html' % page[0], html)

            # Dependent files for the pages
            content = ''
            with open(htmlStyles.css, 'rb') as f:
                content = f.read()
            zip.writestr(htmlStyles.css, content)
            if with_revisions:
                zip.writestr(folder_rev + htmlStyles.css, content)
            del content

            # Attached documents
            for doc in documents:
                fn = (PWIC_DOCUMENTS_PATH % project) + doc['filename']
                if isfile(fn):
                    content = ''
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
                         'project': project},
                   request)
        self._commit()

        # Return the file
        content = inmemory.getvalue()
        inmemory.close()
        return web.Response(body=content, headers=MultiDict({'Content-Disposition': 'attachment; filename="%s"' % _attachmentName(project + '.zip')}))

    async def document_get(self: object, request: web.Request) -> web.Response:
        ''' Download a document '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return web.HTTPUnauthorized()

        # Read the properties of the requested document
        id = _int(request.match_info.get('id', 0))
        sql = app['sql'].cursor()
        sql.execute(''' SELECT a.project, a.filename, a.mime, a.size
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

        # Transfer the file
        filename = (PWIC_DOCUMENTS_PATH % row[0]) + row[1]
        if getsize(filename) != row[3]:
            raise web.HTTPConflict()  # Size mismatch causes an infinite download time
        try:
            with open(filename, 'rb') as f:
                content = f.read()
        except FileNotFoundError:
            raise web.HTTPNotFound()
        headers = {'Content-Type': row[2],
                   'Content-Length': str(row[3])}
        if request.rel_url.query.get('attachment', None) is not None:
            headers['Content-Disposition'] = 'attachment; filename="%s"' % _attachmentName(row[1])
        return web.Response(body=content, headers=MultiDict(headers))

    async def api_logon(self: object, request: web.Request) -> web.Response:
        ''' API to log on people '''
        # Checks
        if app['no_logon']:
            raise web.HTTPBadRequest()
        self._checkIP(request)

        # Fetch the submitted data
        post = await self._handlePost(request)
        user = _safeName(post.get('user', ''), extra='')
        pwd = '' if user == PWIC_USER_ANONYMOUS else _sha256(post.get('password', ''))
        lang = post.get('language', PWIC_DEFAULT_LANGUAGE)
        if lang not in app['langs']:
            lang = PWIC_DEFAULT_LANGUAGE

        # Logon with the credentials
        ok = False
        sql = app['sql'].cursor()
        sql.execute(''' SELECT COUNT(a.user)
                        FROM users AS a
                            INNER JOIN roles AS b
                                ON  b.user     = a.user
                                AND b.disabled = ''
                        WHERE a.user     = ?
                          AND a.password = ?''',
                    (user, pwd))
        if sql.fetchone()[0] > 0:
            ok = True
            session = await new_session(request)
            session['user'] = user
            session['language'] = lang
            if user != PWIC_USER_ANONYMOUS:
                pwic_audit(sql, {'author': user,
                                 'event': 'logon'},
                           request)
                self._commit()

        # Final redirection (do not use "raise")
        if request.rel_url.query.get('redirect', None) is not None:
            return web.HTTPFound('/' if ok else '/?failed')
        else:
            return web.HTTPOk() if ok else web.HTTPUnauthorized()

    async def api_logout(self: object, request: web.Request) -> web.Response:
        ''' API to log out '''
        # Logging the disconnection (not visible online) aims to not report a reader as inactive.
        # Knowing that the session is encrypted in the cookie, the event does NOT guarantee that
        # it is effectively destroyed by the user (his web browser generally does it). The session
        # is fully lost upon server restart because a new key is generated.
        user = await self._suser(request)
        if user not in ['', PWIC_USER_ANONYMOUS]:
            pwic_audit(app['sql'].cursor(), {'author': user,
                                             'event': 'logout'},
                       request)
            self._commit()

        # Destroy the session
        session = await get_session(request)
        session.invalidate()
        return await self._handleOutput(request, 'logout', {'title': 'Disconnected from Pwic'})

    async def api_oauth(self: object, request: web.Request) -> web.Response:
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
        if app['no_logon']:
            raise web.HTTPBadRequest()
        self._checkIP(request)

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
            session['user_secret'] = _randomHash()
            _oauth_failed()

        # Call the provider
        sql = app['sql'].cursor()
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
                     'redirect_uri': self._readEnv(sql, '', 'base_url', '') + '/api/oauth',
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
                     'redirect_uri': self._readEnv(sql, '', 'base_url', '') + '/api/oauth',
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
        user = _safeName(user, extra='')
        if user[:4] in ['', 'pwic']:
            _oauth_failed()
        assert('@' in user)

        # Create the default user account
        if sql.execute('SELECT 1 FROM users WHERE user = ?', (user, )).fetchone() is None:
            sql.execute("INSERT INTO users (user, password, initial) VALUES (?, ?, '')", (user, PWIC_MAGIC_OAUTH))
            # Remarks:
            # - PWIC_DEFAULT_PASSWORD is not set because the user will forget to change it
            # - The user cannot change the internal password because the current password will not be hashed correctly
            # - The password can be reset from the administration console only
            # - Then the two authentications methods can coexist
            pwic_audit(sql, {'author': PWIC_USER_SYSTEM,
                             'event': 'create-user',
                             'user': user,
                             'string': PWIC_MAGIC_OAUTH},
                       request)

            # Grant the default rights as reader
            for project in oauth['projects']:
                if sql.execute('SELECT 1 FROM projects WHERE project = ?', (project, )).fetchone() is not None:
                    sql.execute("INSERT INTO roles (project, user, reader) VALUES (?, ?, 'X')", (project, user))
                    if sql.rowcount > 0:
                        pwic_audit(sql, {'author': PWIC_USER_SYSTEM,
                                         'event': 'grant-reader',
                                         'project': project,
                                         'user': user,
                                         'string': PWIC_MAGIC_OAUTH},
                                   request)

        # Register the session
        session = await new_session(request)
        session['user'] = user
        session['language'] = PWIC_DEFAULT_LANGUAGE  # TODO The language is not selectable
        session['user_secret'] = _randomHash()
        pwic_audit(sql, {'author': user,
                         'event': 'logon',
                         'string': PWIC_MAGIC_OAUTH},
                   request)
        self._commit()

        # Final redirection (do not use "raise")
        return web.HTTPFound('/')

    async def api_server_env_get(self: object, request: web.Request) -> web.Response:
        ''' API to return the defined environment variables '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user in ['', PWIC_USER_ANONYMOUS]:
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))

        # Verify that the user is authorized for the project
        sql = app['sql'].cursor()
        if project != '':
            sql.execute(''' SELECT user
                            FROM roles
                            WHERE project  = ?
                              AND user     = ?
                              AND disabled = '' ''',
                        (project, user))
            if sql.fetchone() is None:
                return web.HTTPUnauthorized()

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
            (global_, key, value) = (row[0] == '', row[1], row[2])
            if key in PWIC_ENV_PRIVATE:
                value = None
            if key not in data:
                data[key] = {'value': value,
                             'global': global_}

        # Final result
        return web.Response(text=json.dumps(data), content_type=MIME_JSON)

    async def api_server_ping(self: object, request: web.Request) -> web.Response:
        ''' Notify if the session is still alive '''
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()
        else:
            return web.Response(text='OK', content_type=MIME_TEXT)

    async def api_project_info_get(self: object, request: web.Request) -> web.Response:
        ''' API to fetch the metadata of the project '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user in ['', PWIC_USER_ANONYMOUS]:
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        if project == '':
            raise web.HTTPBadRequest()
        page = _safeName(post.get('page', ''))
        all = post.get('all', None) is not None
        data = {}

        # API not available to the pure readers when some options are activated
        sql = app['sql'].cursor()
        if self._readEnv(sql, project, 'no_history') is not None or \
           self._readEnv(sql, project, 'validated_only') is not None:
            sql.execute(''' SELECT user
                            FROM roles
                            WHERE project   = ?
                              AND user      = ?
                              AND admin     = ''
                              AND manager   = ''
                              AND editor    = ''
                              AND validator = ''
                              AND reader    = 'X'
                              AND disabled  = '' ''',
                        (project, user))
            if sql.fetchone() is not None:
                raise web.HTTPForbidden()

        # Fetch the pages
        exposeMD = self._readEnv(sql, project, 'api_expose_markdown', None) is not None
        sql.execute(''' SELECT b.page, b.revision, b.latest, b.draft, b.final,
                               b.header, b.protection, b.author, b.date, b.time,
                               b.title, b.markdown, b.tags, b.comment, b.milestone,
                               b.valuser, b.valdate, b.valtime
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                                AND (b.page = ? OR '' = ?)
                                AND b.latest IN ('%sX')
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.disabled = ''
                        ORDER BY b.page ASC,
                                 b.revision DESC''' % ("','" if all else '', ),
                    (page, page, project, user))
        for row in sql.fetchall():
            if row[0] not in data:
                data[row[0]] = {'revisions': [],
                                'documents': []}
            item = {}
            for i, field in enumerate(['revision', 'latest', 'draft', 'final', 'header',
                                       'protection', 'author', 'date', 'time', 'title',
                                       'markdown', 'tags', 'comment', 'milestone', 'valuser',
                                       'valdate', 'valtime']):
                i += 1
                if field == 'markdown':
                    if exposeMD:
                        item[field] = row[i]
                    item['hash'] = _sha256(row[i], salt=False)
                elif field == 'tags':
                    if row[i] != '':
                        item[field] = row[i].split(' ')
                else:
                    if not isinstance(row[i], str) or row[i] != '':
                        item[field] = row[i]
            item['url'] = '/%s/%s/rev%d' % (quote(project), quote(row[0]), row[1])
            data[row[0]]['revisions'].append(item)

        # Fetch the documents
        sql.execute(''' SELECT b.id, b.page, b.filename, b.mime, b.size,
                               b.hash, b.author, b.date, b.time
                        FROM roles AS a
                            INNER JOIN documents AS b
                                ON   b.project = a.project
                                AND (b.page = ? OR '' = ?)
                            INNER JOIN pages AS c
                                ON  c.project = a.project
                                AND c.page    = b.page
                                AND c.latest  = 'X'
                        WHERE a.project   = ?
                          AND a.user      = ?
                          AND a.disabled  = ''
                        ORDER BY b.page, b.filename''',
                    (page, page, project, user))
        for row in sql.fetchall():
            data[row[1]]['documents'].append({'id': row[0],
                                              'filename': row[2],
                                              'mime': row[3],
                                              'size': row[4],
                                              'hash': row[5],
                                              'author': row[6],
                                              'date': row[7],
                                              'time': row[8],
                                              'url': '/special/document/%d/%s?attachment' % (row[0], quote(row[1]))})

        # Final result
        return web.Response(text=json.dumps(data), content_type=MIME_JSON)

    async def api_project_env_set(self: object, request: web.Request) -> web.Response:
        ''' API to modify some of the project-dependent settings '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        key = post.get('key', '')
        value = post.get('value', '')
        if project == '' or key not in PWIC_ENV_PROJECT_DEPENDENT_ONLINE:
            raise web.HTTPBadRequest()

        # Verify that the user is administrator of the project
        sql = app['sql'].cursor()
        if sql.execute(''' SELECT user
                           FROM roles
                           WHERE project  = ?
                             AND user     = ?
                             AND admin    = 'X'
                             AND disabled = '' ''',
                       (project, user)).fetchone() is None:
            raise web.HTTPUnauthorized()

        # Update the variable
        if value == '':
            sql.execute('DELETE FROM env WHERE project = ? AND key = ?', (project, key))
        else:
            sql.execute('INSERT OR REPLACE INTO env (project, key, value) VALUES (?, ?, ?)', (project, key, value))
        pwic_audit(sql, {'author': user,
                         'event': '%sset-%s' % ('un' if value == '' else '', key),
                         'project': project,
                         'string': value},
                   request)
        self._commit()
        raise web.HTTPOk()

    async def api_project_progress_get(self: object, request: web.Request) -> web.Response:
        ''' API to analyze the progress of the project '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        tags = post.get('tags', '').strip()
        if '' in [project, tags]:
            raise web.HTTPBadRequest()

        # Verify that the user is authorized for the project
        sql = app['sql'].cursor()
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
                if _xb(row[2]):
                    item['validated'] += 1
                elif _xb(row[1]):
                    item['final'] += 1
                elif _xb(row[0]):
                    item['draft'] += 1
                else:
                    item['step'] += 1
                item['total'] += 1
            data[tag] = item

        # Final result
        return web.Response(text=json.dumps(data), content_type=MIME_JSON)

    async def api_project_graph_get(self: object, request: web.Request) -> web.Response:
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
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        if project == '':
            raise web.HTTPBadRequest()

        # Fetch the pages
        regex_page = re.compile(PWIC_REGEX_PAGE)
        sql = app['sql'].cursor()
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
        pages = []
        maps = []

        def _makeLink(fromProject: str, fromPage: str, toProject: str, toPage: str) -> None:
            if (fromProject, fromPage) != (toProject, toPage):
                tuple = (toProject, toPage, fromProject, fromPage)
                pos = bisect_left(maps, tuple)
                if pos >= len(maps) or maps[pos] != tuple:
                    insort(maps, tuple)

        def _getNodeID(project: str, page: str) -> str:
            tuple = (project, page)
            pos = bisect_left(pages, tuple)
            if (pos >= len(pages)) or (pages[pos] != tuple):
                insort(pages, tuple)
                return _getNodeID(project, page)
            else:
                return 'n%d' % (pos + 1)

        def _getNodeTitle(sql: object, project: str, page: str) -> str:
            # TODO Possible technical improvement here to avoid selects in loops
            sql.execute(''' SELECT title
                            FROM pages
                            WHERE project = ?
                              AND page    = ?
                              AND latest  = 'X' ''',
                        (project, page))
            row = sql.fetchone()
            return '' if row is None else row[0]

        for row in sql.fetchall():
            # Reference the processed page
            _getNodeID(row[0], row[1])
            _makeLink('', '', row[0], row[1])

            # Assign the bookmarks to the home page
            if _xb(row[2]):
                _makeLink(row[0], PWIC_DEFAULT_PAGE, row[0], row[1])

            # Find the links to the other pages
            subpages = regex_page.findall(row[3])
            if subpages is not None:
                for sp in subpages:
                    _getNodeID(sp[0], sp[1])
                    _makeLink(row[0], row[1], sp[0], sp[1])
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
            authorized_projects.append(row[0])

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
                        title = _getNodeTitle(sql, project, page)
                        if title != '' and project not in authorized_projects:
                            title = '[No authorization]'
                        viz += '%s [label="%s"; tooltip="%s"%s%s];\n' % \
                               (_getNodeID(project, page),
                                page.replace('"', '\\"'),
                                title.replace('"', '\\"') if title != '' else '[The page does not exist]',
                                ('; URL="/%s/%s"' % (project, page) if project in authorized_projects and title != '' else ''),
                                ('; color=red' if title == '' else ''))

            # Create the links in the cluster of the targeted node (else there is no box)
            if '' not in [fromProject, fromPage]:
                viz += '%s -> %s;\n' % (_getNodeID(fromProject, fromPage),
                                        _getNodeID(toProject, toPage))

        # Final output
        if len(maps) > 0:
            viz += '}\n'
        viz += '}'
        return web.Response(text=viz, content_type='text/vnd.graphviz')

    async def api_page_create(self: object, request: web.Request) -> None:
        ''' API to create a new page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        kb = 'kb' in post
        page = '' if kb else _safeName(post.get('page', ''))
        milestone = post.get('milestone', '').strip()
        tags = post.get('tags', '')
        ref_project = _safeName(post.get('ref_project', ''))
        ref_page = _safeName(post.get('ref_page', ''))
        ref_tags = 'ref_tags' in post
        if project in ['', 'api', 'special'] or (not kb and page in ['', 'special']):
            raise web.HTTPBadRequest()

        # Consume a KBid
        sql = app['sql'].cursor()
        if kb:
            sql.execute('BEGIN EXCLUSIVE TRANSACTION')
            kbid = int(self._readEnv(sql, project, 'kbid', 0)) + 1
            sql.execute('INSERT OR REPLACE INTO env (project, key, value) VALUES (?, ?, ?)',
                        (project, 'kbid', kbid))
            page = 'kb%06d' % kbid
            # No commit because the creation of the page can fail below
        else:
            if re.compile(r'^kb[0-9]{6}$').match(page) is not None:
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
        if row is None or row[0] is not None:
            if kb:
                self._rollback()
            raise web.HTTPFound('/special/create-page?failed')

        # Fetch the default markdown if the page is created in reference to another one
        default_markdown = '# %s' % page
        default_tags = ''
        if ref_project != '' and ref_page != '':
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
                if kb:
                    self._rollback()
                raise web.HTTPFound('/special/create-page?failed')
            default_markdown = row[0]
            if ref_tags:
                default_tags = row[1]

        # Handle the creation of the page
        dt = _dt()
        revision = 1
        sql.execute(''' INSERT INTO pages (project, page, revision, author, date, time, title, markdown, tags, comment, milestone)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (project, page, revision, user, dt['date'], dt['time'], page, default_markdown,
                     self._sanitizeTags(tags + ' ' + default_tags), 'Initial', milestone))
        assert(sql.rowcount > 0)
        pwic_audit(sql, {'author': user,
                         'event': 'create-page',
                         'project': project,
                         'page': page,
                         'revision': revision},
                   request)
        self._commit()
        raise web.HTTPFound('/%s/%s?success' % (project, page))

    async def api_page_edit(self: object, request: web.Request) -> None:
        ''' API to update an existing page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        page = _safeName(post.get('page', ''))
        title = post.get('title', '').strip()
        markdown = post.get('markdown', '')
        tags = self._sanitizeTags(post.get('tags', ''))
        comment = post.get('comment', '').strip()
        milestone = post.get('milestone', '').strip()
        draft = 'draft' in post
        final = 'final' in post
        protection = _x('protection' in post)
        header = _x('header' in post)
        dt = _dt()
        if '' in [user, project, page, title, comment]:
            raise web.HTTPBadRequest()
        if final:
            draft = False

        # Fetch the last revision of the page and the profile of the user
        sql = app['sql'].cursor()
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
                             markdown, tags, comment, milestone)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (project, page, revision + 1, _x(draft), _x(final), header,
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
            if final:
                sql.execute(''' DELETE FROM pages
                                WHERE project   = ?
                                  AND page      = ?
                                  AND revision <= ?
                                  AND author    = ?
                                  AND draft     = 'X'
                                  AND final     = ''
                                  AND valuser   = '' ''',
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
                            SET header = '',
                                latest = ''
                            WHERE project   = ?
                              AND page      = ?
                              AND revision <= ?''',
                        (project, page, revision))

            # Clear the cache
            sql.execute(''' DELETE FROM cache
                            WHERE project = ?
                              AND page    = ?''',
                        (project, page))
            self._commit()
        raise web.HTTPFound('/%s/%s?success' % (project, page))

    async def api_page_validate(self: object, request: web.Request) -> None:
        ''' Validate the pages '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the revision to validate
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        page = _safeName(post.get('page', ''))
        revision = _int(post.get('revision', 0))
        if '' in [project, page] or revision == 0:
            raise web.HTTPBadRequest()

        # Verify that it is possible to validate the page
        sql = app['sql'].cursor()
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
                   request)
        self._commit()
        raise web.HTTPOk()

    async def api_page_delete(self: object, request: web.Request) -> None:
        ''' Delete a page upon administrative request '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the revision to delete
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        page = _safeName(post.get('page', ''))
        revision = _int(post.get('revision', 0))
        if '' in [project, page] or revision == 0:
            raise web.HTTPBadRequest()

        # Verify that the deletion is possible
        sql = app['sql'].cursor()
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
            raise web.HTTPUnauthorized()
        header = row[0]

        # Clear the cache
        sql.execute(''' DELETE FROM cache
                        WHERE project = ?
                          AND page    = ?''',
                    (project, page))

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
                                    SET latest = 'X',
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
        if sql.fetchone()[0] == 0:
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
                    remove(fn)
                except (OSError, FileNotFoundError):
                    if isfile(fn):
                        self._rollback()
                        raise web.HTTPFound('/%s/%s?failed' % (project, page))

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

        # Final
        self._commit()
        raise web.HTTPOk()

    async def api_page_export(self: object, request: web.Request) -> web.Response:
        ''' API to export a page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Read the parameters
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        page = _safeName(post.get('page', ''))
        revision = _int(post.get('revision', 0))
        format = post.get('format', '').lower()
        if '' in [project, page, format]:
            raise web.HTTPBadRequest()

        # Read the selected revision
        sql = app['sql'].cursor()
        disabled_formats = self._readEnv(sql, project, 'disabled_formats', '').split(' ')
        if format in disabled_formats or '*' in disabled_formats:
            raise web.HTTPForbidden()
        sql.execute(''' SELECT b.revision, b.latest, b.author, b.date, b.time,
                               b.title, b.markdown, b.tags
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON    b.project  = a.project
                                AND   b.page     = ?
                                AND ( b.revision = ?
                                 OR ( 0 = ?
                                  AND b.latest   = 'X' )
                                )
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.disabled = '' ''',
                    (page, revision, revision, project, user))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPUnauthorized()

        # Initialization
        dt = _dt()
        baseUrl = self._readEnv(sql, '', 'base_url', '')
        pageUrl = '%s/%s/%s/rev%d' % (baseUrl, project, page, row[0])
        endname = _attachmentName('%s_%s_rev%d.%s' % (project, page, row[0], format))

        # Fetch the legal notice
        legal_notice = self._readEnv(sql, project, 'legal_notice', '').strip()
        legal_notice = re.sub(PWIC_REGEX_HTML_TAG, '', legal_notice)
        legal_notice = legal_notice.replace('\r', '')

        # Format MD
        if format == 'md':
            return web.Response(body=row[6], headers=MultiDict({'Content-Type': 'text/markdown',
                                                                'Content-Disposition': 'attachment; filename="%s"' % endname}))

        # Format HTML
        elif format == 'html':
            htmlStyles = pwic_styles_html()
            html = htmlStyles.html % (row[2].replace('"', '&quote;'),
                                      row[3],
                                      row[4],
                                      page.replace('<', '&lt;').replace('>', '&gt;'),
                                      row[5].replace('<', '&lt;').replace('>', '&gt;'),
                                      htmlStyles.getCss(rel=False),
                                      '' if legal_notice == '' else ('<!--\n%s\n-->' % legal_notice),
                                      self._md2html(sql, project, page, row[6], cache=_xb(row[1]))[0])
            html = html.replace('<a href="/', '<a href="%s/' % baseUrl)
            return web.Response(body=html, headers=MultiDict({'Content-Type': htmlStyles.mime,
                                                              'Content-Disposition': 'attachment; filename="%s"' % endname}))

        # Format ODT
        elif format == 'odt':
            # MD --> HTML --> ODT
            html = self._md2html(sql, project, page, row[6],
                                 cache=False,  # No cache to recalculate the headers through the styles
                                 headerNumbering=False)[0]
            html = html.replace('<div class="codehilite"><pre><span></span><code>', '<blockcode>')
            html = html.replace('</code></pre></div>', '</blockcode>')
            html = html.replace('<pre><code>', '<blockcode>')
            html = html.replace('</code></pre>', '</blockcode>')

            # Extract the meta-informations of the embedded pictures
            docids = ['0']
            subdocs = re.compile(PWIC_REGEX_DOCUMENT).findall(row[6])
            if subdocs is not None:
                for sd in subdocs:
                    sd = str(_int(sd[0]))
                    if sd not in docids:
                        docids.append(sd)
            query = ''' SELECT a.id, a.project, a.page, a.filename, a.mime
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
                fn = (PWIC_DOCUMENTS_PATH % project) + rowdoc[3]
                if isfile(fn):
                    try:
                        w, h = imagesize.get(fn)

                        # Optimize the maximal size
                        MAX_W = 600  # px
                        MAX_H = 900  # px
                        if w > MAX_W:
                            h *= MAX_W / w
                            w = MAX_W
                        if h > MAX_H:
                            w *= MAX_H / h
                            h = MAX_H
                    except ValueError:
                        w, h = 50, 50  # Default area
                    pictMeta[rowdoc[0]] = {'filename': fn,
                                           'link': 'special/document/%d' % rowdoc[0],
                                           'link_odt_img': 'special/document_%d' % rowdoc[0],  # LibreOffice does not support the paths with multiple folders
                                           'uncompressed': rowdoc[4] in [MIME_BMP, MIME_SVG],
                                           'manifest': '<manifest:file-entry manifest:full-path="special/document_%d" manifest:media-type="%s" />' % (rowdoc[0], rowdoc[4]),
                                           'width': _int(w),
                                           'height': _int(h)}

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
                content = ''
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
                                                       escape(row[5]),
                                                       escape(project), escape(page),
                                                       ('<meta:keyword>%s</meta:keyword>' % escape(row[7])) if row[7] != '' else '',
                                                       escape(row[2]),
                                                       escape(row[3]), escape(row[4]),
                                                       escape(user),
                                                       escape(dt['date']), escape(dt['time']),
                                                       row[0]))
            xml = odtStyles.styles
            xml = xml.replace('<!-- styles-code -->', odtStyles.getOptimizedCodeStyles(html) if odtGenerator.has_code else '')
            xml = xml.replace('<!-- styles-heading-format -->', odtStyles.getHeadingStyles(self._readEnv(sql, project, 'heading_mask')))
            if legal_notice != '':
                legal_notice = ''.join(['<text:p text:style-name="Footer">%s</text:p>' % line for line in legal_notice.split('\n')])
            xml = xml.replace('<!-- styles-footer -->', legal_notice)
            xml = xml.replace('fo:page-width=""', 'fo:page-width="%s"' % self._readEnv(sql, project, 'odt_page_width', '21cm').strip().replace(' ', '').replace(',', '.').replace('"', '\\"'))
            xml = xml.replace('fo:page-height=""', 'fo:page-height="%s"' % self._readEnv(sql, project, 'odt_page_height', '29.7cm').strip().replace(' ', '').replace(',', '.').replace('"', '\\"'))
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

    async def api_markdown(self: object, request: web.Request) -> web.Response:
        ''' Return the HTML corresponding to the posted Markdown '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the parameters
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        content = post.get('content', '')
        if project == '':
            raise web.HTTPBadRequest()

        # Verify that the user is able to write
        sql = app['sql'].cursor()
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
        html, _ = self._md2html(sql, project, None, content, cache=False)
        return web.Response(text=html, content_type=MIME_TEXT)

    async def api_user_create(self: object, request: web.Request) -> None:
        ''' API to create a new user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        wisheduser = post.get('user', '').strip().lower()
        newuser = _safeName(post.get('user', ''), extra='')
        if '' in [project, newuser] or (newuser[:4] == 'pwic'):
            raise web.HTTPBadRequest()
        if wisheduser != newuser:  # Invalid chars spotted
            raise web.HTTPFound('/special/create-user?project=%s&failed' % escape(project))

        # Verify that the user is administrator of the provided project
        ok = False
        sql = app['sql'].cursor()
        sql.execute(''' SELECT user
                        FROM roles
                        WHERE project  = ?
                          AND user     = ?
                          AND admin    = 'X'
                          AND disabled = '' ''',
                    (project, user))
        if sql.fetchone() is None:
            raise web.HTTPUnauthorized()

        # Create the new user
        if self._readEnv(sql, '', 'no_new_user_online') is not None:
            sql.execute(''' SELECT user
                            FROM users
                            WHERE user = ?''',
                        (newuser, ))
            if sql.fetchone() is None:
                raise web.HTTPFound('/special/create-user?project=%s&failed' % escape(project))
        else:
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
                        SELECT ?, ?, 'X'
                        WHERE NOT EXISTS ( SELECT 1 FROM roles WHERE project = ? AND user = ? )''',
                    (project, newuser, project, newuser))
        if sql.rowcount > 0:
            ok = True
            pwic_audit(sql, {'author': user,
                             'event': 'grant-reader',
                             'project': project,
                             'user': newuser},
                       request)
        self._commit()

        # Redirection
        raise web.HTTPFound('/%s/special/roles?%s' % (project, 'success' if ok else 'failed'))

    async def api_user_change_password(self: object, request: web.Request) -> None:
        ''' Change the password of the current user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user[:4] in ['', 'pwic']:
            raise web.HTTPUnauthorized()

        # Get the posted values
        ok = False
        post = await self._handlePost(request)
        current = post.get('password_current', '')
        new1 = post.get('password_new1', '')
        new2 = post.get('password_new2', '')
        if '' not in [current, new1, new2] and (new1 == new2) and (new1 != current):

            # Verify the format of the new password
            sql = app['sql'].cursor()
            mask = self._readEnv(sql, '', 'password_regex', '')
            if mask != '':
                try:
                    if re.compile(mask).match(new1) is None:
                        raise web.HTTPBadRequest()
                except Exception:
                    raise web.HTTPInternalServerError()

            # Verify the current password
            sql.execute(''' SELECT user FROM users
                            WHERE user = ? AND password = ?''',
                        (user, _sha256(current)))
            if sql.fetchone() is not None:
                # Update the password
                sql.execute("UPDATE users SET initial = '', password = ? WHERE user = ?", (_sha256(new1), user))
                if sql.rowcount > 0:
                    pwic_audit(sql, {'author': user,
                                     'event': 'change-password',
                                     'user': user},
                               request)
                self._commit()
                ok = True

        # Redirection
        raise web.HTTPFound('/special/user/%s?%s' % (user, 'success' if ok else 'failed'))

    async def api_user_roles_set(self: object, request: web.Request) -> web.Response:
        ''' Change the roles of a user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the posted values
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        userpost = post.get('name', '')
        roles = ['admin', 'manager', 'editor', 'validator', 'reader', 'disabled', 'delete']
        try:
            roleid = roles.index(post.get('role', ''))
            delete = (roles[roleid] == 'delete')
        except ValueError:
            raise web.HTTPBadRequest()
        if '' in [project, userpost] or (userpost[:4] == 'pwic' and roles in ['admin', 'delete']):
            raise web.HTTPBadRequest()

        # Select the current rights of the user
        sql = app['sql'].cursor()
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
        if row is None or (not delete and _xb(row[7])):
            raise web.HTTPUnauthorized()

        # Delete a user
        if delete:
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
                return web.Response(text='OK', content_type=MIME_TEXT)
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
                                 'event': '%s-%s' % ('grant' if _xb(newvalue) else 'ungrant', roles[roleid]),
                                 'project': project,
                                 'user': userpost},
                           request)
                self._commit()
                return web.Response(text=newvalue, content_type=MIME_TEXT)

    async def api_document_create(self: object, request: web.Request) -> None:
        ''' API to create a new document '''
        # Verify that the user is connected
        user = await self._suser(request)
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
        if doc['content'] is None or len(doc['content']) == 0 or '' in [doc['project'], doc['page'], doc['filename']]:  # The mime is checked later
            raise web.HTTPBadRequest()

        # Verify that the target folder exists
        if not isdir(PWIC_DOCUMENTS_PATH % doc['project']):
            raise web.HTTPInternalServerError()

        # Verify the authorizations
        sql = app['sql'].cursor()
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
            raise web.HTTPUnauthorized()
        current_revision = row[0]

        # Verify the consistency of the filename
        row = self._readEnv(sql, doc['project'], 'document_name_regex')
        if row is not None:
            try:
                regex_doc = re.compile(row, re.VERBOSE)
            except Exception:
                raise web.HTTPInternalServerError()
            if regex_doc.search(doc['filename']) is None:
                raise web.HTTPBadRequest()

        # Verify the file type
        if self._readEnv(sql, '', 'mime_enforcement') is not None:
            if not self._checkMime(doc):
                raise web.HTTPUnsupportedMediaType()
        if re.compile(PWIC_REGEX_MIME).match(doc['mime']) is None:
            raise web.HTTPBadRequest()

        # Verify the maximal document size
        maxsize = _int(self._readEnv(sql, doc['project'], 'max_document_size'))
        if maxsize != 0 and len(doc['content']) > maxsize:
            raise web.HTTPRequestEntityTooLarge(maxsize, len(doc['content']))

        # Verify the maximal project size
        # ... is there a check ?
        max_project_size = self._readEnv(sql, doc['project'], 'max_project_size')
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
        if self._readEnv(sql, '', 'maintenance') is not None:
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
                    remove(fn)
                except Exception:
                    if isfile(fn):
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
                   request)
        self._commit()
        raise web.HTTPOk()

    async def api_document_list(self: object, request: web.Request) -> web.Response:
        ''' Return the list of the attached documents '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Read the parameters
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        page = _safeName(post.get('page', ''))
        if '' in [project, page]:
            raise web.HTTPBadRequest()

        # Read the documents
        sql = app['sql'].cursor()
        markdown = sql.execute(''' SELECT markdown
                                   FROM pages
                                   WHERE project = ?
                                     AND page    = ?
                                     AND latest  = 'X' ''',
                               (project, page)).fetchone()[0]
        sql.execute(''' SELECT b.id, b.filename, b.mime, b.size, b.hash, b.author, b.date, b.time
                        FROM roles AS a
                            INNER JOIN documents AS b
                                ON  b.project = a.project
                                AND b.page    = ?
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.disabled = ''
                        ORDER BY b.filename''',
                    (page, project, user))
        result = []
        for row in sql.fetchall():
            result.append({'id': row[0],
                           'filename': row[1],
                           'mime': row[2],
                           'mime_icon': _mime2icon(row[2]),
                           'size': _size2str(row[3]),
                           'hash': row[4],
                           'author': row[5],
                           'date': row[6],
                           'time': row[7],
                           'used': ('(/special/document/%d)' % row[0]) in markdown or ('(/special/document/%d "' % row[0]) in markdown})
        return web.Response(text=json.dumps(result), content_type=MIME_JSON)

    async def api_document_delete(self: object, request: web.Request) -> None:
        ''' Delete a document '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the revision to delete
        post = await self._handlePost(request)
        project = _safeName(post.get('project', ''))
        page = _safeName(post.get('page', ''))
        id = _int(post.get('id', 0))
        filename = _safeFileName(post.get('filename', ''))
        if '' in [project, page, filename] or id == 0:
            raise web.HTTPBadRequest()

        # Verify that the deletion is possible
        sql = app['sql'].cursor()
        sql.execute(''' SELECT b.id
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
        if sql.fetchone() is None:
            raise web.HTTPUnauthorized()  # Or not found

        # Delete the file
        fn = (PWIC_DOCUMENTS_PATH % project) + filename
        try:
            remove(fn)
        except (OSError, FileNotFoundError):
            if isfile(fn):
                raise web.HTTPInternalServerError()

        # Delete the index
        sql.execute('DELETE FROM documents WHERE id = ?', (id, ))
        pwic_audit(sql, {'author': user,
                         'event': 'delete-document',
                         'project': project,
                         'page': page,
                         'string': filename},
                   request)
        self._commit()
        raise web.HTTPOk()

    async def api_swagger(self: object, request: web.Request) -> web.Response:
        ''' Display the features of the API '''
        return await self._handleOutput(request, 'page-swagger', {'title': 'API specification'})


# ====================
#  Server entry point
# ====================

app = None


def main() -> bool:
    global app

    # Command-line
    parser = argparse.ArgumentParser(description='Pwic Server version %s' % PWIC_VERSION)
    parser.add_argument('--host', default='127.0.0.1', help='Listening host')
    parser.add_argument('--port', type=int, default=8080, help='Listening port')
    parser.add_argument('--sql-trace', action='store_true', help='Display the SQL queries in the console for debugging purposes')
    args = parser.parse_args()

    # Modules
    app = web.Application()
    # ... launch time
    app['up'] = _dt()
    # ... languages
    app['langs'] = sorted([f for f in listdir(PWIC_TEMPLATES_PATH) if isdir(join(PWIC_TEMPLATES_PATH, f))])
    if PWIC_DEFAULT_LANGUAGE not in app['langs']:
        print('Error: English template is missing')
        return False
    # ... templates
    app['jinja'] = Environment(loader=FileSystemLoader(PWIC_TEMPLATES_PATH), trim_blocks=True, lstrip_blocks=True)
    # ... SQLite
    app['sql'] = sqlite3.connect(PWIC_DB_SQLITE)
    if args.sql_trace:
        app['sql'].set_trace_callback(_sqlprint)
    sql = app['sql'].cursor()
    sql.execute('PRAGMA optimize')
    pwic_audit(sql, {'author': PWIC_USER_SYSTEM,
                     'event': 'start-server'})
    app['sql'].commit()
    # ... PWIC
    app['pwic'] = PwicServer()
    setup(app, EncryptedCookieStorage(urandom(32)))  # Storage for cookies
    # ... Markdown parser
    app['markdown'] = Markdown(extras=['tables', 'footnotes', 'fenced-code-blocks', 'strike', 'underline'],
                               safe_mode=app['pwic']._readEnv(sql, '', 'safe_mode') is not None)

    # Routes
    app.router.add_static('/static/', path='./static/', append_version=False)
    app.add_routes([web.post('/api/logon', app['pwic'].api_logon),
                    web.get('/api/logout', app['pwic'].api_logout),
                    web.get('/api/oauth', app['pwic'].api_oauth),
                    web.post('/api/server/env/get', app['pwic'].api_server_env_get),
                    web.post('/api/server/ping', app['pwic'].api_server_ping),
                    web.post('/api/project/info/get', app['pwic'].api_project_info_get),
                    web.post('/api/project/env/set', app['pwic'].api_project_env_set),
                    web.post('/api/project/progress/get', app['pwic'].api_project_progress_get),
                    web.post('/api/project/graph/get', app['pwic'].api_project_graph_get),
                    web.post('/api/page/create', app['pwic'].api_page_create),
                    web.post('/api/page/edit', app['pwic'].api_page_edit),
                    web.post('/api/page/validate', app['pwic'].api_page_validate),
                    web.post('/api/page/delete', app['pwic'].api_page_delete),
                    web.post('/api/page/export', app['pwic'].api_page_export),
                    web.post('/api/markdown/convert', app['pwic'].api_markdown),
                    web.post('/api/user/create', app['pwic'].api_user_create),
                    web.post('/api/user/password/change', app['pwic'].api_user_change_password),
                    web.post('/api/user/roles/set', app['pwic'].api_user_roles_set),
                    web.post('/api/document/create', app['pwic'].api_document_create),
                    web.post('/api/document/list', app['pwic'].api_document_list),
                    web.post('/api/document/delete', app['pwic'].api_document_delete),
                    web.get('/api', app['pwic'].api_swagger),
                    web.get('/special/logon', app['pwic']._handleLogon),
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
                    web.get(r'/{project:[^\/]+}/special/export', app['pwic'].project_export),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}/rev{new_revision:[0-9]+}/compare/rev{old_revision:[0-9]+}', app['pwic'].page_compare),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}/rev{revision:[0-9]+}', app['pwic'].page),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}/{action:view|edit|history}', app['pwic'].page),
                    web.get(r'/special/document/{id:[0-9]+}/{dummy:[^\/]+}', app['pwic'].document_get),
                    web.get(r'/special/document/{id:[0-9]+}', app['pwic'].document_get),
                    web.get(r'/{project:[^\/]+}/{page:[^\/]+}', app['pwic'].page),
                    web.get(r'/{project:[^\/]+}', app['pwic'].page),
                    web.get('/', app['pwic'].page)])

    # SSL
    if app['pwic']._readEnv(sql, '', 'ssl') is None:
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
    if app['pwic']._readEnv(sql, '', 'cors') is None:
        app['cors'] = None
    else:
        import aiohttp_cors
        app['cors'] = aiohttp_cors.setup(app, defaults={'*': aiohttp_cors.ResourceOptions(allow_headers='*')})  # expose_headers='*'
        for route in list(app.router.routes()):
            app['cors'].add(route)

    # General options of the server
    app['no_logon'] = app['pwic']._readEnv(sql, '', 'no_logon') is not None
    app['oauth'] = {'provider': app['pwic']._readEnv(sql, '', 'oauth_provider', None),
                    'tenant': app['pwic']._readEnv(sql, '', 'oauth_tenant', ''),
                    'identifier': app['pwic']._readEnv(sql, '', 'oauth_identifier', ''),
                    'server_secret': app['pwic']._readEnv(sql, '', 'oauth_secret', ''),
                    'domains': _list(app['pwic']._readEnv(sql, '', 'oauth_domains')),
                    'projects': _list(app['pwic']._readEnv(sql, '', 'oauth_projects'))}

    # Compile the IP filters
    def _compile_ip():
        nonlocal sql
        app['ip_filter'] = []
        for mask in app['pwic']._readEnv(sql, '', 'ip_filter', '').split(' '):
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
    app['xff'] = app['pwic']._readEnv(sql, '', 'xff') is not None

    # Logging
    logfile = app['pwic']._readEnv(sql, '', 'http_log_file', '')
    logformat = app['pwic']._readEnv(sql, '', 'http_log_format', PWIC_DEFAULT_LOGGING_FORMAT)
    if logfile != '':
        import logging
        logging.basicConfig(filename=logfile, datefmt='%d/%m/%Y %H:%M:%S', level=logging.INFO)

    # Launch the server
    del sql
    web.run_app(app,
                host=args.host,
                port=args.port,
                ssl_context=https,
                access_log_format=logformat)
    return True


main()
