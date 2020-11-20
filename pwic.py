#!/usr/bin/env python

import argparse
from aiohttp import web, MultipartReader, hdrs
from aiohttp_session import setup, get_session, new_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from urllib.parse import parse_qs, quote
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
from base64 import b64encode

from pwic_md import Markdown
from pwic_lib import PWIC_VERSION, PWIC_DB, PWIC_DB_SQLITE, PWIC_DOCUMENTS_PATH, PWIC_USER_ANONYMOUS, \
    PWIC_USER_SYSTEM, PWIC_DEFAULT_PASSWORD, PWIC_DEFAULT_LANGUAGE, PWIC_DEFAULT_PAGE, \
    PWIC_PRIVATE_KEY, PWIC_PUBLIC_KEY, PWIC_REGEX_PAGE, PWIC_REGEX_DOCUMENT, PWIC_REGEX_MIME, PWIC_REGEX_HTML_TAG, \
    PWIC_EMOJIS, PWIC_CHARS_UNSAFE, MIME_BMP, MIME_JSON, MIME_GENERIC, MIME_SVG, MIME_TEXT, PWIC_MIMES, \
    _x, _xb, _int, _dt, _recursiveReplace, _sha256, _safeName, _safeFileName, _size2str, \
    pwic_extended_syntax, pwic_audit, pwic_search_parse, pwic_search_tostring, pwic_html2odt
from pwic_styles import pwic_styles_html, pwic_styles_odt


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

    def _mime2icon(self: object, mime: str) -> str:
        ''' Return the emojis that corresponds to the MIME '''
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

    def _attachmentName(self: object, name: str) -> str:
        ''' Return the file name for a proper download '''
        return "=?utf-8?B?%s?=" % (b64encode(name.encode()).decode())

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

    def _checkIP(self: object, request: object, sql: object) -> None:
        ''' Handle the HTTP request to check the IP address '''
        # Initialization
        okIncl = False
        hasIncl = False
        koExcl = False
        try:
            # Read the parameters
            ip = request.remote
            mask = self._readEnv(sql, '', 'ip_filter')
            if mask in [None, '']:
                return
            list = mask.split(';')

            # Filter the IP
            for item in list:
                item = item.strip()
                if item == '':
                    continue

                # Negation flag
                negate = item[:1] == '~'
                if negate:
                    item = item[1:]

                # Condition types
                # ... networks
                if '/' in item:
                    condition = ip_address(ip) in ip_network(item)
                # ... mask for IP
                elif '*' in item or '?' in item:
                    regex_ip = re.compile(item.replace('.', '\\.').replace('?', '.').replace('*', '.*'))
                    condition = regex_ip.match(ip) is not None
                # ... raw IP
                else:
                    condition = (item == ip)

                # Evaluation
                if negate:
                    koExcl = koExcl or condition
                    if koExcl:  # Boolean accelerator
                        break
                else:
                    okIncl = okIncl or condition
                    hasIncl = True
        except Exception:
            raise web.HTTPInternalServerError()
        if koExcl or (hasIncl != okIncl):
            raise web.HTTPUnauthorized()

    async def _suser(self: object, request: object) -> str:
        ''' Retrieve the logged user '''
        if app['no_logon']:
            return PWIC_USER_ANONYMOUS
        else:
            session = await get_session(request)
            return session.get('user', '')

    async def _handlePost(self: object, request: object) -> object:
        ''' Return the POST as a readable object.get() '''
        result = {}
        if request.body_exists:
            data = await request.text()
            result = parse_qs(data)
            for res in result:
                result[res] = result[res][0]
        return result

    async def _handleLogon(self: object, request: object) -> str:
        ''' Show the logon page '''
        return await self._handleOutput(request, 'logon', {'title': 'Connect to Pwic'})

    async def _handleOutput(self: object, request: object, name: str, pwic: object) -> object:
        ''' Serve the right template, in the right language, with the right PWIC structure and additional data '''
        pwic['user'] = await self._suser(request)
        pwic['emojis'] = PWIC_EMOJIS
        pwic['constants'] = {'anonymous_user': PWIC_USER_ANONYMOUS,
                             'db_path': PWIC_DB,
                             'default_language': PWIC_DEFAULT_LANGUAGE,
                             'languages': app['langs'],
                             'unsafe_chars': PWIC_CHARS_UNSAFE,
                             'version': PWIC_VERSION}

        # Check the access by IP
        sql = app['sql'].cursor()
        self._checkIP(request, sql)

        # The project-dependent variables have the priority
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
            if key not in pwic['env']:
                pwic['env'][key] = {'value': value,
                                    'global': global_}
                if key in ['max_document_size', 'max_project_size']:
                    pwic['env'][key + '_str'] = {'value': _size2str(_int(value)),
                                                 'global': global_}

        # Render the template
        session = await get_session(request)
        pwic['language'] = session.get('language', PWIC_DEFAULT_LANGUAGE)
        template = app['jinja'].get_template('%s/%s.html' % (pwic['language'], name))
        return web.Response(text=template.render(pwic=pwic), content_type='text/html')

    async def page(self: object, request: object) -> object:
        ''' Serve the pages '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Show the requested page
        sql = app['sql'].cursor()
        project = _safeName(request.match_info.get('project', ''))
        page = _safeName(request.match_info.get('page', PWIC_DEFAULT_PAGE))
        page_special = (page == 'special')
        revision = _int(request.match_info.get('revision', 0))
        action = request.match_info.get('action', 'view')
        pwic = {'title': 'Wiki',
                'project': project,
                'page': page,
                'revision': revision}
        dt = _dt()

        # Fetch the name of the project...
        if project != '':
            sql.execute(''' SELECT b.description, a.admin, a.manager, a.editor, a.validator, a.reader
                            FROM roles AS a
                                INNER JOIN projects AS b
                                    ON b.project = a.project
                            WHERE a.project  = ?
                              AND a.user     = ?
                              AND a.disabled = ''
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
                pwic['projects'].append({'project': row[0], 'description': row[1]})
            if len(pwic['projects']) == 1:
                raise web.HTTPTemporaryRedirect('/%s' % pwic['projects'][0]['project'])
            else:
                return await self._handleOutput(request, 'project-select', pwic)

        # Fetch the links of the header line
        sql.execute(''' SELECT a.page, a.title
                        FROM pages AS a
                        WHERE a.project = ?
                          AND a.header = 'X'
                        ORDER BY a.title''',
                    (project, ))
        pwic['links'] = []
        for row in sql.fetchall():
            pwic['links'].append({'project': project,
                                  'page': row[0],
                                  'title': row[1]})
            if row[0] == PWIC_DEFAULT_PAGE:
                pwic['links'].insert(0, pwic['links'].pop())    # Push to top of list because it is the home page

        # Fetch the name of the page
        if page != '':
            if page_special:
                row = ['Special']
            else:
                sql.execute(''' SELECT title
                                FROM pages
                                WHERE project = ?
                                  AND page    = ?
                                  AND latest  = 'X' ''',
                            (project, page))
                row = sql.fetchone()
                if row is None:
                    raise web.HTTPNotFound()  # Page not found
            pwic['page_title'] = row[0]

            # Show the requested page (not necessarily the latest one)
            if action == 'view':
                if not page_special:
                    sql.execute(''' SELECT revision, latest, draft, final, protection,
                                           author, date, time, title, markdown,
                                           tags, valuser, valdate, valtime
                                    FROM pages
                                    WHERE   project  = ?
                                      AND   page     = ?
                                      AND ( revision = ?
                                       OR ( 0 = ?
                                        AND latest   = 'X' )
                                      )''',
                                (project, page, revision, revision))
                    row = sql.fetchone()
                    if row is None:
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
                                    ORDER BY disabled  DESC,
                                             admin     DESC,
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
                                                  'mime_icon': self._mime2icon(row[4]),
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
                return await self._handleOutput(request, 'page-special' if page_special else 'page', pwic)

            # Edit the requested page
            elif action == 'edit':
                sql.execute(''' SELECT draft, final, header, protection, title, markdown, tags, milestone
                                FROM pages
                                WHERE project = ?
                                  AND page    = ?
                                  AND latest  = 'X' ''',
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
                pwic['tags'] = row[6]
                pwic['milestone'] = row[7]
                return await self._handleOutput(request, 'page-edit', pwic)

            # Show the history of the page
            elif action == 'history':
                sql.execute(''' SELECT revision, latest, draft, final, author,
                                       date, time, title, comment, milestone,
                                       valuser, valdate, valtime
                                FROM pages
                                WHERE project = ?
                                  AND page = ?
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

    async def page_help(self: object, request: object) -> object:
        ''' Serve the help page to any user '''
        pwic = {'project': 'special',
                'page': 'help',
                'title': 'Help for Pwic'}
        return await self._handleOutput(request, 'help', pwic)

    async def page_create(self: object, request: object) -> object:
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

    async def user_create(self: object, request: object) -> object:
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

    async def page_user(self: object, request: object) -> object:
        ''' Serve the page to view the profile of a user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Fetch the information of the user
        sql = app['sql'].cursor()
        userpage = _safeName(request.match_info.get('userpage', None), extra='')
        sql.execute('SELECT initial FROM users WHERE user = ?', (userpage, ))
        row = sql.fetchone()
        if row is None:
            raise web.HTTPNotFound()
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

    async def page_search(self: object, request: object) -> object:
        ''' Serve the search engine '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Parse the query
        sql = app['sql'].cursor()
        project = _safeName(request.match_info.get('project', ''))
        terms = request.rel_url.query.get('q', '')
        query = pwic_search_parse(terms)
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
        sql.execute(''' SELECT a.project, a.page, a.draft, a.final, a.author,
                               a.date, a.time, a.title, LOWER(a.markdown), a.tags,
                               a.valuser, b.document_count
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
                          AND a.latest  = 'X'
                        ORDER BY a.date DESC,
                                 a.time DESC''',
                    (project, project))
        for row in sql.fetchall():
            tagList = row[9].split(' ')         # Tags

            # Apply the filters
            ok = True
            score = 0
            for q in query['excluded']:         # The first occurrence of an excluded term excludes the whole page
                if (q == ':draft' and _xb(row[2]))                              \
                   or (q == ':final' and _xb(row[3]))                           \
                   or (q[:7] == 'author:' and q[7:] in row[4].lower())          \
                   or (q[:6] == 'title:' and q[6:] in row[7].lower())           \
                   or (q == ':validated' and row[10] != '')                     \
                   or (q[:10] == 'validator:' and q[10:] in row[10].lower())    \
                   or (q == ':document' and _int(row[11]) > 0)                  \
                   or (q[1:] in tagList if q[:1] == '#' else False)             \
                   or (q == row[1].lower())                                     \
                   or (q in row[8]):
                    ok = False
                    break
            if ok:
                for q in query['included']:     # The first non-occurrence of an included term excludes the whole page
                    if q == ':draft':
                        count = _int(_xb(row[2]))
                    elif q == ':final':
                        count = _int(_xb(row[3]))
                    elif q[:7] == 'author:':
                        count = row[4].lower().count(q[7:])
                    elif q[:6] == 'title:':
                        count = row[7].lower().count(q[6:])
                    elif q == ':validated':
                        count = _int(row[10] != '')
                    elif q[:10] == 'validator:':
                        count = _int(q[10:] in row[10].lower())
                    elif q == ':document':
                        count = _int(_int(row[11]) > 0)
                    elif (q[1:] in tagList if q[:1] == '#' else False):
                        count = 5               # A tag counts more
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
            pwic['pages'].append({'project': row[0],
                                  'page': row[1],
                                  'author': row[4],
                                  'date': row[5],
                                  'time': row[6],
                                  'title': row[7],
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
                                      'mime_icon': self._mime2icon(row[4]),
                                      'size': _size2str(row[5]),
                                      'author': row[6],
                                      'date': row[7],
                                      'time': row[8]})

        # Show the pages by score desc and title asc
        pwic['pages'].sort(key=lambda x: x['title'])
        pwic['pages'].sort(key=lambda x: x['score'], reverse=True)
        return await self._handleOutput(request, 'search', pwic=pwic)

    async def page_roles(self: object, request: object) -> object:
        ''' Serve the search engine '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Fetch the roles
        sql = app['sql'].cursor()
        project = _safeName(request.match_info.get('project', ''))
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
                                  'reader': _xb(row[6]),
                                  'disabled': _xb(row[7])})
        if len(pwic['roles']) == 0:
            raise web.HTTPUnauthorized()        # Or project not found
        else:
            return await self._handleOutput(request, 'user-roles', pwic=pwic)

    async def page_links(self: object, request: object) -> object:
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

    async def page_graph(self: object, request: object) -> object:
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

    async def page_compare(self: object, request: object) -> object:
        ''' Serve the page that compare two revisions '''
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

        pwic = {'title': 'Comparison',
                'project': project,
                'project_description': row[0],
                'page': page,
                'page_title': row[1],
                'new_revision': new_revision,
                'old_revision': old_revision,
                'diff': _diff(row[3], row[2])}
        return await self._handleOutput(request, 'page-compare', pwic=pwic)

    async def project_export(self: object, request: object) -> object:
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

        # Build the zip file
        if len(pages) == 0:
            raise web.HTTPUnauthorized()
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
            sql.execute('SELECT filename FROM documents WHERE project = ?', (project, ))
            for row in sql.fetchall():
                fn = (PWIC_DOCUMENTS_PATH % project) + row[0]
                if isfile(fn):
                    content = ''
                    with open(fn, 'rb') as f:
                        content = f.read()
                    zip.writestr('documents/%s' % row[0], content)
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
        return web.Response(body=content, headers=MultiDict({'Content-Disposition': 'attachment; filename="%s"' % self._attachmentName(project + '.zip')}))

    async def document_get(self: object, request: object) -> object:
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
            headers['Content-Disposition'] = 'attachment; filename="%s"' % self._attachmentName(row[1])
        return web.Response(body=content, headers=MultiDict(headers))

    async def api_logon(self: object, request: object) -> object:
        ''' API to log on people '''
        # Checks
        if app['no_logon']:
            raise web.HTTPBadRequest()
        sql = app['sql'].cursor()
        self._checkIP(request, sql)

        # Fetch the submitted data
        post = await self._handlePost(request)
        user = _safeName(post.get('logon_user', ''), extra='')
        pwd = '' if user == PWIC_USER_ANONYMOUS else _sha256(post.get('logon_password', ''))
        lang = post.get('logon_language', PWIC_DEFAULT_LANGUAGE)
        if lang not in app['langs']:
            lang = PWIC_DEFAULT_LANGUAGE

        # Logon with the credentials
        ok = False
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

    async def api_logout(self: object, request: object) -> object:
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

    async def api_server_env(self: object, request: object) -> object:
        ''' API to return the defined environment variables '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('env_project', ''))

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
            if key not in data:
                data[key] = {'value': value,
                             'global': global_}

        # Final result
        return web.Response(text=json.dumps(data), content_type=MIME_JSON)

    async def api_server_ping(self: object, request: object) -> object:
        ''' Notify if the session is still alive '''
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()
        else:
            return web.Response(text='OK', content_type=MIME_TEXT)

    async def api_project_info(self: object, request: object) -> object:
        ''' API to fetch the metadata of the project '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('info_project', ''))
        if project == '':
            raise web.HTTPBadRequest()
        all = post.get('info_all', '') != ''
        data = {}

        # Fetch the pages
        sql = app['sql'].cursor()
        exposeMD = self._readEnv(sql, project, 'api_expose_markdown', None) is not None
        sql.execute(''' SELECT b.page, b.revision, b.latest, b.draft, b.final,
                               b.header, b.protection, b.author, b.date, b.time,
                               b.title, b.markdown, b.tags, b.comment, b.milestone,
                               b.valuser, b.valdate, b.valtime
                        FROM roles AS a
                            INNER JOIN pages AS b
                                ON  b.project = a.project
                                AND b.latest IN ("%sX")
                        WHERE a.project  = ?
                          AND a.user     = ?
                          AND a.disabled = ''
                        ORDER BY b.page ASC,
                                 b.revision DESC''' % ('","' if all else '', ),
                    (project, user))
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
                                ON b.project = a.project
                            INNER JOIN pages AS c
                                ON  c.project = a.project
                                AND c.page    = b.page
                                AND c.latest  = 'X'
                        WHERE a.project   = ?
                          AND a.user      = ?
                          AND a.validator = 'X'
                          AND a.disabled  = ''
                        ORDER BY b.page, b.filename''',
                    (project, user))
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

    async def api_project_progress(self: object, request: object) -> object:
        ''' API to analyze the progress of the project '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('progress_project', ''))
        tags = post.get('progress_tags', '').strip()
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

    async def api_project_graph(self: object, request: object) -> None:
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
        project = _safeName(post.get('graph_project', ''))
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

    async def api_page_create(self: object, request: object) -> None:
        ''' API to create a new page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('create_project', ''))
        page = _safeName(post.get('create_page', ''))
        milestone = post.get('create_milestone', '').strip()
        ref_project = _safeName(post.get('create_ref_project', ''))
        ref_page = _safeName(post.get('create_ref_page', ''))
        ref_tags = _x('create_ref_tags' in post)
        if project in ['', 'api', 'special'] or page in ['', 'special']:
            raise web.HTTPBadRequest()

        # Verify that the user is manager of the provided project, and that the page doesn't exist yet
        sql = app['sql'].cursor()
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
            raise web.HTTPTemporaryRedirect('/special/create-page?failed')

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
                raise web.HTTPTemporaryRedirect('/special/create-page?failed')
            default_markdown = row[0]
            if ref_tags:
                default_tags = row[1]

        # Handle the creation of the page
        dt = _dt()
        revision = 1
        sql.execute(''' INSERT INTO pages (project, page, revision, author, date, time, title, markdown, tags, comment, milestone)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (project, page, revision, user, dt['date'], dt['time'], page, default_markdown, default_tags, 'Initial', milestone))
        assert(sql.rowcount > 0)
        pwic_audit(sql, {'author': user,
                         'event': 'create-page',
                         'project': project,
                         'page': page,
                         'revision': revision},
                   request)
        self._commit()
        raise web.HTTPFound('/%s/%s?success' % (project, page))

    async def api_page_edit(self: object, request: object) -> None:
        ''' API to update an existing page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('edit_project', ''))
        page = _safeName(post.get('edit_page', ''))
        title = post.get('edit_title', '').strip()
        markdown = post.get('edit_markdown', '')
        tags = post.get('edit_tags', '')
        comment = post.get('edit_comment', '').strip()
        milestone = post.get('edit_milestone', '').strip()
        draft = _x('edit_draft' in post)
        final = _x('edit_final' in post)
        protection = _x('edit_protection' in post)
        header = _x('edit_header' in post)
        dt = _dt()
        if '' in [user, project, page, title, comment]:
            raise web.HTTPBadRequest()
        if final:
            draft = ''

        # Reprocess the tags in alphabetical order
        tags = _recursiveReplace(tags.replace('\t', ' ').strip().lower(), '  ', ' ')
        tags = ' '.join(sorted(list(set(tags.split(' ')))))

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
                    (project, page, revision + 1, draft, final, header,
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

    async def api_page_markdown(self: object, request: object) -> object:
        ''' Return the HTML corresponding to the posted Markdown '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the parameters
        post = await self._handlePost(request)
        project = _safeName(post.get('markdown_project', ''))
        content = post.get('markdown_content', '')
        if project == '':
            raise web.HTTPBadRequest()

        # Return the converted output
        html, _ = self._md2html(app['sql'].cursor(), project, None, content, cache=False)
        return web.Response(text=html, content_type=MIME_TEXT)

    async def api_page_validate(self: object, request: object) -> None:
        ''' Validate the pages '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the revision to validate
        post = await self._handlePost(request)
        project = _safeName(post.get('validate_project', ''))
        page = _safeName(post.get('validate_page', ''))
        revision = _int(post.get('validate_revision', 0))
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

    async def api_page_delete(self: object, request: object) -> None:
        ''' Delete a page upon administrative request '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the revision to delete
        post = await self._handlePost(request)
        project = _safeName(post.get('delete_project', ''))
        page = _safeName(post.get('delete_page', ''))
        revision = _int(post.get('delete_revision', 0))
        if '' in [project, page] or revision == 0:
            raise web.HTTPBadRequest()

        # Verify that the deletion is possible
        if (page == PWIC_DEFAULT_PAGE) and (revision == 1):
            raise web.HTTPUnauthorized()    # Deleting the first page when a project is freshly created may stuck the user at the error 404
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
                        raise web.HTTPTemporaryRedirect('/%s/%s?failed' % (project, page))

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

    async def api_page_export(self: object, request: object) -> object:
        ''' API to export a page '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Read the parameters
        post = await self._handlePost(request)
        project = _safeName(post.get('export_project', ''))
        page = _safeName(post.get('export_page', ''))
        revision = _int(post.get('export_revision', 0))
        format = post.get('export_format', '').lower()
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
        endname = self._attachmentName('%s_%s_rev%d.%s' % (project, page, row[0], format))

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
                                           'uncompressed': rowdoc[4] in [MIME_BMP, MIME_SVG],
                                           'manifest': '<manifest:file-entry manifest:full-path="special/document/%d" manifest:media-type="%s" />' % (rowdoc[0], rowdoc[4]),
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
                    odt.writestr(meta['link'], content)
                else:
                    odt.writestr(meta['link'], content, compress_type=zipfile.ZIP_STORED, compresslevel=0)
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

    async def api_user_create(self: object, request: object) -> None:
        ''' API to create a new user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            return await self._handleLogon(request)

        # Fetch the submitted data
        post = await self._handlePost(request)
        project = _safeName(post.get('create_project', ''))
        wisheduser = post.get('create_user', '').strip().lower()
        newuser = _safeName(post.get('create_user', ''), extra='')
        if '' in [project, newuser] or (newuser[:4] == 'pwic'):
            raise web.HTTPBadRequest()
        if wisheduser != newuser:  # Invalid chars spotted
            raise web.HTTPTemporaryRedirect('/special/create-user?project=%s&failed' % escape(project))

        # Verify that the user is administrator of the provided project
        ok = False
        sql = app['sql'].cursor()
        sql.execute(''' SELECT user FROM roles
                        WHERE project  = ?
                          AND user     = ?
                          AND admin    = 'X'
                          AND disabled = '' ''',
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
        if ok:
            raise web.HTTPFound('/%s/special/roles?success' % project)
        else:
            raise web.HTTPTemporaryRedirect('/%s/special/roles?failed' % project)

    async def api_user_change_password(self: object, request: object) -> None:
        ''' Change the password of the current user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user[:4] in ['', 'pwic']:
            raise web.HTTPUnauthorized()

        # Get the posted values
        ok = False
        post = await self._handlePost(request)
        current = post.get('user_password_current', '')
        new1 = post.get('user_password_new1', '')
        new2 = post.get('user_password_new2', '')
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
        if ok:
            raise web.HTTPFound('/special/user/%s?success' % user)
        else:
            raise web.HTTPTemporaryRedirect('/special/user/%s?failed' % user)

    async def api_user_roles(self: object, request: object) -> object:
        ''' Change the roles of a user '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the posted values
        post = await self._handlePost(request)
        project = _safeName(post.get('user_project', ''))
        userpost = post.get('user_name', '')
        roles = ['admin', 'manager', 'editor', 'validator', 'reader', 'disabled', 'delete']
        try:
            roleid = roles.index(post.get('user_role', ''))
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

    async def api_document_create(self: object, request: object) -> None:
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
                if name[:9] == 'document_':
                    name = name[9:]
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

    async def api_document_list(self: object, request: object) -> object:
        ''' Return the list of the attached documents '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Read the parameters
        post = await self._handlePost(request)
        project = _safeName(post.get('document_project', ''))
        page = _safeName(post.get('document_page', ''))
        if '' in [project, page]:
            raise web.HTTPBadRequest()

        # Read the documents
        sql = app['sql'].cursor()
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
                           'mime_icon': self._mime2icon(row[2]),
                           'size': _size2str(row[3]),
                           'hash': row[4],
                           'author': row[5],
                           'date': row[6],
                           'time': row[7]})
        return web.Response(text=json.dumps(result), content_type=MIME_JSON)

    async def api_document_delete(self: object, request: object) -> None:
        ''' Delete a document '''
        # Verify that the user is connected
        user = await self._suser(request)
        if user == '':
            raise web.HTTPUnauthorized()

        # Get the revision to delete
        post = await self._handlePost(request)
        project = _safeName(post.get('document_project', ''))
        page = _safeName(post.get('document_page', ''))
        id = _int(post.get('document_id', 0))
        filename = _safeFileName(post.get('document_filename', ''))
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

    async def api_swagger(self: object, request: object) -> object:
        ''' Display the features of the API '''
        return await self._handleOutput(request, 'page-swagger', {'title': 'API specification'})


# ====================
#  Server entry point
# ====================

app = None


def main() -> bool:
    global app

    # Command-line
    parser = argparse.ArgumentParser(description='Pwic Server')
    parser.add_argument('--host', default='127.0.0.1', help='Listening host')
    parser.add_argument('--port', type=int, default=1234, help='Listening port')
    args = parser.parse_args()

    # Modules
    app = web.Application()
    # ... languages
    app['langs'] = sorted([f for f in listdir('templates/') if isdir(join('templates/', f))])
    if PWIC_DEFAULT_LANGUAGE not in app['langs']:
        print('Error: English template is missing')
        return False
    # ... templates
    app['jinja'] = Environment(loader=FileSystemLoader('./templates/'))
    # ... SQLite
    app['sql'] = sqlite3.connect(PWIC_DB_SQLITE)
    # app['sql'].set_trace_callback(print)
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
    app.router.add_static('/static/', path='./static/')
    app.add_routes([web.post('/api/logon', app['pwic'].api_logon),
                    web.get('/api/logout', app['pwic'].api_logout),
                    web.post('/api/server/env', app['pwic'].api_server_env),
                    web.post('/api/server/ping', app['pwic'].api_server_ping),
                    web.post('/api/project/info', app['pwic'].api_project_info),
                    web.post('/api/project/progress', app['pwic'].api_project_progress),
                    web.post('/api/project/graph', app['pwic'].api_project_graph),
                    web.post('/api/page/create', app['pwic'].api_page_create),
                    web.post('/api/page/edit', app['pwic'].api_page_edit),
                    web.post('/api/page/markdown', app['pwic'].api_page_markdown),
                    web.post('/api/page/validate', app['pwic'].api_page_validate),
                    web.post('/api/page/delete', app['pwic'].api_page_delete),
                    web.post('/api/page/export', app['pwic'].api_page_export),
                    web.post('/api/user/create', app['pwic'].api_user_create),
                    web.post('/api/user/password/change', app['pwic'].api_user_change_password),
                    web.post('/api/user/roles', app['pwic'].api_user_roles),
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

    # No logon
    app['no_logon'] = app['pwic']._readEnv(sql, '', 'no_logon') is not None

    # Launch the server
    del sql
    web.run_app(app, host=args.host, port=args.port, ssl_context=https)
    return True


main()
