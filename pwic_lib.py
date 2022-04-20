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

from typing import Any, Dict, List, Optional, Tuple, Union
import sqlite3
import re
from collections import OrderedDict
from datetime import datetime, timedelta
from os import urandom
from os.path import splitext
from hashlib import sha256
from base64 import b64encode
from aiohttp import web
from html import escape
from html.parser import HTMLParser
from parsimonious.grammar import Grammar
from parsimonious.nodes import NodeVisitor
from string import ascii_lowercase, ascii_uppercase


# ===================================================
#  Constants
# ===================================================

# Paths
PWIC_VERSION = '1.0-rc7'
PWIC_DB = './db'
PWIC_DB_SQLITE = PWIC_DB + '/pwic.sqlite'
PWIC_DB_SQLITE_BACKUP = PWIC_DB + '/pwic_%s.sqlite'
PWIC_DB_SQLITE_AUDIT = PWIC_DB + '/pwic_audit.sqlite'
PWIC_DOCUMENTS_PATH = PWIC_DB + '/documents/%s/'
PWIC_TEMPLATES_PATH = './templates/'

# Security + HTTPS
PWIC_SALT = ''                                      # Random string to secure the generated hashes for the passwords
PWIC_PRIVATE_KEY = 'db/pwic_https.key'
PWIC_PUBLIC_KEY = 'db/pwic_https.crt'
PWIC_CHARS_UNSAFE = '\\/:;%*?=&#\'"!<>(){}[]|'      # Various signs incompatible with filesystem, HTML, SQL, etc...
PWIC_MAGIC_OAUTH = 'OAuth'
PWIC_NOT_PROJECT = ['', 'api', 'special']

# Thematic constants
PWIC_USERS = {'anonymous': 'pwic_anonymous',        # Account for the random visitors
              'ghost': 'pwic_ghost',                # Account for the deleted users (not implemented)
              'system': 'pwic_system'}              # Account for the technical operations
PWIC_DEFAULTS = {'dt_mask': '%Y-%m-%d %H:%M:%S',            # Fixed format of the datetime
                 'heading': '1.1.1.1.1.1.',                 # Default format of the paragraphs
                 'kb_mask': 'kb%06d',                       # Format for the KB pages
                 'language': 'en',                          # Default language-dependent template for the UI
                 'limit_filename': '128',                   # Max length for the file names
                 'limit_field': '2048',                     # Max length for the submitted inline strings
                 'logging_format': '%a %t "%r" %s %b',      # HTTP log format
                 'odt_img_defpix': '150',                   # Unknown size of a picture for the export to ODT
                 'page': 'home',                            # Root page of every project
                 'password': 'initial',                     # Default password for the new accounts
                 'port': '8080',                            # Default HTTP port
                 }
PWIC_REGEXES = {'document': re.compile(r'\]\(\/special\/document\/([0-9]+)(\)|\/|\#| ")'),      # Find a document in Markdown
                'document_imgsrc': re.compile(r'^\/?special\/document\/([0-9]+)([\?\#].*)?$'),  # Find the picture ID in IMG.SRC
                'kb_mask': re.compile(r'^kb[0-9]{6}$'),                                         # Name of the pages KB
                'mime': re.compile(r'^[a-z]+\/[a-z0-9\.\+\-]+$'),                               # Check the format of the mime
                'page': re.compile(r'\]\(\/([^\/\#\?\)]+)\/([^\/\#\?\)]+)(\/rev[0-9]+)?'),      # Find a page in Markdown
                'protocol': re.compile(r'^https?:\/\/', re.IGNORECASE),                         # Valid protocols for the links
                }

# Options
PWIC_ENV_PROJECT_INDEPENDENT = ['api_cors', 'base_url', 'client_size_max', 'file_formats', 'keep_sessions', 'http_log_file',
                                'http_log_format', 'https', 'ip_filter', 'magic_bytes', 'maintenance', 'no_login', 'oauth_domains',
                                'oauth_identifier', 'oauth_provider', 'oauth_secret', 'oauth_tenant', 'password_regex']
PWIC_ENV_PROJECT_DEPENDENT = ['api_expose_markdown', 'audit_range', 'auto_join', 'css', 'css_dark', 'css_printing', 'dark_theme',
                              'document_name_regex', 'document_size_max', 'edit_time_min', 'emojis', 'export_project_revisions',
                              'file_formats_disabled', 'heading_mask', 'kbid', 'keep_drafts', 'language', 'legal_notice', 'mathjax',
                              'mde', 'message', 'no_cache', 'no_export_project', 'no_graph', 'no_heading', 'no_help', 'no_history',
                              'no_index_rev', 'no_new_user', 'no_printing', 'no_rss', 'no_search', 'no_text_selection',
                              'odt_image_height_max', 'odt_image_width_max', 'odt_page_height', 'odt_page_width', 'page_count_max',
                              'project_size_max', 'quick_fix', 'revision_count_max', 'revision_size_max', 'robots', 'rss_size',
                              'show_members_max', 'skipped_tags', 'support_email', 'support_phone', 'support_text', 'support_url',
                              'title', 'validated_only']
PWIC_ENV_PROJECT_DEPENDENT_ONLINE = ['audit_range', 'auto_join', 'dark_theme', 'emojis', 'file_formats_disabled', 'heading_mask',
                                     'keep_drafts', 'language', 'mathjax', 'mde', 'message', 'no_graph', 'no_heading', 'no_help',
                                     'no_history', 'no_printing', 'no_rss', 'no_search', 'no_text_selection', 'odt_image_height_max',
                                     'odt_image_width_max', 'odt_page_height', 'odt_page_width', 'quick_fix', 'rss_size', 'show_members_max',
                                     'support_email', 'support_phone', 'support_text', 'support_url', 'title', 'validated_only']
PWIC_ENV_PROJECT_DEPENDENT_ONLY = ['auto_join']
PWIC_ENV_PRIVATE = ['oauth_secret']

# Emojis
PWIC_EMOJIS = {'alien': '&#x1F47D;',
               'bang': '&#x1F4A5;',
               'brick': '&#x1F9F1;',
               'calendar': '&#x1F4C5;',
               'camera': '&#x1F3A5;',               # 1F4F9
               'chains': '&#x1F517;',
               'check': '&#x2714;',
               'clamp': '&#x1F5DC;',
               'cloud': '&#x2601;',
               'dice': '&#x1F3B2;',
               'door': '&#x1F6AA;',
               'eye': '&#x1F441;',
               'finger_left': '&#x1F448;',
               'finger_up': '&#x261D;',
               'flag': '&#x1F3C1;',
               'gemini': '&#x264A;',
               'glasses': '&#x1F453;',
               'globe': '&#x1F310;',
               'green_check': '&#x2705;',
               'hammer': '&#x1F528;',
               'headphone': '&#x1F3A7;',
               'help': '&#x1F4DA;',
               'home': '&#x1F3E0;',
               'hourglass': '&#x23F3;',
               'id': '&#x1F194;',
               'image': '&#x1F4F8;',                # 1F5BC
               'inbox': '&#x1F4E5;',
               'key': '&#x1F511;',
               'laptop': '&#x1F4BB;',
               'locked': '&#x1F512;',
               'notes': '&#x1F4CB;',
               'outbox': '&#x1F4E4;',
               'padlock': '&#x1F510;',
               'pill': '&#x1F48A;',
               'pin': '&#x1F4CC;',
               'plug': '&#x1F50C;',
               'plus': '&#x2795;',
               'printer': '&#x1F5A8;',
               'recycle': '&#x267B;',
               'red_check': '&#x274C;',
               'refresh': '&#x1F504;',
               'rss': '&#x1F50A;',
               'save': '&#x1F4BE;',
               'scroll': '&#x1F4DC;',
               'search': '&#x1F50D;',
               'server': '&#x1F5A5;',
               'set_square': '&#x1F4D0;',
               'sheet': '&#x1F4C4;',
               'star': '&#x2B50;',
               'top': '&#x1F51D;',
               'truck': '&#x1F69A;',
               'unlocked': '&#x1F513;',
               'users': '&#x1F465;',
               'validate': '&#x1F44C;',
               'warning': '&#x26A0;',
               'watch': '&#x231A;'}


# ===================================================
#  MIMES
#  https://www.iana.org/assignments/media-types/media-types.xhtml
# ===================================================

ZIP = ['PK']
MATROSKA = ['\x1A\x45\xDF\xA3']
CFBF = ['\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1']
tyMime = List[Tuple[List[str],                  # Extensions in lower case
                    List[str],                  # Mimes
                    Optional[List[str]],        # Magic bytes
                    bool]]                      # Compressed format
PWIC_MIMES: tyMime = [([''], ['application/octet-stream'], None, False),
                      (['7z'], ['application/x-7z-compressed'], ['7z'], True),
                      (['aac'], ['audio/vnd.dlna.adts'], None, True),
                      (['abw'], ['application/x-abiword'], None, False),
                      (['accdb'], ['application/msaccess'], ['\x00\x01\x00\x00Standard ACE DB'], False),  # NUL SOH NUL NUL
                      (['aif', 'aifc', 'aiff'], ['audio/aiff'], ['AIFF', 'FORM'], True),
                      (['apk'], ['application/vnd.android.package-archive'], ZIP, True),
                      (['avi'], ['video/avi'], ['AVI', 'RIFF'], True),
                      (['avif'], ['image/avif'], None, True),
                      (['bin'], ['application/octet-stream'], None, True),
                      (['bmp'], ['image/bmp'], ['BM'], False),
                      (['bz'], ['application/x-bzip'], ['BZ'], True),
                      (['bz2'], ['application/x-bzip2'], ['BZ'], True),
                      (['cer'], ['application/x-x509-ca-cert'], None, False),
                      (['chm'], ['application/vnd.ms-htmlhelp'], ['ITSM'], False),
                      (['crt'], ['application/x-x509-ca-cert'], None, False),
                      (['css'], ['text/css'], None, False),
                      (['csv'], ['text/csv', 'application/vnd.ms-excel'], None, False),
                      (['deb'], ['application/x-debian-package'], ZIP, True),
                      (['der'], ['application/x-x509-ca-cert'], None, False),
                      (['dll'], ['application/x-msdownload'], ['MZ'], False),
                      (['doc'], ['application/msword'], CFBF, False),
                      (['docm'], ['application/vnd.ms-word.document.macroEnabled.12'], ZIP, True),
                      (['docx'], ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'], ZIP, True),
                      (['dwg'], ['image/vnd.dwg'], None, False),
                      (['dxf'], ['image/vnd.dxf'], None, False),
                      (['emf'], ['image/x-emf'], None, False),
                      (['eml'], ['message/rfc822'], None, False),
                      (['eps'], ['application/postscript'], None, False),
                      (['epub'], ['application/epub+zip'], ZIP, True),
                      (['exe'], ['application/x-msdownload'], ['MZ'], False),
                      (['flac'], ['audio/x-flac'], ['fLaC'], True),
                      (['flv'], ['video/x-flv'], ['FLV'], False),
                      (['gif'], ['image/gif'], ['GIF87a', 'GIF89a'], True),
                      (['gv'], ['text/vnd.graphviz'], None, False),
                      (['gz', 'gzip'], ['application/x-gzip'], ['\x1F\x8B'], True),
                      (['hlp'], ['application/winhlp'], None, False),
                      (['htm', 'html'], ['text/html'], None, False),
                      (['ico'], ['image/x-icon'], ['\x00\x00\x01\x00'], False),
                      (['ics'], ['text/calendar'], None, False),
                      (['jar'], ['application/java-archive'], ZIP, True),
                      (['jp2'], ['image/jp2'], ['\x00\x00\x00\xFFjP'], True),
                      (['jpg', 'jpeg'], ['image/jpeg'], ['\xFF\xD8\xFF'], True),
                      (['js'], ['application/javascript'], None, False),
                      (['json'], ['application/json'], None, False),
                      (['kml'], ['application/vnd.google-earth.kml+xml'], None, False),
                      (['kmz'], ['application/vnd.google-earth.kmz'], ZIP, True),
                      (['latex'], ['application/x-latex'], None, False),
                      (['m4a'], ['video/mp4'], None, True),
                      (['mdb'], ['application/msaccess'], ['\x00\x01\x00\x00Standard Jet DB'], False),  # NUL SOH NUL NUL
                      (['mid', 'midi'], ['audio/mid'], ['MThd'], False),
                      (['mka', 'mkv'], ['video/x-matroska'], MATROSKA, True),
                      (['mov'], ['video/quicktime'], None, True),
                      (['mp3'], ['audio/mpeg'], ['\xFF\xFB', '\xFF\xF3', '\xFF\xF2'], True),
                      (['mp4'], ['video/mp4'], ['ftypisom'], True),
                      (['mpg', 'mpeg'], ['video/mpeg'], ['\x00\x00\x01\xB3'], True),
                      (['mpp'], ['application/vnd.ms-project'], None, False),
                      (['oda'], ['application/oda'], None, False),
                      (['odf'], ['application/vnd.oasis.opendocument.formula'], ZIP, True),
                      (['odg'], ['application/vnd.oasis.opendocument.graphics'], ZIP, True),
                      (['odi'], ['application/vnd.oasis.opendocument.image'], None, False),
                      (['odp'], ['application/vnd.oasis.opendocument.presentation'], ZIP, True),
                      (['ods'], ['application/vnd.oasis.opendocument.spreadsheet'], ZIP, True),
                      (['odt'], ['application/vnd.oasis.opendocument.text'], ZIP, True),
                      (['oga', 'ogg'], ['audio/ogg'], None, True),
                      (['ogv'], ['video/ogg'], None, True),
                      (['one'], ['application/msonenote'], None, False),
                      (['otf'], ['application/x-font-otf'], None, False),
                      (['otp'], ['application/vnd.oasis.opendocument.presentation-template'], ZIP, True),
                      (['pdf'], ['application/pdf'], ['%PDF-'], False),
                      (['pdfxml'], ['application/vnd.adobe.pdfxml'], None, False),
                      (['png'], ['image/png'], ['\x89PNG'], True),
                      (['pot'], ['application/vnd.ms-powerpoint'], CFBF, False),
                      (['potm'], ['application/vnd.ms-powerpoint.template.macroEnabled.12'], ZIP, True),
                      (['potx'], ['application/vnd.openxmlformats-officedocument.presentationml.template'], ZIP, True),
                      (['pps'], ['application/vnd.ms-powerpoint'], CFBF, False),
                      (['ppsm'], ['application/vnd.ms-powerpoint.slideshow.macroEnabled.12'], ZIP, True),
                      (['ppsx'], ['application/vnd.openxmlformats-officedocument.presentationml.slideshow'], ZIP, True),
                      (['ppt'], ['application/vnd.ms-powerpoint'], CFBF, False),
                      (['pptm'], ['application/vnd.ms-powerpoint.presentation.macroEnabled.12'], ZIP, True),
                      (['pptx'], ['application/vnd.openxmlformats-officedocument.presentationml.presentation'], ZIP, True),
                      (['ps'], ['application/postscript'], ['%!PS'], False),
                      (['psd'], ['image/vnd.adobe.photoshop'], None, False),
                      (['pub'], ['application/vnd.ms-publisher'], CFBF, False),
                      (['rar'], ['application/x-rar-compressed'], ['Rar!\x1A\x07\x00', 'Rar!\x1A\x07\x01'], True),
                      (['rss'], ['application/rss+xml'], None, False),
                      (['rtf'], ['application/rtf'], ['{\rtf1'], False),
                      (['sqlite'], ['application/vnd.sqlite3'], ['SQLite format 3\x00'], False),
                      (['sti'], ['application/vnd.sun.xml.impress.template'], None, False),
                      (['svg'], ['image/svg+xml'], None, False),
                      (['swf'], ['application/x-shockwave-flash'], ['CWS', 'FWS'], False),
                      (['sxc'], ['application/vnd.sun.xml.calc'], None, False),
                      (['sxd'], ['application/vnd.sun.xml.draw'], None, False),
                      (['sxi'], ['application/vnd.sun.xml.impress'], None, False),
                      (['sxm'], ['application/vnd.sun.xml.math'], None, False),
                      (['sxw'], ['application/vnd.sun.xml.writer'], None, False),
                      (['tar'], ['application/x-tar'], ['ustar\x0000', 'ustar  \x00'], True),
                      (['tgz'], ['application/x-compressed'], ['\x1F\x8B'], True),
                      (['tif', 'tiff'], ['image/tiff'], ['II*\x00', 'II\x00*'], False),
                      (['tsv'], ['text/tab-separated-values'], None, False),
                      (['ttf'], ['application/x-font-ttf'], None, False),
                      (['txt'], ['text/plain'], None, False),
                      (['vcf'], ['text/x-vcard'], None, False),
                      (['vsd'], ['application/vnd.ms-visio.viewer'], CFBF, False),
                      (['vsdm'], ['application/vnd.ms-visio.viewer'], ZIP, True),
                      (['vsdx'], ['application/vnd.ms-visio.viewer'], ZIP, True),
                      (['wav'], ['audio/wav'], ['WAV', 'RIFF'], False),
                      (['weba'], ['audio/webm'], None, True),
                      (['webm'], ['video/webm'], MATROSKA, True),
                      (['webp'], ['image/webp'], ['WEBP', 'RIFF'], True),
                      (['wma'], ['audio/x-ms-wma'], None, True),
                      (['wmf'], ['image/x-wmf'], None, False),
                      (['wmv'], ['video/x-ms-wmv'], None, True),
                      (['woff'], ['application/x-font-woff', 'font/woff'], None, False),
                      (['woff2'], ['application/x-font-woff', 'font/woff2'], ['wOF2'], True),
                      (['xaml'], ['application/xaml+xml'], None, False),
                      (['xls'], ['application/vnd.ms-excel'], CFBF, False),
                      (['xlsm'], ['application/vnd.ms-excel.sheet.macroEnabled.12'], ZIP, True),
                      (['xlsx'], ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'], ZIP, True),
                      (['xml'], ['text/xml'], None, False),
                      (['xsl'], ['text/xml'], None, False),
                      (['yaml'], ['text/yaml'], None, False),
                      (['z'], ['application/x-compress'], ['\x1F\xA0'], True),
                      (['zip'], ['application/x-zip-compressed'], ZIP, True)]


def pwic_file_ext(filename: str) -> str:
    ''' Return the file extension of the file '''
    return splitext(filename)[1][1:].strip().lower()


def pwic_mime(ext: str) -> Optional[str]:
    ''' Return the default mime that corresponds to the file extension '''
    ext = ext.strip().lower()
    for (mext, mtyp, mhdr, mzip) in PWIC_MIMES:
        if ext in mext:
            return mtyp[0]
    return None


def pwic_mime_compressed(ext: str) -> bool:
    ''' Return the possible state of compression based on the file extension '''
    ext = ext.strip().lower()
    for (mext, mtyp, mhdr, mzip) in PWIC_MIMES:
        if ext in mext:
            return mzip
    return False


def pwic_magic_bytes(ext: str) -> Optional[List[str]]:
    ''' Return the magic bytes that corresponds to the file extension '''
    ext = ext.strip().lower()
    for (mext, mtyp, mhdr, mzip) in PWIC_MIMES:
        if ext in mext:
            return mhdr
    return None


def pwic_mime2icon(mime: str) -> str:
    ''' Return the emoji that corresponds to the MIME '''
    if mime[:6] == 'image/':
        return PWIC_EMOJIS['image']
    if mime[:6] == 'video/':
        return PWIC_EMOJIS['camera']
    if mime[:6] == 'audio/':
        return PWIC_EMOJIS['headphone']
    if mime[:12] == 'application/':
        return PWIC_EMOJIS['server']
    return PWIC_EMOJIS['sheet']


# ===================================================
#  Reusable functions
# ===================================================

def pwic_attachment_name(name: str) -> str:
    ''' Return the file name for a proper download '''
    return "=?utf-8?B?%s?=" % (b64encode(name.encode()).decode())


def pwic_dt(days: int = 0) -> Dict[str, str]:
    ''' Return some key dates and time '''
    from pwic_extension import PwicExtension
    curtime = datetime.now(tz=PwicExtension.on_timezone())
    return {'date': str(curtime)[:10],
            'date-30d': str(curtime - timedelta(days=30))[:10],
            'date-90d': str(curtime - timedelta(days=90))[:10],
            'date-nd': str(curtime - timedelta(days=days))[:10],
            'time': str(curtime)[11:19]}


def pwic_dt_diff(date1: str, date2: str) -> int:
    if date1 > date2:
        date1, date2 = date2, date1
    d1 = datetime.strptime(date1 + ' 00:00:00', PWIC_DEFAULTS['dt_mask'])
    d2 = datetime.strptime(date2 + ' 00:00:00', PWIC_DEFAULTS['dt_mask'])
    return (d2 - d1).days


def pwic_int(value: Any, base=10) -> int:
    ''' Safe conversion to integer in the chosen base '''
    try:
        if base == 10:
            return int(value)
        return int(value, base)
    except (ValueError, TypeError):
        return 0


def pwic_ishex(value: str) -> bool:
    return pwic_int(str(value), base=16) > 0


def pwic_flag(flag: str) -> str:
    # Check the parameter
    flag = flag.strip().lower()
    if len(flag) != 2:
        return ''

    # Build the unicode flag
    emoji = ''
    for i in range(2):
        if flag[i] in ascii_lowercase:
            emoji += chr(ascii_lowercase.find(flag[i]) + 0x1F1E6)
        else:
            return ''
    return emoji


def pwic_list(inputstr: Optional[str], do_sort: bool = False) -> List[str]:
    ''' Build a list of unique values from a string and keep the initial order (by default) '''
    if inputstr is None:
        inputstr = ''
    inputstr = pwic_recursive_replace(inputstr.replace('\r', ' ').replace('\n', ' ').replace('\t', ' '), '  ', ' ').strip()
    values = [] if inputstr == '' else list(OrderedDict((e, None) for e in inputstr.split(' ')))
    if do_sort:
        values.sort()
    return values


def pwic_list_tags(tags: str) -> str:
    ''' Reorder a list of tags written as a string '''
    return ' '.join(pwic_list(tags.replace('#', '').lower(), do_sort=True))


def pwic_option(sql: Optional[sqlite3.Cursor],
                project: Optional[str],
                name: str,
                default: Optional[str] = None,
                globale: bool = True,
                ) -> Optional[str]:
    ''' Read a variable from the table ENV that can be project-dependent or not '''
    if sql is None:
        return default
    query = ''' SELECT value
                FROM env
                WHERE project = ?
                  AND key     = ?
                  AND value  <> '' '''
    row = None
    if name in PWIC_ENV_PROJECT_INDEPENDENT:
        project = ''
    if project not in ['', None]:
        row = sql.execute(query, (project, name)).fetchone()
    if (row is None) and globale:
        row = sql.execute(query, ('', name)).fetchone()
    return default if row is None else row['value']


def pwic_random_hash() -> str:
    ''' Generate a random 64-char-long string '''
    return pwic_sha256(str(urandom(64)))[:32] + pwic_sha256(str(urandom(64)))[32:]


def pwic_recursive_replace(text: str, search: str, replace: str) -> str:
    ''' Replace a string recursively '''
    while True:
        curlen = len(text)
        text = text.replace(search, replace)
        if len(text) == curlen:
            break
    return text.strip()


def pwic_row_factory(cursor: sqlite3.Cursor, row: Tuple[Any, ...]):
    ''' Assign names to the SQL output '''
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def pwic_safe_file_name(name: str) -> str:
    ''' Ensure that a file name is acceptable '''
    name = pwic_safe_name(name, extra='').replace(' ', '_').replace('\t', '_')
    name = pwic_recursive_replace(name, '..', '.')
    name = pwic_recursive_replace(name, '__', '_')
    return '' if name[:1] == '.' else name


def pwic_safe_name(name: Optional[str], extra: str = '.@') -> str:
    ''' Ensure that a string will not collide with the reserved characters of the operating system '''
    chars = PWIC_CHARS_UNSAFE + extra
    if name is None:
        name = ''
    for c in chars:
        name = name.replace(c, '')
    return name.strip().lower()[:pwic_int(PWIC_DEFAULTS['limit_filename'])]


def pwic_safe_user_name(name: str) -> str:
    ''' Ensure that a user name is acceptable '''
    return pwic_safe_name(name, extra='')


def pwic_sha256(value: Union[str, bytearray], salt: bool = True) -> str:
    ''' Calculate the SHA256 as string for the given value '''
    if type(value) == bytearray:
        assert(salt is False)
        return sha256(value).hexdigest()
    text = (PWIC_SALT if salt else '') + str(value)
    return sha256(text.encode()).hexdigest()


def pwic_sha256_file(filename: str) -> str:
    ''' Calculate the SHA256 as string for the given file '''
    try:
        hashval = sha256()
        with open(filename, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                hashval.update(block)
        return hashval.hexdigest()
    except FileNotFoundError:
        return ''


def pwic_shrink(value: Optional[str]) -> str:
    if value is None:
        value = ''
    return value.replace('\r', '').replace('\n', '').replace('\t', '').replace(' ', '').strip().lower()


def pwic_size2str(size: Union[int, float]) -> str:
    ''' Convert a size to a readable format '''
    units = ' kMGTPEZ'
    for i in range(len(units)):
        if size < 1024:
            break
        size /= 1024
    return ('%.1f %sB' % (size, units[i].strip())).replace('.0 ', ' ')


def pwic_sql_print(query: Optional[str]) -> None:
    ''' Quick and dirty callback to print the SQL queries on a single line for debugging purposes '''
    if query is not None:
        dt = pwic_dt()
        print('[%s %s] %s' % (dt['date'],
                              dt['time'],
                              ' '.join([pwic_recursive_replace(q.strip().replace('\r', '').replace('\t', ' '), '  ', ' ') for q in query.split('\n')])))


def pwic_str2bytearray(inputstr: str) -> bytearray:
    ''' Convert string to bytearray '''
    barr = bytearray()      # =bytearray(bytes.encode()) breaks the bytes sequence due to the encoding
    for c in inputstr:
        barr.append(ord(c))
    return barr


def pwic_x(value: Any) -> str:
    ''' Reduce an input value to a boolean string '''
    return '' if value in [None, '', 0, '0', False, 'false', 'False', '-', '~', 'no', 'No', 'off', 'Off'] else 'X'


def pwic_xb(value: str) -> bool:
    ''' Convert 'X' to a boolean '''
    return value == 'X'


# ===================================================
#  Editor
# ===================================================

def pwic_extended_syntax(markdown: str, mask: Optional[str], headerNumbering: bool = True) -> Tuple[str, List[Dict]]:
    ''' Automatic numbering of the MD headers '''
    # Local functions
    def _numeric(value: int) -> str:
        return str(value)

    def _roman(value: int) -> str:
        if value < 1 or value > 4999:
            return '0'
        buffer = ''
        for letter, threshold in (('M', 1000),
                                  ('CM', 900),
                                  ('D', 500),
                                  ('CD', 400),
                                  ('C', 100),
                                  ('XC', 90),
                                  ('L', 50),
                                  ('XL', 40),
                                  ('X', 10),
                                  ('IX', 9),
                                  ('V', 5),
                                  ('IV', 4),
                                  ('I', 1)):
            while value >= threshold:
                buffer += letter
                value -= threshold
        return buffer

    def _romanMin(value: int) -> str:
        return _roman(value).lower()

    def _letter(value: int, mask: str) -> str:
        # stackoverflow.com/questions/48983939
        def _divmod(n, base):
            a, b = divmod(n, base)
            if b == 0:
                return a - 1, b + base
            return a, b

        if value <= 0:
            return '0'
        buffer = []
        while value > 0:
            value, d = _divmod(value, len(mask))
            buffer.append(mask[d - 1])
        return ''.join(reversed(buffer))

    def _letterMin(value: int) -> str:
        return _letter(value, ascii_lowercase)

    def _letterMaj(value: int) -> str:
        return _letter(value, ascii_uppercase)

    # Initialisation
    reg_header = re.compile(r'^<h([1-6])>', re.IGNORECASE)
    lines = markdown.replace('\r', '').split('\n')
    numbering: List[int] = []
    last_depth = 0
    tmap = []
    tmask = {'1': _numeric,
             'I': _roman,
             'i': _romanMin,
             'A': _letterMaj,
             'a': _letterMin}

    # Complete the mask
    if mask is None:
        mask = ''
    a = len(mask)
    b = len(PWIC_DEFAULTS['heading'])
    if a < b:
        mask += PWIC_DEFAULTS['heading'][a - b:]

    # For each line
    for i, line in enumerate(lines):
        match = reg_header.match(line)
        if match is not None:
            depth = int(match.group(1))

            # Align the found header to the right depth
            if depth > last_depth:
                while len(numbering) < depth:
                    numbering.append(0)
            elif depth < last_depth:
                while len(numbering) > depth:
                    numbering.pop(-1)
            last_depth = depth
            numbering[depth - 1] += 1

            # Build the readable identifier of the paragraph
            sdisp = ''
            stag = ''
            for n in range(len(numbering)):
                m2n = mask[2 * n]
                if m2n not in tmask:
                    m2n = '1'
                snum = tmask[m2n](numbering[n])
                ssep = mask[2 * n + 1]
                sdisp += '%s%s' % (snum, ssep)
                stag += '_%s' % snum.lower()

            # Adapt the line
            if headerNumbering:
                lines[i] = '%s id="p%s"><span class="pwic_paragraph_id" title="#p%s">%s</span> %s' % (line[:3], stag, stag, sdisp, line[4:])
            else:
                lines[i] = '%s id="p%s">%s' % (line[:3], stag, line[4:])
            tmap.append({'header': sdisp,
                         'tag': 'p%s' % stag,
                         'level': stag.count('_'),
                         'title': line.strip()[4:-5]})

    # Final formatting
    return '\n'.join(lines), tmap


# ===================================================
#  Traceability of the activities
# ===================================================

def pwic_audit(sql: sqlite3.Cursor, obj: Dict[str, Union[str, int]], request: Optional[web.Request] = None) -> None:
    ''' Save an event into the audit log '''
    # Forced properties of the event
    dt = pwic_dt()
    obj['date'] = dt['date']
    obj['time'] = dt['time']
    if request is not None:
        obj['ip'] = str(request.remote)
    assert(obj.get('event', '') != '')

    # Log the event
    fields = ''
    tupstr = ''
    tup: Tuple[Union[str, int], ...] = ()
    for key in obj:
        fields += '%s, ' % pwic_safe_name(key)
        tupstr += '?, '
        tup += (obj[key], )
    query = 'INSERT INTO audit.audit (%s) VALUES (%s)' % (fields[:-2], tupstr[:-2])
    sql.execute(query, tup)
    assert(sql.rowcount == 1)

    # Specific event
    from pwic_extension import PwicExtension
    try:
        PwicExtension.on_audit(sql, obj, request is not None)
    except Exception:
        pass


# ===================================================
#  Search engine
# ===================================================

class PwicSearchVisitor(NodeVisitor):
    def __init__(self) -> None:
        self.negate = False
        self.included: List[str] = []
        self.excluded: List[str] = []

    def visit_decl(self, node, visited_children) -> None:
        pass

    def visit_term(self, node, visited_children) -> None:
        pass

    def visit_comb(self, node, visited_children) -> None:
        pass

    def visit_space(self, node, visited_children) -> None:
        pass

    def visit_negate(self, node, visited_children) -> None:
        if node.match.group(0) == '-':
            self.negate = True

    def visit_individual(self, node, visited_children) -> None:
        (self.excluded if self.negate else self.included).append(node.match.group(0).strip().lower())
        self.negate = False

    def visit_quoted(self, node, visited_children) -> None:
        (self.excluded if self.negate else self.included).append(node.match.group(0)[1:-1].strip().lower())
        self.negate = False


def pwic_search_parse(query: str) -> Optional[Dict[str, List[str]]]:
    # Parse the query
    if query in ['', None]:
        return None
    try:
        ast = Grammar(
            r'''
            decl        = term*
            term        = space negate space comb
            comb        = individual / quoted

            space       = ~r"[\s\t]*"
            negate      = ~r"-?"
            individual  = ~r'[^\"|^\s]+'
            quoted      = ~r'\"[^\"]+\"'
            '''
        ).parse(query.strip())

        # Extract the keywords
        psv = PwicSearchVisitor()
        psv.visit(ast)
        return {'included': psv.included,
                'excluded': psv.excluded}
    except Exception:
        return None


def pwic_search2string(query: Dict[str, List[str]]) -> str:
    if query is None:
        return ''
    result = ''
    for q in query['included']:
        quote = '"' if ' ' in q else ''
        result += ' %s%s%s' % (quote, q, quote)
    for q in query['excluded']:
        quote = '"' if ' ' in q else ''
        result += ' -%s%s%s' % (quote, q, quote)
    return result.strip()


# ===================================================
#  HTML cleaner
# ===================================================

class pwic_html_cleaner(HTMLParser):
    def __init__(self, skipped_tags: str):
        HTMLParser.__init__(self)
        self._skipped_tags = pwic_list('applet iframe link meta script style ' + skipped_tags.lower())

    def reset(self):
        HTMLParser.reset(self)
        self._mute = ''                 # Tag switched off until </> is found
        self._code = ''                 # Special code block
        self._html = ''                 # Final buffer

    def handle_starttag(self, tag, attrs):
        tag = tag.strip().lower()
        if (self._mute == '') and (tag in self._skipped_tags):
            self._mute = tag
            return
        if (self._code == '') and (tag in ['blockcode', 'code', 'svg']):
            self._code = tag
        if self._mute == '':
            buffer = ''
            for (k, v) in attrs:
                k = pwic_shrink(k)
                if (k in ['alt', 'class', 'height', 'href', 'id', 'src', 'style', 'title', 'width']) or \
                   ((self._code == 'svg') and (k[:2] != 'on')):
                    v2 = pwic_shrink(v)
                    if ('javascript' not in v2) and ('url:' not in v2):
                        buffer += ' %s="%s"' % (k, v)
            self._html += '<%s%s>' % (tag, buffer)

    def handle_endtag(self, tag):
        tag = tag.strip().lower()
        if self._code == tag:
            self._code = ''
        if self._mute == tag:
            self._mute = ''
        else:
            self._html += '</%s>' % (tag)

    def handle_data(self, data):
        if self._mute == '':
            if self._code in ['blockcode', 'code']:
                data = data.replace('<', '&lt;').replace('>', '&gt;')   # No escape()
            self._html += data

    def get_html(self) -> str:
        return re.sub(r'<span( class="\w+")?>(\s+)?<\/span>', r'\2', self._html)


# ===================================================
#  html2odt
# ===================================================

class pwic_html2odt(HTMLParser):
    def __init__(self, baseUrl: str, project: str, page: str, pictMeta: Dict = None) -> None:
        # The parser can be feeded only once
        HTMLParser.__init__(self)

        # External parameters
        self.baseUrl = baseUrl
        self.project = project
        self.page = page
        self.pictMeta = pictMeta

        # Mappings
        self.maps = {'a': 'text:a',
                     'b': 'text:span',
                     'blockquote': None,
                     'blockcode': 'text:p',
                     'br': 'text:line-break',
                     'code': 'text:span',
                     'del': 'text:span',
                     'div': None,
                     'em': 'text:span',
                     'h1': 'text:h',
                     'h2': 'text:h',
                     'h3': 'text:h',
                     'h4': 'text:h',
                     'h5': 'text:h',
                     'h6': 'text:h',
                     'hr': 'text:p',
                     'i': 'text:span',
                     'img': 'draw:image',
                     'inf': 'text:span',
                     'ins': 'text:span',
                     'li': 'text:list-item',
                     'ol': 'text:list',
                     'p': 'text:p',
                     'span': 'text:span',
                     'strike': 'text:span',
                     'strong': 'text:span',
                     'sup': 'text:span',
                     'table': 'table:table',
                     'tbody': None,
                     'td': 'table:table-cell',
                     'th': 'table:table-cell',
                     'thead': None,
                     'tr': 'table:table-row',
                     'u': 'text:span',
                     'ul': 'text:list'}
        self.attributes = {'a': {'xlink:href': '#href',
                                 'xlink:type': 'simple'},
                           'b': {'text:style-name': 'Strong'},
                           'blockcode': {'text:style-name': 'CodeBlock'},
                           'code': {'text:style-name': 'Code'},
                           'del': {'text:style-name': 'Strike'},
                           'em': {'text:style-name': 'Italic'},
                           'h1': {'text:style-name': 'H1',
                                  'text:outline-level': '1'},
                           'h2': {'text:style-name': 'H2',
                                  'text:outline-level': '2'},
                           'h3': {'text:style-name': 'H3',
                                  'text:outline-level': '3'},
                           'h4': {'text:style-name': 'H4',
                                  'text:outline-level': '4'},
                           'h5': {'text:style-name': 'H5',
                                  'text:outline-level': '5'},
                           'h6': {'text:style-name': 'H6',
                                  'text:outline-level': '6'},
                           'hr': {'text:style-name': 'HR'},
                           'i': {'text:style-name': 'Italic'},
                           'img': {'xlink:href': '#src',
                                   'xlink:type': 'simple',
                                   'xlink:show': 'embed',
                                   'xlink:actuate': 'onLoad',
                                   'dummy:alt': '#alt',
                                   'dummy:title': '#title'},
                           'inf': {'text:style-name': 'Inf'},
                           'ins': {'text:style-name': 'Underline'},
                           'ol': {'text:style-name': 'ListStructureNumeric',
                                  'text:continue-numbering': 'true'},
                           'p': {'text:style-name': '#'},
                           'span': {'text:style-name': '#class'},
                           'strike': {'text:style-name': 'Strike'},
                           'strong': {'text:style-name': 'Strong'},
                           'sup': {'text:style-name': 'Sup'},
                           'table': {'table:style-name': 'Table'},
                           'td': {'table:style-name': 'TableCell'},
                           'th': {'table:style-name': 'TableCellHeader'},
                           'u': {'text:style-name': 'Underline'},
                           'ul': {'text:style-name': 'ListStructure',
                                  'text:continue-numbering': 'true'}}
        self.noclosing = ['br', 'hr']
        self.extrasBefore = {'img': ('<draw:frame text:anchor-type="as-char" svg:width="{$w}cm" svg:height="{$h}cm" style:rel-width="scale" style:rel-height="scale">', '</draw:frame>')}
        self.extrasAfter = {'a': ('<text:span text:style-name="Link">', '</text:span>'),
                            'td': ('<text:p>', '</text:p>'),
                            'th': ('<text:p>', '</text:p>')}

        # Processing
        self.tag_path: List[str] = []
        self.table_descriptors: List[Dict[str, int]] = []
        self.blockquote_on = False
        self.blockcode_on = False
        self.has_code = False
        self.lastIMGalt = ''
        self.lastIMGtitle = ''

        # Output
        self.odt = ''

    def _replace_marker(self, joker: str, content: str) -> None:
        pos = self.odt.rfind(joker)
        if pos != -1:
            self.odt = self.odt[:pos] + str(content) + self.odt[pos + len(joker):]

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()

        # Rules
        lastTag = self.tag_path[-1] if len(self.tag_path) > 0 else ''
        # ... no imbricated paragraphs
        if tag == lastTag == 'p':
            return
        # ... list item should be enclosed by <p>
        if (tag != 'p') and (lastTag == 'li'):
            self.tag_path.append('p')
            self.odt += '<%s>' % self.maps['p']
        # ... subitems should close <p>
        elif (tag in ['ul', 'ol']) and (lastTag == 'p'):
            self.tag_path.pop()
            self.odt += '</%s>' % self.maps['p']
        del lastTag

        # Identify the new tag
        self.tag_path.append(tag)
        if tag == 'blockquote':
            self.blockquote_on = True
        if tag == 'blockcode':
            self.blockcode_on = True
            self.has_code = True

        # Mapping of the tag
        if tag not in self.maps:
            self.odt += '<text:span text:style-name="Error">Unknown tag \'%s\'.</text:span>' % tag
        else:
            if self.maps[tag] is not None:
                # Automatic extra tags
                if tag in self.extrasBefore:
                    self.odt += self.extrasBefore[tag][0]

                # Tag itself
                self.odt += '<' + str(self.maps[tag])
                if tag in self.attributes:
                    for property_key in self.attributes[tag]:
                        property_value = self.attributes[tag][property_key]
                        if property_value[:1] != '#':
                            if property_key[:5] != 'dummy':
                                self.odt += ' %s="%s"' % (property_key, escape(property_value))
                        else:
                            property_value = property_value[1:]
                            if tag == 'p':
                                if self.blockquote_on:
                                    self.odt += ' text:style-name="Blockquote"'
                                    break
                            else:
                                for key, value in attrs:
                                    if key == property_value:
                                        # Fix the base URL for the links
                                        if (tag == 'a') and (key == 'href'):
                                            if value[:1] in ['/']:
                                                value = self.baseUrl + str(value)
                                            elif value[:1] in ['?', '#', '.']:
                                                value = '%s/%s/%s%s' % (self.baseUrl, self.project, self.page, value)
                                            elif value[:2] == './' or value[:3] == '../':
                                                value = '%s/%s/%s/%s' % (self.baseUrl, self.project, self.page, value)

                                        # Fix the attributes for the pictures
                                        if tag == 'img':
                                            if key == 'alt':
                                                self.lastIMGalt = value
                                            elif key == 'title':
                                                self.lastIMGtitle = value
                                            elif key == 'src':
                                                if value[:1] == '/':
                                                    value = value[1:]
                                                if self.pictMeta is not None:
                                                    docid_re = PWIC_REGEXES['document_imgsrc'].match(value)
                                                    if docid_re is not None:
                                                        width = height = 0
                                                        docid = pwic_int(docid_re.group(1))
                                                        if docid in self.pictMeta:
                                                            if self.pictMeta[docid]['remote'] or (self.pictMeta[docid]['link'] == value):
                                                                value = self.pictMeta[docid]['link_odt_img']
                                                            width = self.pictMeta[docid]['width']
                                                            height = self.pictMeta[docid]['height']
                                                        if 0 in [width, height]:
                                                            width = height = pwic_int(PWIC_DEFAULTS['odt_img_defpix'])
                                                        self._replace_marker('{$w}', '%.2f' % (2.54 * width / 120.))
                                                        self._replace_marker('{$h}', '%.2f' % (2.54 * height / 120.))

                                        # Fix the class name for the syntax highlight
                                        if (tag == 'span') and self.blockcode_on and (key == 'class'):
                                            value = 'Code_' + value

                                        if property_key[:5] != 'dummy':
                                            self.odt += ' %s="%s"' % (property_key, escape(value))
                                        break
                if tag in self.noclosing:
                    self.odt += '/'
                self.odt += '>'

                # Handle the column descriptors of the tables
                if tag == 'table':
                    self.table_descriptors.append({'cursor': len(self.odt),
                                                   'count': 0,
                                                   'max': 0})
                if tag in ['th', 'td']:
                    self.table_descriptors[-1]['count'] += 1

        # Automatic extra tags
        if tag in self.extrasAfter:
            self.odt += self.extrasAfter[tag][0]

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()

        # Rules
        lastTag = self.tag_path[-1] if len(self.tag_path) > 0 else ''
        # ... no imbricated paragraphs
        if (tag == 'p') and (lastTag != 'p'):
            return
        # ... list item should be enclosed by <p>
        if (tag == 'li') and (lastTag == 'p'):
            self.tag_path.pop()
            self.odt += '</%s>' % self.maps['p']
        del lastTag

        # Identify the tag
        assert(self.tag_path[-1] == tag)
        self.tag_path.pop()

        # Automatic extra tags
        if tag in self.extrasAfter:
            self.odt += self.extrasAfter[tag][1]

        # Final mapping
        if tag in self.maps:
            if tag not in self.noclosing:
                if tag == 'blockquote':
                    self.blockquote_on = False
                if tag == 'blockcode':
                    self.blockcode_on = False
                if self.maps[tag] is not None:
                    self.odt += '</%s>' % self.maps[tag]

                    # Handle the descriptors of the tables
                    if tag == 'tr':
                        self.table_descriptors[-1]['max'] = max(self.table_descriptors[-1]['count'],
                                                                self.table_descriptors[-1]['max'])
                        self.table_descriptors[-1]['count'] = 0
                    if tag == 'table':
                        cursor = self.table_descriptors[-1]['cursor']
                        self.odt = (self.odt[:cursor]
                                    + '<table:table-columns>'
                                    + ''.join(['<table:table-column/>' for _ in range(self.table_descriptors[-1]['max'])])
                                    + '</table:table-columns>'
                                    + self.odt[cursor:])
                        self.table_descriptors.pop()

        # Dynamic replacement text for a picture
        if tag == 'img':
            if self.lastIMGalt != '':
                self.odt += '<svg:title>%s</svg:title>' % escape(self.lastIMGalt)
                self.lastIMGalt = ''
            if self.lastIMGtitle != '':
                self.odt += '<svg:desc>%s</svg:desc>' % escape(self.lastIMGtitle)
                self.lastIMGtitle = ''

        # Automatic extra tags
        if tag in self.extrasBefore:
            self.odt += self.extrasBefore[tag][1]

    def handle_data(self, data: str) -> None:
        data = escape(data)
        # List item should be enclosed by <p>
        if (self.tag_path[-1] if len(self.tag_path) > 0 else '') == 'li':
            self.tag_path.append('p')
            self.odt += '<%s>' % self.maps['p']
        # Text alignment for the code
        if self.blockcode_on:
            data = data.replace('\r', '')
            data = data.replace('\n', '<text:line-break/>')
            data = data.replace('\t', '<text:tab/>')
            data = data.replace(' ', '<text:s/>')
        # Default behavior
        self.odt += data
