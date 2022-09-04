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
from parsimonious.grammar import Grammar
from parsimonious.nodes import NodeVisitor
from string import ascii_lowercase, ascii_uppercase


# ===================================================
#  Constants
# ===================================================

# Paths
PWIC_VERSION = '1.0'
PWIC_DB = './db'
PWIC_DB_SQLITE = PWIC_DB + '/pwic.sqlite'
PWIC_DB_SQLITE_BACKUP = PWIC_DB + '/pwic_%s.sqlite'
PWIC_DB_SQLITE_AUDIT = PWIC_DB + '/pwic_audit.sqlite'
PWIC_DOCUMENTS_PATH = PWIC_DB + '/documents/%s/'
PWIC_LOCALE_PATH = './locale/'
PWIC_TEMPLATES_PATH = './templates/'

# Security + HTTPS
PWIC_SALT = ''                                      # Random string to secure the generated hashes for the passwords
PWIC_PRIVATE_KEY = 'db/pwic_https.key'
PWIC_PUBLIC_KEY = 'db/pwic_https.crt'
PWIC_CHARS_UNSAFE = '\\/:;%*?=&#\'"!<>(){}[]|'      # Various signs incompatible with filesystem, HTML, SQL, etc...
PWIC_MAGIC_OAUTH = 'OAuth'
PWIC_NOT_PROJECT = ['', 'api', 'special', 'static']

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
                'length': re.compile(r'^(\d+(.\d*)?)(cm|mm|in|pt|pc|px|em)?$'),                 # Length in XML
                'mime': re.compile(r'^[a-z]+\/[a-z0-9\.\+\-]+$'),                               # Check the format of the mime
                'page': re.compile(r'\]\(\/([^\/\#\?\)]+)\/([^\/\#\?\)" ]+)(\/rev[0-9]+)?'),    # Find a page in Markdown
                'protocol': re.compile(r'^https?:\/\/', re.IGNORECASE),                         # Valid protocols for the links
                'tag_name': re.compile(r'<\/?([a-z]+)[ >]', re.IGNORECASE),                     # Find the HTML tags
                'tag_all': re.compile(r'<\/?\w+( [^>]+)?>', re.IGNORECASE),                     # Tag in HTML
                'tag_comment': re.compile(r'<!--.*-->', re.IGNORECASE),                         # Comment in HTML
                }
PWIC_DPI = 120.                                     # Pixels per inch
PWIC_RTL = ['ar', 'fa', 'he']                       # RTL languages

# Options
PWIC_ENV_PROJECT_INDEPENDENT = ['api_cors', 'base_url', 'client_size_max', 'db_async', 'fixed_templates', 'keep_sessions', 'http_log_file',
                                'http_log_format', 'http_referer', 'https', 'ip_filter', 'magic_bytes', 'maintenance', 'no_highlight',
                                'no_login', 'oauth_domains', 'oauth_identifier', 'oauth_provider', 'oauth_secret', 'oauth_tenant',
                                'password_regex', 'registration_link', 'strict_cookies']
PWIC_ENV_PROJECT_DEPENDENT = ['api_expose_markdown', 'audit_range', 'auto_join', 'css', 'css_dark', 'css_printing', 'dark_theme',
                              'document_name_regex', 'document_size_max', 'edit_time_min', 'emojis', 'export_project_revisions',
                              'file_formats_disabled', 'heading_mask', 'kbid', 'keep_drafts', 'language', 'legal_notice', 'link_new_tab',
                              'link_nofollow', 'mathjax', 'mde', 'message', 'no_cache', 'no_copy_code', 'no_document_conversion',
                              'no_export_project', 'no_graph', 'no_heading', 'no_help', 'no_history', 'no_link_review', 'no_new_user',
                              'no_printing', 'no_rss', 'no_search', 'no_sort_table', 'no_space_page', 'no_text_selection',
                              'odt_image_height_max', 'odt_image_width_max', 'odt_page_height', 'odt_page_landscape', 'odt_page_margin',
                              'odt_page_width', 'page_count_max', 'project_size_max', 'quick_fix', 'revision_count_max', 'revision_size_max',
                              'robots', 'rss_size', 'rstrip', 'seo_hide_revs', 'show_members_max', 'skipped_tags', 'support_email',
                              'support_phone', 'support_text', 'support_url', 'title', 'validated_only', 'zip_no_exec']
PWIC_ENV_PROJECT_DEPENDENT_ONLINE = ['audit_range', 'auto_join', 'dark_theme', 'emojis', 'file_formats_disabled', 'heading_mask',
                                     'keep_drafts', 'language', 'link_new_tab', 'link_nofollow', 'mathjax', 'mde', 'message', 'no_copy_code',
                                     'no_document_conversion', 'no_graph', 'no_heading', 'no_help', 'no_history', 'no_link_review',
                                     'no_printing', 'no_rss', 'no_search', 'no_sort_table', 'no_space_page', 'no_text_selection',
                                     'odt_image_height_max', 'odt_image_width_max', 'odt_page_height', 'odt_page_landscape',
                                     'odt_page_margin', 'odt_page_width', 'quick_fix', 'rss_size', 'rstrip', 'show_members_max',
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
               'double': '&#x268B;',
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
               'left': '&#x226A;',
               'locked': '&#x1F512;',
               'noblank': '&#x22DB;',
               'notes': '&#x1F4CB;',
               'oneline': '&#x2AA5;',
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
               'right': '&#x226B;',
               'rss': '&#x1F50A;',
               'save': '&#x1F4BE;',
               'scroll': '&#x1F4DC;',
               'search': '&#x1F50D;',
               'server': '&#x1F5A5;',
               'set_square': '&#x1F4D0;',
               'sheet': '&#x1F4C4;',
               'sparkles': '&#x2728;',
               'star': '&#x2B50;',
               'top': '&#x1F51D;',
               'truck': '&#x1F69A;',
               'unlocked': '&#x1F513;',
               'users': '&#x1F465;',
               'validate': '&#x1F44C;',
               'warning': '&#x26A0;',
               'watch': '&#x231A;'}


# Custom exception
class PwicError(Exception):
    pass


# ===================================================
#  Mimes
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
                      (['md'], ['text/markdown'], None, False),
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
PWIC_EXECS = ['bat', 'cat', 'cmd', 'com', 'dll', 'docm', 'drv', 'exe', 'potm', 'ppsm', 'pptm', 'ps1', 'scr', 'sh', 'sys', 'vbs', 'xlsm']


def pwic_file_ext(filename: str) -> str:
    ''' Return the file extension of the file '''
    return splitext(filename)[1][1:].strip().lower()


def pwic_mime(ext: str) -> Optional[str]:
    ''' Return the default mime that corresponds to the file extension '''
    values = pwic_mime_list(ext)
    return None if len(values) == 0 else values[0]


def pwic_mime_list(ext: str) -> List[str]:
    ''' Return the possible mimes that correspond to the file extension '''
    ext = ext.strip().lower()
    for (mext, mtyp, mhdr, mzip) in PWIC_MIMES:
        if ext in mext:
            return mtyp
    return []


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


def pwic_convert_length(value: Optional[Union[str, int, float]], target_unit: str, precision: int, dpi: float = PWIC_DPI) -> str:
    ''' Convert a length from a unit to another one '''
    # Conversion factors
    factors = {'cm': (dpi / 2.54, 'px'),
               'mm': (0.1, 'cm'),
               'in': (2.54, 'cm'),
               'pt': (1. / 72., 'in'),
               'pc': (12., 'pt'),
               'px': (1., 'px'),
               'em': (0., 'px'),                # Relative length
               '': (1., '')}

    # Read the input value
    if (value is None) or (target_unit not in factors):
        return '0'
    if not isinstance(value, str):
        length = float(value)
        unit = 'px'
    else:
        value = value.strip().replace(' ', '').replace(',', '.').lower()
        m = PWIC_REGEXES['length'].match(value)
        if m is None:
            return '0'
        try:
            length = float(m.group(1))
        except ValueError:
            return '0'
        unit = m.group(3) or 'px'

    # Convert to pixels
    while True:
        (k, unit) = factors[unit]
        length *= k
        if unit == 'px':
            break

    # Convert to the target unit
    length /= factors[target_unit][0]
    return str(round(length, precision)) + target_unit


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
    ''' Calculate the number of days between 2 dates '''
    if date1 > date2:
        date1, date2 = date2, date1
    d1 = datetime.strptime(date1 + ' 00:00:00', PWIC_DEFAULTS['dt_mask'])
    d2 = datetime.strptime(date2 + ' 00:00:00', PWIC_DEFAULTS['dt_mask'])
    return (d2 - d1).days


def pwic_int(value: Any, base=10) -> int:
    ''' Safe conversion to integer in the chosen base '''
    try:
        if base != 10:
            return int(value, base)
        return int(float(value) if '.' in str(value) else value)
    except (ValueError, TypeError):
        return 0


def pwic_ishex(value: str) -> bool:
    return pwic_int(str(value), base=16) > 0


def pwic_flag(flag: str) -> str:
    ''' Convert a country in ISO format to emoji '''
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


def pwic_nns(value: Optional[str]) -> str:
    ''' Return a non-null string '''
    return str('' if value is None else value)


def pwic_notag(value: str) -> str:
    ''' Remove the HTML tags from a string '''
    while True:
        i = len(value)
        value = PWIC_REGEXES['tag_all'].sub('', value)
        value = PWIC_REGEXES['tag_comment'].sub('', value)
        if len(value) == i:
            break
    return value


def pwic_option(sql: Optional[sqlite3.Cursor],
                project: Optional[str],
                name: str,
                default: Optional[str] = None,
                globale: bool = True,
                ) -> Optional[str]:
    ''' Read a variable from the table ENV that can be project-dependent or not '''
    if sql is None:
        return default
    try:
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
        result = default if row is None else row['value']
        if isinstance(result, str):
            result = result.replace('\r', '')
        return result
    except sqlite3.OperationalError:    # During init-db
        return default


def pwic_random_hash() -> str:
    ''' Generate a random 64-char-long string '''
    return pwic_sha256(str(urandom(64)))[:32] + pwic_sha256(str(urandom(64)))[32:]


def pwic_read_attr(attrs: List[Tuple[str, Optional[str]]], key: str, default: str = '') -> str:
    for (k, v) in attrs:
        if k == key:
            return pwic_nns(v)
    return default


def pwic_recursive_replace(text: str, search: str, replace: str, strip: bool = True) -> str:
    ''' Replace a string recursively '''
    while True:
        curlen = len(text)
        text = text.replace(search, replace)
        if len(text) == curlen:
            break
    if strip:
        text = text.strip()
    return text


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
        if salt:
            raise PwicError
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
    ''' Convert a string into its shortest value in lower case '''
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
    lines = markdown.split('\n')
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
            for n, c in enumerate(numbering):
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
#  System
# ===================================================

def pwic_audit(sql: sqlite3.Cursor, obj: Dict[str, Union[str, int]], request: Optional[web.Request] = None) -> None:
    ''' Save an event into the audit log '''
    from pwic_extension import PwicExtension

    # Check
    if PwicExtension.on_audit_skip(sql, request, obj):
        return

    # Forced properties of the event
    dt = pwic_dt()
    obj['date'] = dt['date']
    obj['time'] = dt['time']
    if request is not None:
        obj['ip'] = PwicExtension.on_ip_header(request)
    if obj.get('event', '') == '':
        raise PwicError

    # Log the event
    fields = ''
    tupstr = ''
    tup: Tuple[Union[str, int], ...] = ()
    for key in obj:
        fields += '%s, ' % pwic_safe_name(key)
        tupstr += '?, '
        tup += (obj[key], )
    query = 'INSERT INTO audit.audit (%s) VALUES (%s)'
    sql.execute(query % (fields[:-2], tupstr[:-2]), tup)
    if sql.rowcount != 1:
        raise PwicError

    # Specific event
    try:
        PwicExtension.on_audit(sql, request, obj)
    except Exception:       # nosec B110
        pass


def pwic_connect(dbfile: str = PWIC_DB_SQLITE,
                 dbaudit: Optional[str] = PWIC_DB_SQLITE_AUDIT,
                 trace: bool = False,
                 in_memory: bool = True,
                 asynchronous: bool = False,
                 vacuum: bool = False,
                 ) -> Tuple[sqlite3.Connection, sqlite3.Cursor]:
    ''' Connect to the database with the relevant options '''
    # Connection
    db = sqlite3.connect(dbfile)
    db.row_factory = pwic_row_factory
    if trace:
        db.set_trace_callback(pwic_sql_print)

    # Cursor and options
    sql = db.cursor()
    attached = dbaudit is not None
    if attached:
        sql.execute(''' ATTACH DATABASE ? AS audit''', (dbaudit, ))
    if in_memory:
        sql.execute(''' PRAGMA main.journal_mode = MEMORY''')
        if attached:
            sql.execute(''' PRAGMA audit.journal_mode = MEMORY''')
    if asynchronous or (pwic_option(sql, '', 'db_async') is not None):
        sql.execute(''' PRAGMA main.synchronous = OFF''')
        if attached:
            sql.execute(''' PRAGMA audit.synchronous = OFF''')
    if vacuum:
        sql.execute(''' VACUUM main''')
        if attached:
            sql.execute(''' VACUUM audit''')
    return db, sql


def pwic_detect_language(request: web.Request, allowed_langs: List[str], sso: bool = False) -> str:
    ''' Detect the default language of the user from the HTTP headers '''
    # Detect from the HTTP headers
    head = request.headers.get('Accept-Language', '')
    langs = pwic_list(head.replace(',', ' ').replace(';', ' '))
    result = PWIC_DEFAULTS['language']
    for e in langs:
        if '-' in e:
            e = e[:2]
        if e in allowed_langs:
            result = e
            break

    # Custom detection
    from pwic_extension import PwicExtension
    return PwicExtension.on_language_detected(request, result, allowed_langs, sso)


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
