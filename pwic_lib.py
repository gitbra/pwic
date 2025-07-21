# Pwic.wiki server running on Python and SQLite
# Copyright (C) 2020-2025 Alexandre Bréard
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
# along with this program. If not, see <https://www.gnu.org/licenses/>.

from typing import Any, Dict, List, Optional, Tuple, Union
import sqlite3
import re
from collections import namedtuple, OrderedDict
from datetime import datetime, timedelta
from time import time
from os import urandom
from os.path import splitext
from hashlib import sha256
from base64 import b64encode
from string import ascii_lowercase, ascii_uppercase
from html.parser import HTMLParser
from urllib.parse import urlparse
from aiohttp import ClientSession, web

from pwic_md import Markdown


TyEnv = namedtuple('TyEnv', 'pindep, pdep, online, private')
TyMime = namedtuple('TyMime', 'exts, mimes, magic, compressed')
TyRobotsDict = Dict[str, Optional[bool]]

CFBF = ['\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1']
MATROSKA = ['\x1A\x45\xDF\xA3']
XML = ['<']
ZIP = ['PK']


class PwicConst:
    ''' Constants used by Pwic.wiki '''

    # ========
    #  System
    # ========

    VERSION = '1.2'
    DB = './db'
    DB_SQLITE = DB + '/pwic.sqlite'
    DB_SQLITE_BACKUP = DB + '/pwic_%s.sqlite'
    DB_SQLITE_AUDIT = DB + '/pwic_audit.sqlite'
    DOCUMENTS_PATH = DB + '/documents/%s/'
    LOCALE_PATH = './locale/'
    TEMPLATES_PATH = './templates/'
    BOOL_COLUMNS = ['admin', 'manager', 'editor', 'validator', 'reader', 'disabled',      # roles
                    'initial',                                                            # users
                    'latest', 'draft', 'final', 'header', 'protection']                   # pages

    # ==========
    #  Security
    # ==========

    SALT = ''                                               # Private random characters to secure the generated hashes for the passwords
    PRIVATE_KEY = 'db/pwic_https.key'
    PUBLIC_KEY = 'db/pwic_https.crt'
    CHARS_UNSAFE = '\\/:;%*?=&#\'"!<>(){}[]|'               # Various signs incompatible with filesystem, HTML, SQL...
    MAGIC_OAUTH = 'OAuth'
    NOT_PROJECT = ['', 'admin', 'api', 'bugs', 'issues', 'special', 'static', 'tracker']
    NOT_PAGE = ['', 'special']

    # ========
    #  Packed
    # ========

    USERS = {'anonymous': 'pwic_anonymous',                 # Account for the random visitors
             'bot': 'pwic_bot',                             # Account for the detected bots
             'ghost': 'pwic_ghost',                         # Account for the deleted users (not implemented)
             'system': 'pwic_system'}                       # Account for the technical operations
    DEFAULTS = {'dt_mask': '%Y-%m-%d %H:%M:%S',             # Fixed format of the datetime
                'heading': '1.1.1.1.1.1.',                  # Default format of the paragraphs
                'host': '127.0.0.1',                        # Default HTTP host when the server starts
                'kb_length': 6,                             # Length of the identifier for the KB pages
                'language': 'en',                           # Default language-dependent template for the UI
                'limit_filename': '128',                    # Max length for the file names
                'limit_field': '2048',                      # Max length for the submitted inline strings
                'logging_format': '%a %t "%r" %s %b',       # HTTP log format
                'odt_img_defpix': '150',                    # Unknown size of a picture for the export to ODT
                'page': 'home',                             # Root page of every project
                'password': 'initial',                      # Default password for the new accounts
                'port': '8080',                             # Default HTTP port when the server starts
                }
    REGEXES = {'document': re.compile(r'\]\(\/special\/document\/([0-9]+)(\)|\/|\#|\?| ")'),                    # Find a document in Markdown
               'document_imgsrc': re.compile(r'^\/?special\/document\/([0-9]+)([\#\?].*)?$'),                   # Find the picture ID in IMG.SRC
               'empty_tag': re.compile(r'<\b(\w+)\b(?<!table)\b(?<!tr|th|td)><\/\1>', re.IGNORECASE),           # Removable blank HTML tags, except table elements
               'empty_tag_with_attrs': re.compile(r'<(\w+(?<!th|td))(\s+\w+="?\w+"?)*>(\s*)<\/\1>', re.IGNORECASE),                 # Removable blank HTML tags, except table elements
               'adjacent_tag': re.compile(r'<\/(b|big|em|i|small|span|strong|sub|sup)[ \t]*>([ \t]*)<\1[ \t]*>', re.IGNORECASE),    # Removable adjacent inline HTML tags
               'length': re.compile(r'^(\d+(.\d*)?)(cm|mm|in|pt|pc|px|em)?$'),                                  # Length in XML
               'md_strip': re.compile(r'\([^\)]+\)|\*+|-+|\~+|\[|\]|\(|\)|`'),                                  # QnD removal of Markdown
               'mime': re.compile(r'^[a-z]+\/[a-z0-9\.\+\-]+$', re.IGNORECASE),                                 # Check the format of the mime
               'page': re.compile(r'\]\((\.|\/[^\/\#\?\)"]+)\/([^\/\#\?\)"]+)(\/rev[0-9]+)?(\#|\?|\)| ")'),     # Find a page in Markdown
               'protocol': re.compile(r'^https?:\/\/', re.IGNORECASE),                                          # Valid protocols for the links
               'search_terms': re.compile(r'(-?)("[^"\n]+"|[^ \n]+)[\t ]*', re.IGNORECASE),                     # Split the search terms
               'tag_name': re.compile(r'<\/?([a-z]+)[ >]', re.IGNORECASE),                                      # Find the HTML tags
               'tag_all': re.compile(r'<\??\/?\w+( [^>]+)?>', re.IGNORECASE),                                   # Tag in HTML
               'tag_comment': re.compile(r'<!--.*-->', re.IGNORECASE),                                          # Comment in HTML
               }

    # =========
    #  Options
    # =========

    ENV = {'api_cors': TyEnv(True, False, False, False),
           'api_expose_markdown': TyEnv(True, True, False, False),
           'api_restrict': TyEnv(True, True, True, False),
           'audit_range': TyEnv(True, True, True, False),
           'auto_join': TyEnv(False, True, True, False),
           'base_url': TyEnv(True, False, False, False),
           'client_size_max': TyEnv(True, False, False, False),
           'compressed_cache': TyEnv(True, False, False, False),
           'copyright_years': TyEnv(True, True, True, False),
           'css': TyEnv(True, True, False, False),
           'css_dark': TyEnv(True, True, False, False),
           'css_printing': TyEnv(True, True, False, False),
           'dark_theme': TyEnv(True, True, True, False),
           'db_async': TyEnv(True, False, False, False),
           'document_name_regex': TyEnv(True, True, False, False),
           'document_pixels_max': TyEnv(True, True, True, False),
           'document_size_max': TyEnv(True, True, False, False),
           'edit_time_min': TyEnv(True, True, False, False),
           'emojis': TyEnv(True, True, True, False),
           'export_project_revisions': TyEnv(True, True, False, False),
           'feed_size': TyEnv(True, True, True, False),
           'file_formats_disabled': TyEnv(True, True, True, False),
           'fixed_templates': TyEnv(True, False, False, False),
           'heading_mask': TyEnv(True, True, True, False),
           'http_404': TyEnv(True, True, True, False),
           'http_log_file': TyEnv(True, False, False, False),
           'http_log_format': TyEnv(True, False, False, False),
           'http_referer': TyEnv(True, False, False, False),
           'https': TyEnv(True, False, False, False),
           'ip_filter': TyEnv(True, False, False, False),
           'keep_drafts': TyEnv(True, True, True, False),
           'keep_sessions': TyEnv(True, False, False, False),
           'language': TyEnv(True, True, True, False),
           'legal_notice': TyEnv(True, True, False, False),
           'link_new_tab': TyEnv(True, True, True, False),
           'link_nofollow': TyEnv(True, True, True, False),
           'magic_bytes': TyEnv(True, False, False, False),
           'maintenance': TyEnv(True, False, False, False),
           'manifest': TyEnv(True, True, True, False),
           'mathjax': TyEnv(True, True, True, False),
           'message': TyEnv(True, True, True, False),
           'no_cache': TyEnv(True, True, False, False),
           'no_copy_code': TyEnv(True, True, True, False),
           'no_dictation': TyEnv(True, True, True, False),
           'no_document_conversion': TyEnv(True, True, True, False),
           'no_document_list': TyEnv(True, True, True, False),
           'no_export_project': TyEnv(True, True, False, False),
           'no_feed': TyEnv(True, True, True, False),
           'no_graph': TyEnv(True, True, True, False),
           'no_heading': TyEnv(True, True, True, False),
           'no_help': TyEnv(True, True, True, False),
           'no_highlight': TyEnv(True, False, False, False),
           'no_history': TyEnv(True, True, True, False),
           'no_link_review': TyEnv(True, True, True, False),
           'no_login': TyEnv(True, False, False, False),
           'no_new_user': TyEnv(True, True, False, False),
           'no_printing': TyEnv(True, True, True, False),
           'no_search': TyEnv(True, True, True, False),
           'no_sitemap': TyEnv(True, True, True, False),
           'no_sort_table': TyEnv(True, True, True, False),
           'no_space_page': TyEnv(True, True, True, False),
           'no_table_csv': TyEnv(True, True, True, False),
           'no_text_selection': TyEnv(True, True, True, False),
           'oauth_domains': TyEnv(True, False, False, False),
           'oauth_identifier': TyEnv(True, False, False, False),
           'oauth_provider': TyEnv(True, False, False, False),
           'oauth_secret': TyEnv(True, False, False, True),
           'oauth_tenant': TyEnv(True, False, False, False),
           'odata': TyEnv(True, False, False, False),
           'odt_image_height_max': TyEnv(True, True, True, False),
           'odt_image_width_max': TyEnv(True, True, True, False),
           'odt_page_height': TyEnv(True, True, True, False),
           'odt_page_landscape': TyEnv(True, True, True, False),
           'odt_page_margin': TyEnv(True, True, True, False),
           'odt_page_width': TyEnv(True, True, True, False),
           'page_count_max': TyEnv(True, True, False, False),
           'password_regex': TyEnv(True, False, False, False),
           'project_size_max': TyEnv(True, True, False, False),
           'pwic_audit_id': TyEnv(True, False, False, True),
           'pwic_session': TyEnv(True, False, False, True),
           'quick_fix': TyEnv(True, True, True, False),
           'remote_url': TyEnv(True, True, False, False),
           'registration_link': TyEnv(True, False, False, False),
           'revision_count_max': TyEnv(True, True, False, False),
           'revision_size_max': TyEnv(True, True, False, False),
           'robots': TyEnv(True, True, False, False),
           'rstrip': TyEnv(True, True, True, False),
           'seo_hide_revs': TyEnv(True, True, False, False),
           'session_expiry': TyEnv(True, False, False, False),
           'show_members_max': TyEnv(True, True, True, False),
           'skipped_tags': TyEnv(True, True, False, False),
           'strict_cookies': TyEnv(True, False, False, False),
           'support_email': TyEnv(True, True, True, False),
           'support_phone': TyEnv(True, True, True, False),
           'support_text': TyEnv(True, True, True, False),
           'support_url': TyEnv(True, True, True, False),
           'title': TyEnv(True, True, True, False),
           'totp': TyEnv(True, False, False, False),
           'validated_only': TyEnv(True, True, True, False),
           'zip_no_exec': TyEnv(True, True, False, False),
           }

    # ===============
    #  Miscellaneous
    # ===============

    DPI = 120.                                              # Pixels per inch
    RTL = ['ar', 'fa', 'he']                                # RTL languages
    VOID_HTML = ['area', 'base', 'br', 'col', 'embed',
                 'hr', 'img', 'input', 'link', 'meta',
                 'source', 'track', 'wbr']                  # Self-closing HTML tags
    USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'

    # ========
    #  Emojis
    # ========

    EMOJIS = {'alien': '&#x1F47D;',
              'atom': '&#x269B;&#xFE0F;',
              'bang': '&#x1F4A5;',
              'brick': '&#x1F9F1;',
              'calendar': '&#x1F4C5;',
              'camera': '&#x1F3A5;',                        # 1F4F9
              'chains': '&#x1F517;',
              'check': '&#x2714;&#xFE0F;',
              'clamp': '&#x1F5DC;&#xFE0F;',
              'clock': '&#x23F0;',
              'cloud': '&#x2601;&#xFE0F;',
              'curved_left_arrow': '&#x21A9;&#xFE0F;',
              'dice': '&#x1F3B2;',
              'door': '&#x1F6AA;',
              'double': '&#x268B;',
              'eye': '&#x1F441;&#xFE0F;',
              'finger_left': '&#x1F448;',
              'finger_up': '&#x261D;&#xFE0F;',
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
              'image': '&#x1F5BC;&#xFE0F;',
              'inbox': '&#x1F4E5;',
              'key': '&#x1F511;',
              'laptop': '&#x1F4BB;',
              'left': '&#x226A;',
              'locked': '&#x1F512;',
              'map': '&#x1F5FA;&#xFE0F;',
              'microphone': '&#x1F3A4;',
              'noblank': '&#x22DB;',
              'notes': '&#x1F4CB;',
              'oneline': '&#x2AA5;',
              'outbox': '&#x1F4E4;',
              'padlock': '&#x1F510;',
              'paperclip': '&#x1F4CE;',
              'pill': '&#x1F48A;',
              'pin': '&#x1F4CC;',
              'plug': '&#x1F50C;',
              'plus': '&#x2795;',
              'printer': '&#x1F5A8;&#xFE0F;',
              'recycle': '&#x267B;&#xFE0F;',
              'red_check': '&#x274C;',
              'refresh': '&#x1F504;',
              'right': '&#x226B;',
              'round_arrow_left': '&#x27F2;',
              'round_arrow_right': '&#x27F3;',
              'rss': '&#x1F50A;',
              'save': '&#x1F4BE;',
              'scroll': '&#x1F4DC;',
              'search': '&#x1F50D;',
              'server': '&#x1F5A5;&#xFE0F;',
              'set_square': '&#x1F4D0;',
              'sheet': '&#x1F4C4;',
              'slot': '&#x1F3B0;',
              'sparkles': '&#x2728;',
              'star': '&#x2B50;',
              'top': '&#x1F51D;',
              'trashcan': '&#x1F5D1;&#xFE0F;',
              'truck': '&#x1F69A;',
              'unlocked': '&#x1F513;',
              'updown': '&#x1F503;',
              'users': '&#x1F465;',
              'validate': '&#x1F44C;',
              'warning': '&#x26A0;&#xFE0F;',
              'watch': '&#x231A;',
              }

    # =======
    #  Mimes
    #  https://www.iana.org/assignments/media-types/media-types.xhtml
    #  ./pa show-mime
    # =======

    MIMES = [TyMime([''], ['application/octet-stream'], None, False),
             TyMime(['7z'], ['application/x-7z-compressed'], ['7z'], True),
             TyMime(['aac'], ['audio/vnd.dlna.adts'], None, True),
             TyMime(['abw'], ['application/x-abiword'], None, False),
             TyMime(['accdb'], ['application/msaccess'], ['\x00\x01\x00\x00Standard ACE DB'], False),  # NUL SOH NUL NUL
             TyMime(['aif', 'aifc', 'aiff'], ['audio/aiff', 'audio/x-aiff'], ['AIFF', 'FORM'], True),
             TyMime(['apk'], ['application/vnd.android.package-archive'], ZIP, True),
             TyMime(['atom'], ['application/atom+xml'], XML, True),
             TyMime(['avi'], ['video/avi', 'video/x-msvideo'], ['AVI', 'RIFF'], True),
             TyMime(['avif'], ['image/avif'], None, True),
             TyMime(['bin'], ['application/octet-stream'], None, True),
             TyMime(['bmp'], ['image/bmp'], ['BM'], False),
             TyMime(['bz'], ['application/x-bzip'], ['BZ'], True),
             TyMime(['bz2'], ['application/x-bzip2'], ['BZ'], True),
             TyMime(['cab'], ['application/vnd.ms-cab-compressed'], None, True),
             TyMime(['cer'], ['application/x-x509-ca-cert', 'application/pkix-cert'], None, False),
             TyMime(['chm'], ['application/vnd.ms-htmlhelp'], ['ITSM'], False),
             TyMime(['crt'], ['application/x-x509-ca-cert'], None, False),
             TyMime(['css'], ['text/css'], None, False),
             TyMime(['csv'], ['text/csv', 'application/vnd.ms-excel'], None, False),
             TyMime(['deb'], ['application/x-debian-package'], ZIP, True),
             TyMime(['der'], ['application/x-x509-ca-cert'], None, False),
             TyMime(['dll'], ['application/x-msdownload', 'application/x-msdos-program'], ['MZ'], False),
             TyMime(['doc'], ['application/msword'], CFBF, False),
             TyMime(['docm'], ['application/vnd.ms-word.document.macroEnabled.12'], ZIP, True),
             TyMime(['docx'], ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'], ZIP, True),
             TyMime(['dotm'], ['application/vnd.ms-word.template.macroEnabled.12'], ZIP, True),
             TyMime(['dotx'], ['application/vnd.openxmlformats-officedocument.wordprocessingml.template'], ZIP, True),
             TyMime(['dwg'], ['image/vnd.dwg'], None, False),
             TyMime(['dxf'], ['image/vnd.dxf'], None, False),
             TyMime(['emf'], ['image/x-emf', 'image/emf'], None, False),
             TyMime(['eml'], ['message/rfc822'], None, False),
             TyMime(['eps'], ['application/postscript'], None, False),
             TyMime(['epub'], ['application/epub+zip'], ZIP, True),
             TyMime(['exe'], ['application/x-msdownload', 'application/x-ms-dos-executable'], ['MZ'], False),
             TyMime(['flac'], ['audio/x-flac', 'audio/flac'], ['fLaC'], True),
             TyMime(['flv'], ['video/x-flv'], ['FLV'], False),
             TyMime(['gif'], ['image/gif'], ['GIF87a', 'GIF89a'], True),
             TyMime(['gv'], ['text/vnd.graphviz'], None, False),
             TyMime(['gz', 'gzip'], ['application/x-gzip', 'application/gzip'], ['\x1F\x8B'], True),
             TyMime(['heif'], ['image/heif'], None, True),
             TyMime(['hlp'], ['application/winhlp'], None, False),
             TyMime(['htm', 'html'], ['text/html'], None, False),
             TyMime(['ico'], ['image/x-icon', 'image/vnd.microsoft.icon'], ['\x00\x00\x01\x00'], False),
             TyMime(['ics'], ['text/calendar'], None, False),
             TyMime(['jar'], ['application/java-archive'], ZIP, True),
             TyMime(['jp2'], ['image/jp2'], ['\x00\x00\x00\xFFjP'], True),
             TyMime(['jpg', 'jpeg'], ['image/jpeg'], ['\xFF\xD8\xFF'], True),
             TyMime(['js'], ['application/javascript'], None, False),
             TyMime(['json'], ['application/json'], None, False),
             TyMime(['kml'], ['application/vnd.google-earth.kml+xml'], None, False),
             TyMime(['kmz'], ['application/vnd.google-earth.kmz'], ZIP, True),
             TyMime(['latex'], ['application/x-latex'], None, False),
             TyMime(['m4a'], ['audio/mp4'], None, True),
             TyMime(['md'], ['text/markdown'], None, False),
             TyMime(['mdb'], ['application/msaccess'], ['\x00\x01\x00\x00Standard Jet DB'], False),  # NUL SOH NUL NUL
             TyMime(['mid', 'midi'], ['audio/mid', 'audio/sp-midi'], ['MThd'], False),
             TyMime(['mka', 'mkv'], ['video/x-matroska'], MATROSKA, True),
             TyMime(['mov'], ['video/quicktime'], None, True),
             TyMime(['mp3'], ['audio/mpeg'], ['\xFF\xFB', '\xFF\xF3', '\xFF\xF2'], True),
             TyMime(['mp4'], ['video/mp4'], ['ftypisom'], True),
             TyMime(['mpg', 'mpeg'], ['video/mpeg'], ['\x00\x00\x01\xB3'], True),
             TyMime(['mpp'], ['application/vnd.ms-project'], None, False),
             TyMime(['oda'], ['application/oda'], None, False),
             TyMime(['odf'], ['application/vnd.oasis.opendocument.formula'], ZIP, True),
             TyMime(['odg'], ['application/vnd.oasis.opendocument.graphics'], ZIP, True),
             TyMime(['odi'], ['application/vnd.oasis.opendocument.image'], None, False),
             TyMime(['odp'], ['application/vnd.oasis.opendocument.presentation'], ZIP, True),
             TyMime(['ods'], ['application/vnd.oasis.opendocument.spreadsheet'], ZIP, True),
             TyMime(['odt'], ['application/vnd.oasis.opendocument.text'], ZIP, True),
             TyMime(['oga', 'ogg'], ['audio/ogg'], None, True),
             TyMime(['ogv'], ['video/ogg'], None, True),
             TyMime(['one'], ['application/msonenote'], None, False),
             TyMime(['otf'], ['application/x-font-otf'], None, False),
             TyMime(['otp'], ['application/vnd.oasis.opendocument.presentation-template'], ZIP, True),
             TyMime(['pdf'], ['application/pdf'], ['%PDF-'], False),
             TyMime(['pdfxml'], ['application/vnd.adobe.pdfxml'], None, False),
             TyMime(['png'], ['image/png'], ['\x89PNG'], True),
             TyMime(['pot', 'pps', 'ppt'], ['application/vnd.ms-powerpoint'], CFBF, False),
             TyMime(['potm'], ['application/vnd.ms-powerpoint.template.macroEnabled.12'], ZIP, True),
             TyMime(['potx'], ['application/vnd.openxmlformats-officedocument.presentationml.template'], ZIP, True),
             TyMime(['ppsm'], ['application/vnd.ms-powerpoint.slideshow.macroEnabled.12'], ZIP, True),
             TyMime(['ppsx'], ['application/vnd.openxmlformats-officedocument.presentationml.slideshow'], ZIP, True),
             TyMime(['pptm'], ['application/vnd.ms-powerpoint.presentation.macroEnabled.12'], ZIP, True),
             TyMime(['pptx'], ['application/vnd.openxmlformats-officedocument.presentationml.presentation'], ZIP, True),
             TyMime(['ps'], ['application/postscript'], ['%!PS'], False),
             TyMime(['psd'], ['image/vnd.adobe.photoshop'], None, False),
             TyMime(['pub'], ['application/vnd.ms-publisher'], CFBF, False),
             TyMime(['rar'], ['application/x-rar-compressed', 'application/vnd.rar'], ['Rar!\x1A\x07\x00', 'Rar!\x1A\x07\x01'], True),
             TyMime(['rss'], ['application/rss+xml', 'application/x-rss+xml'], XML, False),
             TyMime(['rtf'], ['application/rtf'], ['{\rtf1'], False),
             TyMime(['sqlite'], ['application/vnd.sqlite3'], ['SQLite format 3\x00'], False),
             TyMime(['stc'], ['application/vnd.sun.xml.calc.template'], None, False),
             TyMime(['std'], ['application/vnd.sun.xml.draw.template'], None, False),
             TyMime(['sti'], ['application/vnd.sun.xml.impress.template'], None, False),
             TyMime(['svg'], ['image/svg+xml'], XML, False),
             TyMime(['swf'], ['application/x-shockwave-flash', 'application/vnd.adobe.flash.movie'], ['CWS', 'FWS'], False),
             TyMime(['sxc'], ['application/vnd.sun.xml.calc'], None, False),
             TyMime(['sxd'], ['application/vnd.sun.xml.draw'], None, False),
             TyMime(['sxi'], ['application/vnd.sun.xml.impress'], None, False),
             TyMime(['sxm'], ['application/vnd.sun.xml.math'], None, False),
             TyMime(['sxw'], ['application/vnd.sun.xml.writer'], None, False),
             TyMime(['tar'], ['application/x-tar'], ['ustar\x0000', 'ustar  \x00'], True),
             TyMime(['tgz'], ['application/x-compressed'], ['\x1F\x8B'], True),
             TyMime(['tif', 'tiff'], ['image/tiff'], ['II*\x00', 'II\x00*'], False),
             TyMime(['tsv'], ['text/tab-separated-values'], None, False),
             TyMime(['ttf'], ['application/x-font-ttf', 'font/ttf'], None, False),
             TyMime(['txt'], ['text/plain'], None, False),
             TyMime(['vcf'], ['text/x-vcard', 'text/vcard'], None, False),
             TyMime(['vsd'], ['application/vnd.ms-visio.viewer'], CFBF, False),
             TyMime(['vsdm', 'vsdx'], ['application/vnd.ms-visio.viewer'], ZIP, True),
             TyMime(['wav'], ['audio/wav', 'audio/x-wav'], ['WAV', 'RIFF'], False),
             TyMime(['weba'], ['audio/webm'], None, True),
             TyMime(['webm'], ['video/webm'], MATROSKA, True),
             TyMime(['webp'], ['image/webp'], ['WEBP', 'RIFF'], True),
             TyMime(['wma'], ['audio/x-ms-wma'], None, True),
             TyMime(['wmf'], ['image/x-wmf', 'image/wmf'], None, False),
             TyMime(['wmv'], ['video/x-ms-wmv'], None, True),
             TyMime(['woff'], ['application/x-font-woff', 'font/woff'], None, False),
             TyMime(['woff2'], ['application/x-font-woff', 'font/woff2'], ['wOF2'], True),
             TyMime(['xaml'], ['application/xaml+xml'], None, False),
             TyMime(['xla', 'xls', 'xlm'], ['application/vnd.ms-excel'], CFBF, False),
             TyMime(['xlsb'], ['application/vnd.ms-excel.sheet.binary.macroEnabled.12'], ZIP, True),
             TyMime(['xlsm'], ['application/vnd.ms-excel.sheet.macroEnabled.12'], ZIP, True),
             TyMime(['xlsx'], ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'], ZIP, True),
             TyMime(['xml'], ['text/xml', 'application/xml'], XML, False),
             TyMime(['xsl', 'xslt'], ['text/xml', 'application/xslt+xml'], XML, False),
             TyMime(['yaml'], ['text/yaml'], None, False),
             TyMime(['z'], ['application/x-compress'], ['\x1F\xA0'], True),
             TyMime(['zip'], ['application/x-zip-compressed', 'application/zip'], ZIP, True),
             ]
    EXECS = ['bat', 'cat', 'cmd', 'com', 'dll', 'docm', 'drv', 'exe', 'potm', 'ppsm', 'pptm', 'ps1', 'scr', 'sh', 'sys', 'vbs', 'xlsm', 'zsh']


class PwicError(Exception):
    ''' Generic exception for Pwic.wiki '''


class PwicLib:
    # ========
    #  System
    # ========

    @staticmethod
    def audit(sql: sqlite3.Cursor, obj: Dict[str, Union[str, int]], request: Optional[web.Request] = None) -> None:
        ''' Save an event into the audit log '''
        from pwic_extension import PwicExtension

        # Check
        if obj.get('event') in [None, '']:
            raise PwicError()
        if request is not None:
            obj['ip'] = PwicExtension.on_ip_header(request)
        if PwicExtension.on_audit_skip(sql, request, obj.copy()):
            return

        # Log the event
        dt = PwicLib.dt()
        sql.execute(''' INSERT INTO audit.audit (date, time, author, event, user, project, page, reference, string, ip)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ''',
                    (str(obj.get('date', dt['date'])),
                     str(obj.get('time', dt['time'])),
                     str(obj.get('author', PwicConst.USERS['anonymous'])),
                     str(obj.get('event', '')),
                     str(obj.get('user', '')),
                     str(obj.get('project', '')),
                     str(obj.get('page', '')),
                     PwicLib.intval(obj.get('reference', 0)),
                     str(obj.get('string', '')),
                     str(obj.get('ip', '')),
                     ))
        if sql.rowcount != 1:
            raise PwicError()

        # Specific event
        try:
            PwicExtension.on_audit(sql, request, obj)
        except Exception:       # nosec B110
            pass

    @staticmethod
    def connect(dbfile: str = PwicConst.DB_SQLITE,
                dbaudit: Optional[str] = PwicConst.DB_SQLITE_AUDIT,
                trace: bool = False,
                in_memory: bool = True,
                asynchronous: bool = False,
                vacuum: bool = False,
                ) -> Tuple[sqlite3.Connection, sqlite3.Cursor]:
        ''' Connect to the database with the relevant options '''
        # Connection
        db = sqlite3.connect(dbfile)
        db.row_factory = PwicLib.row_factory
        if trace:
            db.set_trace_callback(PwicLib.sql_print)

        # Cursor and options
        sql = db.cursor()
        attached = dbaudit is not None
        if attached:
            sql.execute(''' ATTACH DATABASE ? AS audit''', (dbaudit, ))
        if in_memory:
            sql.execute(''' PRAGMA main.journal_mode = MEMORY''')
            if attached:
                sql.execute(''' PRAGMA audit.journal_mode = MEMORY''')
        if asynchronous or (PwicLib.option(sql, '', 'db_async') is not None):
            sql.execute(''' PRAGMA main.synchronous = OFF''')
            if attached:
                sql.execute(''' PRAGMA audit.synchronous = OFF''')
        if vacuum:
            sql.execute(''' VACUUM main''')
            if attached:
                sql.execute(''' VACUUM audit''')
        return db, sql

    @staticmethod
    def detect_language(request: web.Request, allowed_langs: List[str], sso: bool = False) -> str:
        ''' Detect the default language of the user from the HTTP headers '''
        # Detect from the HTTP headers
        head = request.headers.get('Accept-Language', '')
        langs = PwicLib.list(head.replace(',', ' ').replace(';', ' '))
        result = PwicConst.DEFAULTS['language']
        for e in langs:
            if '-' in e:
                e = e[:2]
            if e in allowed_langs:
                result = e
                break

        # Custom detection
        from pwic_extension import PwicExtension
        return PwicExtension.on_language_detected(request, result, allowed_langs, sso)

    @staticmethod
    def init_markdown(sql: Optional[sqlite3.Cursor]) -> Markdown:
        extras = ['code-friendly', 'cuddled-lists', 'fenced-code-blocks', 'footnotes', 'spoiler', 'strike', 'tables', 'task_list', 'underline']
        if (sql is not None) and (PwicLib.option(sql, '', 'no_highlight') is not None):
            extras.append('highlightjs-lang')                               # highlight.js is not used in the foreground
        return Markdown(extras=extras, safe_mode=False, html4tags=True)

    # ====================
    #  Reusable functions
    # ====================

    @staticmethod
    def attachment_name(name: str) -> str:
        ''' Return the file name for a proper download '''
        return "=?utf-8?B?%s?=" % (b64encode(name.encode()).decode())

    @staticmethod
    def convert_length(value: Optional[Union[str, int, float]], target_unit: str, precision: int, dpi: float = PwicConst.DPI) -> str:
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
            m = PwicConst.REGEXES['length'].match(value)
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

    @staticmethod
    async def download_str(url: str, root_mime: str = '') -> Optional[str]:
        # Check
        pu = urlparse(url)
        if (pu.scheme not in ['http', 'https']) or ('\\' in pu.path) or ('..' in pu.path):
            return None

        # Download
        from pwic_extension import PwicExtension
        try:
            headers = {'User-Agent': PwicConst.USER_AGENT}
            PwicExtension.on_download_pre(url, headers)
            async with ClientSession() as client:
                async with client.get(url=url, headers=headers) as response:
                    data = await response.text()
            assert response.content_type[:len(root_mime)] == root_mime
            return data
        except Exception:
            return None

    @staticmethod
    def dt(days: int = 0) -> Dict[str, str]:
        ''' Return some key dates and time '''
        from pwic_extension import PwicExtension
        curtime = datetime.now(tz=PwicExtension.on_timezone())
        return {'date': str(curtime)[:10],
                'date-30d': str(curtime - timedelta(days=30))[:10],
                'date-90d': str(curtime - timedelta(days=90))[:10],
                'date-nd': str(curtime - timedelta(days=days))[:10],
                'time': str(curtime)[11:19]}

    @staticmethod
    def dt_diff(date1: str, date2: str) -> int:
        ''' Calculate the number of days between 2 dates '''
        if date1 > date2:
            date1, date2 = date2, date1
        d1 = datetime.strptime(date1 + ' 00:00:00', PwicConst.DEFAULTS['dt_mask'])
        d2 = datetime.strptime(date2 + ' 00:00:00', PwicConst.DEFAULTS['dt_mask'])
        return (d2 - d1).days

    @staticmethod
    def dt2rfc822(sdate: str, stime: str) -> str:
        ''' Convert a local date&time or a complete date/time to RFC 822
            The time zone may be provided by PwicExtension.on_timezone()
        '''
        from pwic_extension import PwicExtension
        curtime = datetime.strptime(f'{sdate} {stime}', PwicConst.DEFAULTS['dt_mask'])
        curtime = curtime.replace(tzinfo=PwicExtension.on_timezone())
        return datetime.strftime(curtime, '%a, %d %b %Y %H:%M:%S %Z').replace('UTC', 'UT').strip()

    @staticmethod
    def flag(flag: str) -> str:
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

    @staticmethod
    def floatval(value: Any) -> float:
        ''' Safe conversion to float '''
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def intval(value: Any, base=10) -> int:
        ''' Safe conversion to integer in the chosen base '''
        try:
            if base != 10:
                return int(value, base)
            return int(float(value) if '.' in str(value) else value)
        except (ValueError, TypeError):
            return 0

    @staticmethod
    def is_hex(value: str) -> bool:
        ''' Check if the value is a non-zero hexadecimal value '''
        return PwicLib.intval(str(value), base=16) > 0

    @staticmethod
    def list(inputstr: Optional[str], do_sort: bool = False) -> List[str]:
        ''' Build a list of unique values from a string and keep the initial order (by default) '''
        if inputstr is None:
            inputstr = ''
        inputstr = PwicLib.recursive_replace(inputstr.replace('\r', ' ').replace('\n', ' ').replace('\t', ' '), '  ', ' ').strip()
        values = [] if inputstr == '' else list(OrderedDict((e, None) for e in inputstr.split(' ')))
        if do_sort:
            values.sort()
        return values

    @staticmethod
    def list_tags(tags: str) -> str:
        ''' Reorder a list of tags written as a string '''
        return ' '.join(PwicLib.list(tags.replace('#', '').lower(), do_sort=True))

    @staticmethod
    def nns(value: Optional[str]) -> str:
        ''' Return a non-null string '''
        return str('' if value is None else value)

    @staticmethod
    def no_html(value: str) -> str:
        ''' Remove the HTML tags from a string '''
        value = value.replace('&nbsp;', ' ')
        while True:
            i = len(value)
            value = PwicConst.REGEXES['tag_all'].sub('', value)
            value = PwicConst.REGEXES['tag_comment'].sub('', value)
            if len(value) == i:
                break
        return value

    @staticmethod
    def no_md(value: str) -> str:
        return PwicConst.REGEXES['md_strip'].sub('', value)

    @staticmethod
    def option(sql: Optional[sqlite3.Cursor],
               project: Optional[str],
               name: str,
               default: Optional[str] = None,
               ) -> Optional[str]:
        ''' Read a variable from the table ENV that can be project-dependent or not '''
        if (sql is None) or (name not in PwicConst.ENV):
            return default
        try:
            query = ''' SELECT value
                        FROM env
                        WHERE project = ?
                          AND key     = ?
                          AND value  <> '' '''
            if project is None:
                project = ''

            # Read by project
            if not PwicConst.ENV[name].pdep:
                project = ''
            if project == '':
                row = None
            else:
                row = sql.execute(query, (project, name)).fetchone()

            # Read globally
            if (row is None) and PwicConst.ENV[name].pindep:
                project = ''
                row = sql.execute(query, (project, name)).fetchone()

            # Result
            return default if row is None else row['value']
        except sqlite3.OperationalError:    # During init-db
            return default

    @staticmethod
    def random_hash() -> str:
        ''' Generate a random 64-char-long string '''
        return PwicLib.sha256(str(urandom(64)))[:32] + PwicLib.sha256(str(urandom(64)))[32:]

    @staticmethod
    def read_attr(attrs: List[Tuple[str, Optional[str]]], key: str, default: str = '') -> str:
        ''' Read a list of tuples by the first field and return the value in the second field '''
        for (k, v) in attrs:
            if k == key:
                return PwicLib.nns(v)
        return default

    @staticmethod
    def read_attr_key(attrs: List[Tuple[str, Optional[str]]], key: str) -> bool:
        ''' Check a list of tuples by the first field '''
        for k in attrs:
            if k[0] == key:
                return True
        return False

    @staticmethod
    def recursive_replace(text: str, search: Any, replace: str, strip: bool = True) -> str:
        ''' Replace a string recursively '''
        while True:
            curlen = len(text)
            text = text.replace(search, replace)
            if len(text) == curlen:
                break
        if strip:
            text = text.strip()
        return text

    @staticmethod
    def reserved_user_name(user: str) -> bool:
        user = str(user)
        return (user == '') or ((user[:4].lower() == 'pwic') and ('@' not in user))

    @staticmethod
    def robots2str(robots: TyRobotsDict) -> str:
        ''' Convert structured boolean values into a meta string robots '''
        return ' '.join([('' if robots[k] else 'no') + k for k in robots if robots[k] is not None])

    @staticmethod
    def row_factory(cursor: sqlite3.Cursor, row: Tuple[Any, ...]) -> Dict[str, Any]:
        ''' Assign names to the SQL output '''
        d = {}
        for idx, col in enumerate(cursor.description):
            if col[0] in PwicConst.BOOL_COLUMNS:
                d[col[0]] = PwicLib.xb(row[idx])
            elif ((col[0] == 'value') or ('markdown' in col[0])) and isinstance(row[idx], str):
                d[col[0]] = row[idx].replace('\r', '')
            else:
                d[col[0]] = row[idx]
        return d

    @staticmethod
    def safe_file_name(name: str) -> str:
        ''' Ensure that a file name is acceptable '''
        name = PwicLib.safe_name(name, extra='').replace(' ', '_').replace('\t', '_')
        name = PwicLib.recursive_replace(name, '..', '.')
        name = PwicLib.recursive_replace(name, '__', '_')
        return '' if name[:1] == '.' else name

    @staticmethod
    def safe_name(name: Optional[str], extra: str = '.@') -> str:
        ''' Ensure that a string will not collide with the reserved characters of the operating system '''
        if name is None:
            return ''
        chars = PwicConst.CHARS_UNSAFE + extra
        for c in chars:
            name = name.replace(c, '')
        return name.strip().lower()[:PwicLib.intval(PwicConst.DEFAULTS['limit_filename'])]

    @staticmethod
    def safe_user_name(name: Optional[str]) -> str:
        ''' Ensure that a user name is acceptable '''
        return PwicLib.safe_name(name, extra='')

    @staticmethod
    def sha256(value: Union[str, bytearray], salt: bool = True) -> str:
        ''' Calculate the SHA256 as string for the given value '''
        if isinstance(value, bytearray):
            if salt:
                raise PwicError()
            return sha256(value).hexdigest()
        text = (PwicConst.SALT if salt else '') + str(value)
        return sha256(text.encode()).hexdigest()

    @staticmethod
    def sha256_file(filename: str) -> str:
        ''' Calculate the SHA256 as string for the given file '''
        try:
            hashval = sha256()
            with open(filename, 'rb') as f:
                for block in iter(lambda: f.read(4096), b''):
                    hashval.update(block)
            return hashval.hexdigest()
        except FileNotFoundError:
            return ''

    @staticmethod
    def shrink(value: Optional[str]) -> str:
        ''' Convert a string into its shortest value in lower case '''
        if value is None:
            return ''
        return value.replace('\r', '').replace('\n', '').replace('\t', '').replace(' ', '').strip().lower()

    @staticmethod
    def size2str(size: Union[int, float, str]) -> str:
        ''' Convert a size to a readable format '''
        if isinstance(size, str):
            size = PwicLib.floatval(size)
        units = ' kMGTPEZ'
        for i in range(len(units)):
            if size < 1024:
                break
            size /= 1024
        return ('%.1f %sB' % (size, units[i].strip())).replace('.0 ', ' ')

    @staticmethod
    def sql_print(query: Optional[str]) -> None:
        ''' Quick and dirty callback to print the SQL queries on a single line for debugging purposes '''
        if query is not None:
            dt = PwicLib.dt()
            print('[%s %s] %s' % (dt['date'],
                                  dt['time'],
                                  ' '.join([PwicLib.recursive_replace(q.strip().replace('\r', '').replace('\t', ' '), '  ', ' ') for q in query.split('\n')])))

    @staticmethod
    def str2bytearray(inputstr: str) -> bytearray:
        ''' Convert string to bytearray '''
        barr = bytearray()      # =bytearray(bytes.encode()) breaks the bytes sequence due to the encoding
        for c in inputstr:
            barr.append(ord(c))
        return barr

    @staticmethod
    def str2robots(robots: str) -> TyRobotsDict:
        ''' Convert a meta string robots into structured boolean values '''
        values = PwicLib.list(robots)
        result: TyRobotsDict = {}
        for k in ['archive', 'follow', 'imageindex', 'index', 'snippet', 'translate']:
            if 'no' + k in values:
                result[k] = False
            elif k in values:
                result[k] = True
            else:
                result[k] = None
        return result

    @staticmethod
    def timestamp() -> int:
        ''' Returns the current time stamp '''
        return PwicLib.intval(time())

    @staticmethod
    def x(value: Any) -> str:
        ''' Reduce an input value to a boolean string '''
        return '' if value in [None, 'none', 'None', 'NONE', 'null', 'Null', 'NULL', 'nil', 'Nil', 'NIL', '', 0, '0',
                               False, 'false', 'False', 'FALSE', '-', '~', 'no', 'No', 'NO', 'off', 'Off', 'OFF', 'undefined'] else 'X'

    @staticmethod
    def xb(value: str) -> bool:
        ''' Convert 'X' to a boolean value '''
        return value == 'X'

    # =======
    #  Mimes
    # =======

    @staticmethod
    def file_ext(filename: str) -> str:
        ''' Return the file extension of the file '''
        return splitext(filename)[1][1:].strip().lower()

    @staticmethod
    def magic_bytes(ext: str) -> Optional[List[str]]:
        ''' Return the magic bytes that corresponds to the file extension '''
        ext = ext.strip().lower()
        for item in PwicConst.MIMES:
            if ext in item.exts:
                return item.magic
        return None

    @staticmethod
    def mime(ext: str) -> Optional[str]:
        ''' Return the default mime that corresponds to the file extension '''
        values = PwicLib.mime_list(ext)
        return None if len(values) == 0 else values[0]

    @staticmethod
    def mime_compressed(ext: str) -> bool:
        ''' Return the possible state of compression based on the file extension '''
        ext = ext.strip().lower()
        for item in PwicConst.MIMES:
            if ext in item.exts:
                return item.compressed
        return False

    @staticmethod
    def mime_list(ext: str) -> List[str]:
        ''' Return the possible mimes that correspond to the file extension '''
        ext = ext.strip().lower()
        for item in PwicConst.MIMES:
            if ext in item.exts:
                return item.mimes
        return []

    @staticmethod
    def mime2icon(mime: str) -> str:
        ''' Return the emoji that corresponds to the MIME '''
        if mime[:6] == 'image/':
            return PwicConst.EMOJIS['image']
        if mime[:6] == 'video/':
            return PwicConst.EMOJIS['camera']
        if mime[:6] == 'audio/':
            return PwicConst.EMOJIS['headphone']
        if mime[:12] == 'application/':
            return PwicConst.EMOJIS['server']
        return PwicConst.EMOJIS['sheet']

    @staticmethod
    def mime_zipped(ext: str) -> bool:
        ''' Return if a file extension is a disguised ZIP file '''
        ext = ext.strip().lower()
        for item in PwicConst.MIMES:
            if ext in item.exts:
                return item.magic == ZIP
        return False

    # ===============
    #  Search engine
    # ===============

    @staticmethod
    def search_parse(query: str, case_sensitive: bool) -> Dict[str, List[str]]:
        ''' Build a search object from a string '''
        included = []
        excluded = []
        terms = PwicConst.REGEXES['search_terms'].findall(query.replace('\r', '').strip())
        for negative, term in terms:
            if term.startswith('"') and term.endswith('"'):
                term = term[1:-1]
            if not case_sensitive:
                term = term.lower()
            if negative == '-':
                excluded.append(term)
            else:
                included.append(term)
        included.sort(key=lambda v: v.lower())
        excluded.sort(key=lambda v: v.lower())
        return {'included': included,
                'excluded': excluded}

    @staticmethod
    def search2string(query: Dict[str, List[str]]) -> str:
        ''' Convert a search object back to string '''
        if query is None:
            return ''
        result = ''
        for q in query['included']:
            quote = '"' if ' ' in q else ''
            result += f' {quote}{q}{quote}'
        for q in query['excluded']:
            quote = '"' if ' ' in q else ''
            result += f' -{quote}{q}{quote}'
        return result.strip()

    # ========
    #  Editor
    # ========

    @staticmethod
    def extended_syntax(markdown: str, mask: Optional[str], headerNumbering: bool = True) -> Tuple[str, List[Dict]]:
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
            # sof/48983939
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
        b = len(PwicConst.DEFAULTS['heading'])
        if a < b:
            mask += PwicConst.DEFAULTS['heading'][a - b:]

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
                    snum = tmask[m2n](c)
                    ssep = mask[2 * n + 1]
                    sdisp += f'{snum}{ssep}'
                    stag += f'_{snum.lower()}'

                # Adapt the line
                if headerNumbering:
                    lines[i] = f'{line[:3]} id="p{stag}"><span class="pwic_paragraph_id" title="#p{stag}">{sdisp}</span> {line[4:]}'
                else:
                    lines[i] = f'{line[:3]} id="p{stag}">{line[4:]}'
                tmap.append({'header': sdisp,
                             'tag': f'p{stag}',
                             'level': stag.count('_'),
                             'title': line.strip()[4:-5]})

        # Final formatting
        return '\n'.join(lines), tmap


class PwicBuffer:
    ''' Class to concatenate long strings through a short buffer for better performances '''
    def __init__(self):
        self.buflen = 262144
        self.reset()

    def reset(self):
        ''' Reset the string buffer '''
        self.tmp = ''
        self.data = ''

    def push(self, buffer: str):
        ''' Add a string to the buffer '''
        self.tmp += buffer
        if len(self.tmp) >= self.buflen:
            self.data += self.tmp
            self.tmp = ''

    def pop(self) -> str:
        ''' Get the complete buffered string '''
        self.data += self.tmp
        self.tmp = ''
        return self.data

    def override(self, buffer: str):
        ''' Replace the current buffer by a new string '''
        self.tmp = ''
        self.data = buffer

    def length(self):
        ''' Get the length of the buffered string '''
        return len(self.tmp) + len(self.data)

    def rstrip(self):
        ''' Strip the buffer from the right '''
        self.data += self.tmp
        self.tmp = ''
        self.data = self.data.rstrip()

    def lastchar(self) -> str:
        ''' Get the last character of the buffered string '''
        return self.tmp[-1:] or self.data[-1:]


class PwicHTMLParserTL(HTMLParser):
    ''' Class HTMLParser with a limited duration of execution '''
    def reset(self) -> None:
        ''' Reset all the data of the parser '''
        super().reset()
        self.timer_max = PwicLib.timestamp() + 15
        self.timer_counter = 0

    def feed(self, data: str) -> None:
        ''' Parse the inbound content '''
        # No reset
        try:
            super().feed(data)
        except TimeoutError:
            self.on_timeout()

    def check_timeout(self) -> None:
        ''' Raise an exception if the duration is exhausted '''
        self.timer_counter += 1
        if self.timer_counter >= 16384:
            self.timer_counter = 0
            if PwicLib.timestamp() > self.timer_max:
                raise TimeoutError()

    def on_timeout(self) -> None:
        ''' Abstract event raised when the duration is exhausted '''
