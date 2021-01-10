#!/usr/bin/env python

import re
import datetime
from hashlib import sha256
from html import escape
from html.parser import HTMLParser
from parsimonious.grammar import Grammar
from parsimonious.nodes import NodeVisitor


# ===================================================
#  Constants
# ===================================================

PWIC_VERSION = '1.0-rc4'
PWIC_DB = './db'
PWIC_DB_SQLITE = PWIC_DB + '/pwic.sqlite'
PWIC_DB_SQLITE_BACKUP = PWIC_DB + '/pwic_%s.sqlite'
PWIC_DOCUMENTS_PATH = PWIC_DB + '/documents/%s/'
PWIC_TEMPLATES_PATH = './templates/'
PWIC_USER_ANONYMOUS = 'pwic-anonymous'
PWIC_USER_GHOST = 'pwic-ghost'
PWIC_USER_SYSTEM = 'pwic-system'
PWIC_DEFAULT_PASSWORD = 'initial'
PWIC_DEFAULT_LANGUAGE = 'en'
PWIC_DEFAULT_PAGE = 'home'
PWIC_DEFAULT_HEADING = '1.1.1.1.1.1.'
PWIC_DEFAULT_LOGGING_FORMAT = '%a %t "%r" %s %b'

PWIC_SALT = ''    # Random string to secure the generated hashes for the passwords
PWIC_PRIVATE_KEY = 'db/pwic_secure.key'
PWIC_PUBLIC_KEY = 'db/pwic_secure.crt'

PWIC_REGEX_PAGE = r'\]\(\/([^\/#\)]+)\/([^\/#\)]+)(\/rev[0-9]+)?(\?.*)?(\#.*)?\)'       # Find a page in Markdown
PWIC_REGEX_DOCUMENT = r'\]\(\/special\/document\/([0-9]+)(\?attachment)?( "[^"]+")?\)'  # Find a document in Markdown
PWIC_REGEX_DOCUMENT_IMGSRC = r'^\/?special\/document\/([0-9]+)([\?\#].*)?$'             # Find the picture ID in IMG.SRC
PWIC_REGEX_MIME = r'^[a-z]+\/[a-z0-9\.\+\-]+$'                                          # Check the format of the mime
PWIC_REGEX_HTML_TAG = r'\<[^\>]+\>'                                                     # Find a HTML tag

PWIC_ENV_PROJECT_INDEPENDENT = ['base_url', 'cors', 'http_log_file', 'http_log_format', 'ip_filter', 'maintenance',
                                'mime_enforcement', 'no_logon', 'password_regex', 'safe_mode', 'ssl', 'xff']
PWIC_ENV_PROJECT_DEPENDENT = ['api_expose_markdown', 'audit_range', 'css', 'css_dark', 'dark_mode', 'disabled_formats',
                              'document_name_regex', 'export_project_revisions', 'heading_mask', 'kbid',
                              'legal_notice', 'mathjax', 'max_document_size', 'max_project_size', 'no_export_project',
                              'no_history', 'no_mde', 'no_new_user_online', 'no_printing', 'no_search',
                              'no_text_selection', 'odt_page_height', 'odt_page_width', 'robots', 'support_email',
                              'support_phone', 'support_text', 'support_url', 'validated_only']
PWIC_ENV_PROJECT_DEPENDENT_ONLINE = ['audit_range', 'dark_mode', 'disabled_formats', 'heading_mask', 'mathjax',
                                     'no_history', 'no_mde', 'no_printing', 'no_search', 'no_text_selection',
                                     'odt_page_height', 'odt_page_width', 'support_email', 'support_phone',
                                     'support_text', 'support_url', 'validated_only']

PWIC_EMOJIS = {'alien': '&#x1F47D;',
               'brick': '&#x1F9F1;',
               'bug': '&#x1F41B;',
               'calendar': '&#x1F4C5;',
               'camera': '&#x1F3A5;',               # 1F4F9
               'chains': '&#x1F517;',
               'check': '&#x2714;',
               'clamp': '&#x1F5DC;',
               'clipboard': '&#x1F4CB;',
               'door': '&#x1F6AA;',
               'email': '&#x1F4E7;',
               'eye': '&#x1F441;',
               'finger_down': '&#x1F447;',
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
               'image': '&#x1F4F8;',                # 1F5BC
               'inbox': '&#x1F4E5;',
               'key': '&#x1F511;',
               'laptop': '&#x1F4BB;',
               'left_arrow': '&#x2BC7;',
               'locked': '&#x1F512;',
               'memo': '&#x1F4DD;',
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
               'right_arrow': '&#x21E5;',
               'save': '&#x1F4BE;',
               'scroll': '&#x1F4DC;',
               'search': '&#x1F50D;',
               'server': '&#x1F5A5;',
               'set_square': '&#x1F4D0;',
               'sheet': '&#x1F4C4;',
               'slider': '&#x1F39A;',
               'sos': '&#x1F198;',
               'star': '&#x2B50;',
               'trash': '&#x1F5D1;',
               'unlocked': '&#x1F513;',
               'users': '&#x1F465;',
               'validate': '&#x1F44C;',
               'wave': '&#x1F30A;',
               'world': '&#x1F5FA;'}
PWIC_CHARS_UNSAFE = '\\/:;%*?=&#\'"!<>(){}[]|'      # Various signs incompatible with filesystem, HTML, SQL, etc...


# ===================================================
#  MIMES
#  https://www.iana.org/assignments/media-types/media-types.xhtml
# ===================================================

ZIP = ['PK']
MATROSKA = ['\x1A\x45\xDF\xA3']
CFBF = ['\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1']
MIME_BMP = 'image/bmp'
MIME_JSON = 'application/json'
MIME_GENERIC = 'application/octet-stream'
MIME_SVG = 'image/svg+xml'
MIME_TEXT = 'text/plain'
PWIC_MIMES = [(['7z'], 'application/x-7z-compressed', ['7z']),
              (['aac'], 'audio/vnd.dlna.adts', None),
              (['abw'], 'application/x-abiword', None),
              (['accdb'], 'application/msaccess', ['\x00\x01\x00\x00Standard ACE DB']),  # NUL SOH NUL NUL
              (['aif', 'aifc', 'aiff'], 'audio/aiff', ['AIFF', 'FORM']),
              (['apk'], 'application/vnd.android.package-archive', ZIP),
              (['avi'], 'video/avi', ['AVI', 'RIFF']),
              (['bin'], MIME_GENERIC, None),
              (['bmp'], MIME_BMP, ['BM']),
              (['bz', 'bz2'], 'application/x-bzip2', ['BZ']),
              (['cer'], 'application/x-x509-ca-cert', None),
              (['chm'], 'application/vnd.ms-htmlhelp', ['ITSM']),
              (['crt'], 'application/x-x509-ca-cert', None),
              (['css'], 'text/css', None),
              (['csv'], 'application/vnd.ms-excel', None),
              (['deb'], 'application/x-debian-package', ZIP),
              (['der'], 'application/x-x509-ca-cert', None),
              (['dll'], 'application/x-msdownload', ['MZ']),
              (['doc'], 'application/msword', CFBF),
              (['docm'], 'application/vnd.ms-word.document.macroEnabled.12', ZIP),
              (['docx'], 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', ZIP),
              (['dwg'], 'image/vnd.dwg', None),
              (['dxf'], 'image/vnd.dxf', None),
              (['emf'], 'image/x-emf', None),
              (['eml'], 'message/rfc822', None),
              (['eps'], 'application/postscript', None),
              (['epub'], 'application/epub+zip', ZIP),
              (['exe'], 'application/x-msdownload', ['MZ']),
              (['flac'], 'audio/x-flac', ['fLaC']),
              (['flv'], 'video/x-flv', ['FLV']),
              (['gif'], 'image/gif', ['GIF87a', 'GIF89a']),
              (['gv'], 'text/vnd.graphviz', None),
              (['gz', 'gzip'], 'application/x-gzip', ['\x1F\x8B']),
              (['hlp'], 'application/winhlp', None),
              (['htm'], 'text/html', None),
              (['html'], 'text/html', None),
              (['ico'], 'image/x-icon', ['\x00\x00\x01\x00']),
              (['ics'], 'text/calendar', None),
              (['jar'], 'application/java-archive', ZIP),
              (['jpg', 'jpeg'], 'image/jpeg', ['\xFF\xD8\xFF']),
              (['json'], 'application/json', None),
              (['kml'], 'application/vnd.google-earth.kml+xml', None),
              (['kmz'], 'application/vnd.google-earth.kmz', ZIP),
              (['latex'], 'application/x-latex', None),
              (['mdb'], 'application/msaccess', ['\x00\x01\x00\x00Standard Jet DB']),  # NUL SOH NUL NUL
              (['mid', 'midi'], 'audio/mid', ['MThd']),
              (['mka', 'mkv'], 'video/x-matroska', MATROSKA),
              (['mov'], 'video/quicktime', None),
              (['mp3'], 'audio/mpeg', ['\xFF\xFB', '\xFF\xF3', '\xFF\xF2']),
              (['mp4'], 'video/mp4', ['ftypisom']),
              (['mpg', 'mpeg'], 'video/mpeg', ['\x00\x00\x01\xB3']),
              (['mpp'], 'application/vnd.ms-project', None),
              (['msg'], None, CFBF),
              (['oda'], 'application/oda', None),
              (['odf'], 'application/vnd.oasis.opendocument.formula', None),
              (['odg'], 'application/vnd.oasis.opendocument.graphics', None),
              (['odi'], 'application/vnd.oasis.opendocument.image', None),
              (['odp'], 'application/vnd.oasis.opendocument.presentation', ZIP),
              (['ods'], 'application/vnd.oasis.opendocument.spreadsheet', ZIP),
              (['odt'], 'application/vnd.oasis.opendocument.text', ZIP),
              (['oga'], 'audio/ogg', None),
              (['ogv'], 'video/ogg', None),
              (['one'], 'application/msonenote', None),
              (['otf'], 'application/x-font-otf', None),
              (['otp'], 'application/vnd.oasis.opendocument.presentation-template', None),
              (['pdf'], 'application/pdf', ['%PDF-']),
              (['pdfxml'], 'application/vnd.adobe.pdfxml', None),
              (['png'], 'image/png', ['\x89PNG']),
              (['pot'], 'application/vnd.ms-powerpoint', CFBF),
              (['potm'], 'application/vnd.ms-powerpoint.template.macroEnabled.12', ZIP),
              (['potx'], 'application/vnd.openxmlformats-officedocument.presentationml.template', ZIP),
              (['pps'], 'application/vnd.ms-powerpoint', CFBF),
              (['ppsm'], 'application/vnd.ms-powerpoint.slideshow.macroEnabled.12', ZIP),
              (['ppsx'], 'application/vnd.openxmlformats-officedocument.presentationml.slideshow', ZIP),
              (['ppt'], 'application/vnd.ms-powerpoint', CFBF),
              (['pptm'], 'application/vnd.ms-powerpoint.presentation.macroEnabled.12', ZIP),
              (['pptx'], 'application/vnd.openxmlformats-officedocument.presentationml.presentation', ZIP),
              (['ps'], 'application/postscript', ['%!PS']),
              (['psd'], 'image/vnd.adobe.photoshop', None),
              (['pub'], 'application/vnd.ms-publisher', CFBF),
              (['rar'], 'application/x-rar-compressed', ['Rar!\x1A\x07\x00', 'Rar!\x1A\x07\x01']),
              (['rss'], 'application/rss+xml', None),
              (['rtf'], 'application/msword', ['{\rtf1']),
              (['sti'], 'application/vnd.sun.xml.impress.template', None),
              (['svg'], MIME_SVG, None),
              (['swf'], 'application/x-shockwave-flash', ['CWS', 'FWS']),
              (['sxc'], 'application/vnd.sun.xml.calc', None),
              (['sxd'], 'application/vnd.sun.xml.draw', None),
              (['sxi'], 'application/vnd.sun.xml.impress', None),
              (['sxm'], 'application/vnd.sun.xml.math', None),
              (['sxw'], 'application/vnd.sun.xml.writer', None),
              (['tar'], 'application/x-tar', ['ustar\x0000', 'ustar  \x00']),
              (['tgz'], 'application/x-compressed', ['\x1F\x8B']),
              (['tif', 'tiff'], 'image/tiff', ['II*\x00', 'II\x00*']),
              (['tsv'], 'text/tab-separated-values', None),
              (['ttf'], 'application/x-font-ttf', None),
              (['txt'], 'text/plain', None),
              (['vcf'], 'text/x-vcard', None),
              (['vsd'], 'application/vnd.ms-visio.viewer', CFBF),
              (['vsdm'], 'application/vnd.ms-visio.viewer', ZIP),
              (['vsdx'], 'application/vnd.ms-visio.viewer', ZIP),
              (['wav'], 'audio/wav', ['WAV', 'RIFF']),
              (['weba'], 'audio/webm', None),
              (['webm'], 'video/webm', MATROSKA),
              (['webp'], 'image/webp', ['WEBP', 'RIFF']),
              (['wma'], 'audio/x-ms-wma', None),
              (['wmf'], 'image/x-wmf', None),
              (['wmv'], 'video/x-ms-wmv', None),
              (['woff'], 'application/x-font-woff', None),
              (['woff2'], 'application/x-font-woff', None),
              (['xaml'], 'application/xaml+xml', None),
              (['xls'], 'application/vnd.ms-excel', CFBF),
              (['xlsm'], 'application/vnd.ms-excel.sheet.macroEnabled.12', ZIP),
              (['xlsx'], 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', ZIP),
              (['xml'], 'text/xml', None),
              (['xsl'], 'text/xml', None),
              (['yaml'], 'text/yaml', None),
              (['z'], 'application/x-compress', ['\x1F\xA0']),
              (['zip'], 'application/x-zip-compressed', ZIP)]


# ===================================================
#  Reusable functions
# ===================================================

def _x(value: bool) -> str:
    ''' Convert a boolean to 'X' or empty string '''
    return 'X' if value else ''


def _xb(value: str) -> bool:
    ''' Convert 'X' to a boolean '''
    return value == 'X'


def _int(value: str) -> int:
    ''' Safe conversion to integer '''
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def _dt(drange: int = 0) -> object:
    ''' Return some key dates and time '''
    dts = str(datetime.datetime.now())
    return {'date': dts[:10],
            'date-30d': str(datetime.date.today() - datetime.timedelta(days=30))[:10],
            'date-90d': str(datetime.date.today() - datetime.timedelta(days=90))[:10],
            'date-nd': str(datetime.date.today() - datetime.timedelta(days=drange))[:10],
            'time': dts[11:19]}


def _recursiveReplace(text: str, search: str, replace: str) -> str:
    while True:
        curlen = len(text)
        text = text.replace(search, replace)
        if len(text) == curlen:
            break
    return text.strip()


def _sha256(value: str, salt: bool = True) -> str:
    ''' Calculate the SHA256 as string for the given value '''
    if type(value) == bytearray:
        assert(salt is False)
        return sha256(value).hexdigest()
    else:
        text = (PWIC_SALT if salt else '') + value
        return sha256(text.encode()).hexdigest()


def _safeName(name: str, extra: str = '.@') -> str:
    chars = PWIC_CHARS_UNSAFE + extra
    for i in range(len(chars)):
        name = name.replace(chars[i], '')
    return name.strip().lower()


def _safeFileName(name: str) -> str:
    name = _safeName(name, extra='').replace(' ', '_')
    while True:
        curlen = len(name)
        name = name.replace('..', '.').replace('__', '_')
        if len(name) == curlen:
            break
    return name


def _size2str(size: int) -> str:
    ''' Convert a size to a readable format '''
    units = ' kMGTPEZ'
    for i in range(len(units)):
        if size < 1024:
            break
        size /= 1024
    return ('%.1f %sB' % (size, units[i].strip())).replace('.0 B', ' B')


def _sqlprint(query: str) -> str:
    ''' Quick and dirty callback to print the SQL queries on a single line for debugging purposes '''
    if query is not None:
        dt = _dt()
        print('[%s %s] %s' % (dt['date'],
                              dt['time'],
                              ' '.join([_recursiveReplace(q.strip().replace('\r', '').replace('\t', ' '), '  ', ' ') for q in query.split('\n')])))


# ===================================================
#  Editor
# ===================================================

def pwic_extended_syntax(markdown: str, mask: str, headerNumbering: bool = True) -> (str, object):
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
        # https://stackoverflow.com/questions/48983939/convert-a-number-to-excel-s-base-26
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
        return _letter(value, 'abcdefghijklmnopqrstuvwxyz')

    def _letterMaj(value: int) -> str:
        return _letter(value, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')

    # Initialisation
    reg_header = re.compile(r'^<h([1-6])>', re.IGNORECASE)
    lines = markdown.replace('\r', '').split('\n')
    numbering = []
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
    b = len(PWIC_DEFAULT_HEADING)
    if a < b:
        mask += PWIC_DEFAULT_HEADING[a - b:]

    # For each line
    for i in range(len(lines)):
        line = lines[i]
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
                snum = tmask[mask[2 * n]](numbering[n])
                ssep = mask[2 * n + 1]
                sdisp += '%s%s' % (snum, ssep)
                stag += '%s.' % snum.lower()

            # Adapt the line
            if headerNumbering:
                lines[i] = '%s id="p%s"><span class="pwic_paragraph_id" title="#p%s">%s</span> %s' % (line[:3], stag, stag, sdisp, line[4:])
            else:
                lines[i] = '%s id="p%s">%s' % (line[:3], stag, line[4:])
            tmap.append({'header': sdisp,
                         'level': stag.count('.'),
                         'title': line.strip()[4:-5]})

    # Final formatting
    return '\n'.join(lines), tmap


# ===================================================
#  Traceability of the activities
# ===================================================

def pwic_audit(sql: object, object: object, request: bool = None) -> bool:
    ''' Save an event into the audit log '''
    # Forced properties of the event
    dt = _dt()
    object['date'] = dt['date']
    object['time'] = dt['time']
    if request is not None:
        object['ip'] = request.remote
    assert(object.get('event', '') != '')

    # Log the event
    fields = ''
    tups = ''
    tuple = ()
    for key in object:
        fields += '%s, ' % key
        tups += '?, '
        tuple += (object[key], )
    sql.execute("INSERT INTO audit (%s) VALUES (%s)" % (fields[:-2], tups[:-2]), tuple)
    if sql.rowcount == 1:
        return True
    else:
        assert(False)


# ===================================================
#  Search engine
# ===================================================

class PwicSearchVisitor(NodeVisitor):
    def __init__(self) -> None:
        self.negate = False
        self.included = []
        self.excluded = []

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


def pwic_search_parse(query: str) -> object:
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


def pwic_search_tostring(query: str) -> str:
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
#  html2odt
# ===================================================

class pwic_html2odt(HTMLParser):
    def __init__(self: object, baseUrl: str, project: str, page: str, pictMeta: object = None) -> None:
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
                           'b': {'text:style-name': 'Bold'},
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
        self.extrasBefore = {'img': ('<draw:frame text:anchor-type="as-char" svg:width="{$w}px" svg:height="{$h}px" style:rel-width="scale" style:rel-height="scale">', '</draw:frame>')}
        self.extrasAfter = {'a': ('<text:span text:style-name="Link">', '</text:span>'),
                            'td': ('<text:p>', '</text:p>'),
                            'th': ('<text:p>', '</text:p>')}

        # Processing
        self.regex_imgsrc = re.compile(PWIC_REGEX_DOCUMENT_IMGSRC)
        self.tag_path = []
        self.table_descriptors = []
        self.blockquote_on = False
        self.blockcode_on = False
        self.has_code = False
        self.lastIMGalt = ''
        self.lastIMGtitle = ''

        # Output
        self.odt = ''

    def _replace_marker(self: object, joker: str, content: str) -> None:
        pos = self.odt.rfind(joker)
        if pos != -1:
            self.odt = self.odt[:pos] + str(content) + self.odt[pos + len(joker):]

    def handle_starttag(self: object, tag: str, attrs: object) -> None:
        tag = tag.lower()

        # Rules
        lastTag = self.tag_path[-1] if len(self.tag_path) > 0 else ''
        # ... no imbricated paragraphs
        if tag == lastTag == 'p':
            return
        # ... list item should be enclosed by <p>
        elif tag != 'p' and lastTag == 'li':
            self.tag_path.append('p')
            self.odt += '<%s>' % self.maps['p']
        # ... subitems should close <p>
        elif tag in ['ul', 'ol'] and lastTag == 'p':
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
            self.odt += '<text:p text:style-name="Error">Unknown tag \'%s\'</text:p>' % tag
        else:
            if self.maps[tag] is not None:
                # Automatic extra tags
                if tag in self.extrasBefore:
                    self.odt += self.extrasBefore[tag][0]

                # Tag itself
                self.odt += '<' + self.maps[tag]
                if tag in self.attributes:
                    for property in self.attributes[tag]:
                        property_value = self.attributes[tag][property]
                        if property_value[:1] != '#':
                            if property[:5] != 'dummy':
                                self.odt += ' %s="%s"' % (property, escape(property_value))
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
                                        if tag == 'a' and key == 'href':
                                            if value[:1] in ['/']:
                                                value = self.baseUrl + value
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
                                                    docid = self.regex_imgsrc.match(value)
                                                    if docid is not None:
                                                        docid = _int(docid.group(1))
                                                        if docid in self.pictMeta:
                                                            self._replace_marker('{$w}', self.pictMeta[docid]['width'])
                                                            self._replace_marker('{$h}', self.pictMeta[docid]['height'])

                                        # Fix the class name for the syntax highlight
                                        if tag == 'span' and self.blockcode_on and key == 'class':
                                            value = 'Code_' + value

                                        if property[:5] != 'dummy':
                                            self.odt += ' %s="%s"' % (property, escape(value))
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

    def handle_endtag(self: object, tag: str) -> None:
        tag = tag.lower()

        # Rules
        lastTag = self.tag_path[-1] if len(self.tag_path) > 0 else ''
        # ... no imbricated paragraphs
        if tag == 'p' and lastTag != 'p':
            return
        # ... list item should be enclosed by <p>
        elif tag == 'li' and lastTag == 'p':
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

    def handle_data(self: object, data: str) -> None:
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
