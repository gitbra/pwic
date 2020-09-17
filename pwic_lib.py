#!/usr/bin/env python

import re
import datetime
from hashlib import sha256

from parsimonious.grammar import Grammar
from parsimonious.nodes import NodeVisitor


# ===================================================
#  Constants
# ===================================================

PWIC_VERSION = '0.9'
PWIC_DB = './db/pwic.sqlite'
PWIC_DB_BACKUP = './db/pwic_%s.sqlite'
PWIC_DOCUMENTS_PATH = './db/documents/%s/'
PWIC_USER = 'pwic-system'
PWIC_USER_ANONYMOUS = 'pwic-anonymous'
PWIC_DEFAULT_PASSWORD = 'initial'
PWIC_SALT = ''    # Random string to secure the generated hashes for the passwords
PWIC_PRIVATE_KEY = 'db/pwic_secure.key'
PWIC_PUBLIC_KEY = 'db/pwic_secure.crt'

PWIC_EMOJIS = {'alien': '&#x1F47D;',
               'brick': '&#x1F9F1;',
               'calendar': '&#x1F4C5;',
               'camera': '&#x1F3A5;',               # 1F4F9
               'chains': '&#x1F517;',
               'check': '&#x2714;',
               'clamp': '&#x1F5DC;',
               'door': '&#x1F6AA;',
               'eye': '&#x1F441;',
               'flag': '&#x1F3C1;',
               'gemini': '&#x264A;',
               'glasses': '&#x1F453;',
               'globe': '&#x1F310;',
               'green_check': '&#x2705;',
               'hammer': '&#x1F528;',
               'headphone': '&#x1F3A7;',
               'hourglass': '&#x23F3;',
               'image': '&#x1F4F8;',                # 1F5BC
               'inbox': '&#x1F4E5;',
               'key': '&#x1F511;',
               'laptop': '&#x1F4BB;',
               'left_arrow': '&#x2BC7;',
               'locked': '&#x1F512;',
               'notes': '&#x1F4CB;',
               'padlock': '&#x1F510;',
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
               'sos': '&#x1F198;',
               'star': '&#x2B50;',
               'trash': '&#x1F5D1;',
               'unlocked': '&#x1F513;',
               'users': '&#x1F465;',
               'validate': '&#x1F44C;',
               'world': '&#x1F5FA;'}
PWIC_CHARS_UNSAFE = '\\/:;%*?=&#\'"!<>(){}[]|'      # Various signs incompatible with filesystem, HTML, SQL, etc...


# ===================================================
#  MIMES
# ===================================================

ZIP = ['PK']
MATROSKA = ['\x1A\x45\xDF\xA3']
CFBF = ['\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1']
PWIC_MIMES = [(['7z'], 'application/x-7z-compressed', ['7z']),
              (['aac'], 'audio/vnd.dlna.adts', None),
              (['abw'], 'application/x-abiword', None),
              (['accdb'], 'application/msaccess', ['\x00\x01\x00\x00Standard ACE DB']),  # NUL SOH NUL NUL
              (['aif', 'aifc', 'aiff'], 'audio/aiff', ['AIFF', 'FORM']),
              (['apk'], 'application/vnd.android.package-archive', ZIP),
              (['avi'], 'video/avi', ['AVI', 'RIFF']),
              (['bin'], 'application/octet-stream', None),
              (['bmp'], 'image/bmp', ['BM']),
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
              (['rar'], 'application/x-rar-compressed', None),
              (['rss'], 'application/rss+xml', None),
              (['rtf'], 'application/msword', ['{\rtf1']),
              (['sti'], 'application/vnd.sun.xml.impress.template', None),
              (['svg'], 'image/svg+xml', None),
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

def _x(value):
    ''' Convert a boolean to 'X' or empty string '''
    return 'X' if value is True else ''


def _xb(value):
    ''' Convert 'X' to a boolean '''
    return True if value == 'X' else False


def _int(value):
    ''' Safe conversion to integer '''
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def _dt():
    ''' Return some key dates and time '''
    dts = str(datetime.datetime.now())
    return {'date': dts[:10],
            'date-30d': str(datetime.date.today() - datetime.timedelta(days=30))[:10],
            'date-90d': str(datetime.date.today() - datetime.timedelta(days=90))[:10],
            'time': dts[11:19]}


def _recursiveReplace(text, search, replace):
    while True:
        curlen = len(text)
        text = text.replace(search, replace)
        if len(text) == curlen:
            break
    return text.strip()


def _sha256(value, salt=True):
    ''' Calculate the SHA256 as string for the given value '''
    if type(value) == bytearray:
        assert(salt is False)
        return sha256(value).hexdigest()
    else:
        text = (PWIC_SALT if salt else '') + value
        return sha256(text.encode()).hexdigest()


def _safeName(name, extra='.@'):
    chars = PWIC_CHARS_UNSAFE + extra
    for i in range(len(chars)):
        name = name.replace(chars[i], '')
    return name.lower().strip()


def _safeFileName(name):
    name = _safeName(name, extra='').replace(' ', '_')
    while True:
        curlen = len(name)
        name = name.replace('..', '.').replace('__', '_')
        if len(name) == curlen:
            break
    return name


def _size2str(size):
    ''' Convert a size to a readable format '''
    units = ' kMGTPEZ'
    for i in range(len(units)):
        if size < 1024:
            break
        size /= 1024
    return ('%.1f %sB' % (size, units[i].strip())).replace('.0 B', ' B')


# ===================================================
#  Editor
# ===================================================

def pwic_extended_syntax(markdown):
    ''' Automatic numbering of the MD headers '''
    # Initialisation
    reg_header = re.compile(r'^<h([1-6])>', re.IGNORECASE)
    lines = markdown.replace('\r', '').split('\n')
    numbering = []
    last_depth = 0
    tmap = []

    # For each line
    for i in range(len(lines)):
        line = lines[i]

        # Parse
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
            ss = ''
            for n in numbering:
                ss += '%d.' % n

            # Adapt the line
            lines[i] = '%s id="p%s"><span class="pwic_paragraph_id" title="#p%s">%s</span> %s' % (line[:3], ss, ss, ss, line[4:])
            tmap.append({'header': ss,
                         'level': ss.count('.'),
                         'title': line.strip()[4:-5]})

    # Final formatting
    return '\n'.join(lines), tmap


# ===================================================
#  Traceability of the activities
# ===================================================

def pwic_audit(sql, object, request=None, commit=False):
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
        if commit:
            sql.execute('COMMIT')
        return True
    else:
        assert(False)


# ===================================================
#  Search engine
# ===================================================

class PwicSearchVisitor(NodeVisitor):
    def __init__(self):
        self.negate = False
        self.included = []
        self.excluded = []

    def visit_decl(self, node, visited_children):
        pass

    def visit_term(self, node, visited_children):
        pass

    def visit_comb(self, node, visited_children):
        pass

    def visit_space(self, node, visited_children):
        pass

    def visit_negate(self, node, visited_children):
        if node.match.group(0) == '-':
            self.negate = True

    def visit_individual(self, node, visited_children):
        (self.excluded if self.negate else self.included).append(node.match.group(0).strip().lower())
        self.negate = False

    def visit_quoted(self, node, visited_children):
        (self.excluded if self.negate else self.included).append(node.match.group(0)[1:-1].strip().lower())
        self.negate = False


def pwic_search_parse(query):
    # Parse the query
    if query in ['', None]:
        return None
    try:
        ast = Grammar(
            r"""
            decl        = term*
            term        = space negate space comb
            comb        = individual / quoted

            space       = ~r"[\s\t]*"
            negate      = ~r"-?"
            individual  = ~r'[^\"|^\s]+'
            quoted      = ~r'\"[^\"]+\"'
            """
        ).parse(query.strip())

        # Extract the keywords
        psv = PwicSearchVisitor()
        psv.visit(ast)
        return {'included': psv.included,
                'excluded': psv.excluded}
    except Exception:
        return None


def pwic_search_tostring(query):
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
