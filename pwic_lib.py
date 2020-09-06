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
PWIC_DEFAULT_PASSWORD = 'initial'
PWIC_SALT = ''    # Random string to secure the generated hashes for the passwords
PWIC_PRIVATE_KEY = 'db/pwic_secure.key'
PWIC_PUBLIC_KEY = 'db/pwic_secure.crt'

PWIC_EMOJIS = {'brick': '&#x1F9F1;',
               'calendar': '&#x1F4C5;',
               'chains': '&#x1F517;',
               'check': '&#x2714;',
               'clamp': '&#x1F5DC;',
               'door': '&#x1F6AA;',
               'eye': '&#x1F441;',
               'flag': '&#x1F3C1;',
               'glasses': '&#x1F453;',
               'globe': '&#x1F310;',
               'hammer': '&#x1F528;',
               'hourglass': '&#x23F3;',
               'key': '&#x1F511;',
               'laptop': '&#x1F4BB;',
               'left_arrow': '&#x2BC7;',
               'locked': '&#x1F512;',
               'notes': '&#x1F4CB;',
               'padlock': '&#x1F510;',
               'plug': '&#x1F50C;',
               'printer': '&#x1F5A8;',
               'recycle': '&#x267B;',
               'right_arrow': '&#x21E5;',
               'save': '&#x1F4BE;',
               'scroll': '&#x1F4DC;',
               'search': '&#x1F50D;',
               'set_square': '&#x1F4D0;',
               'sheet': '&#x1F4C4;',
               'sos': '&#x1F198;',
               'star': '&#x2B50;',
               'trash': '&#x1F5D1;',
               'unlocked': '&#x1F513;',
               'users': '&#x1F465;',
               'validate': '&#x1F44C;',
               'world': '&#x1F5FA;'}


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
    except ValueError:
        return 0


def _dt():
    ''' Return some key dates and time '''
    dts = str(datetime.datetime.now())
    return {'date': dts[:10],
            'date-30d': str(datetime.date.today() - datetime.timedelta(days=30))[:10],
            'date-90d': str(datetime.date.today() - datetime.timedelta(days=90))[:10],
            'time': dts[11:19]}


def _sha256(value, salt=True):
    ''' Calculate the SHA256 as string for the given value '''
    text = (PWIC_SALT if salt else '') + value
    return sha256(text.encode()).hexdigest()


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
