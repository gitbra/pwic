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

from typing import Dict, List, Optional, Tuple
import sqlite3
from os.path import join
import re
from zipfile import ZipFile
from html import unescape
from html.parser import HTMLParser

from pwic_lib import PWIC_DOCUMENTS_PATH, pwic_file_ext, pwic_int, pwic_option, pwic_read_attr, pwic_recursive_replace
from pwic_extension import PwicExtension
from pwic_exporter import PwicCleanerHtml


class PwicImporter():
    def __init__(self, user: str):
        self.user = user

    def convert(self, sql: Optional[sqlite3.Cursor], id: int) -> Optional[str]:
        # Read the document
        if (sql is None) or (id == 0):
            return None
        sql.execute(''' SELECT project, page, filename
                        FROM documents
                        WHERE id     = ?
                          AND exturl = '' ''',
                    (id, ))
        row = sql.fetchone()
        if row is None:
            return None

        # Convert the document
        base_url = str(pwic_option(sql, '', 'base_url', ''))
        filename = join(PWIC_DOCUMENTS_PATH % row['project'], row['filename'])
        extension = pwic_file_ext(row['filename'])
        try:
            result = ''
            if extension in PwicImporterHtml.get_extensions():
                result = PwicImporterHtml().get_md(filename)
            if extension in PwicImporterOdt.get_extensions():
                result = PwicImporterOdt(base_url).get_md(filename)
        except Exception:
            return None
        return PwicExtension.on_api_document_convert(sql, row['project'], self.user, row['page'], id, result)

    @staticmethod
    def get_allowed_extensions() -> List[str]:
        return ['odt', 'htm', 'html']


# ===================================================
#  html2md
# ===================================================

class PwicImporterHtml(HTMLParser):       # html2md
    def __init__(self):
        HTMLParser.__init__(self)
        self.map_open = {'a': '[',
                         'b': '**',
                         'blockcode': '\n\n> ',
                         'br': '\n',
                         'code': '`',
                         'div': '\n',
                         'em': '*',
                         'h1': '\n\n# ',
                         'h2': '\n\n## ',
                         'h3': '\n\n### ',
                         'h4': '\n\n#### ',
                         'h5': '\n\n##### ',
                         'h6': '\n\n###### ',
                         'i': '*',
                         'img': '![IMAGE',
                         'li': '\n- ',
                         'ol': '\n',
                         'p': '\n\n',
                         'pre': '```',
                         's': '~~',
                         'strike': '~~',
                         'strong': '**',
                         'sub': '_',
                         'sup': '^',
                         'tr': '\n| ',
                         'u': '--',
                         'ul': '\n'}
        self.map_close = {'a': '](#href)',
                          'b': '**',
                          'code': '`',
                          'em': '*',
                          'h1': '\n',
                          'h2': '\n',
                          'h3': '\n',
                          'h4': '\n',
                          'h5': '\n',
                          'h6': '\n',
                          'i': '*',
                          'img': '](#src)',
                          'ol': '\n',
                          'pre': '```',
                          's': '~~',
                          'strike': '~~',
                          'strong': '**',
                          'sub': '_',
                          'sup': '^',
                          'td': ' |',
                          'th': ' |',
                          'u': '--',
                          'ul': '\n'}

    def reset(self) -> None:
        HTMLParser.reset(self)
        self.md = ''
        self.pre = False
        self.last_tag = ''
        self.last_href = ''
        self.last_src = ''
        self.table_col_max = 0
        self.table_col_cur = 0
        self.table_lin_cur = 0

    def feed(self, data: str):
        cleaner = PwicCleanerHtml('', False)
        cleaner.feed(data)
        HTMLParser.feed(self, cleaner.get_html())

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if not self.pre and (tag == 'pre'):
            self.pre = True
        if not self.pre:
            if tag == 'a':
                self.last_href = pwic_read_attr(attrs, 'href')
            if tag == 'img':
                self.last_src = pwic_read_attr(attrs, 'src')
            if (tag == 'li') and (self.last_tag not in ['ol', 'ul']):
                self.md = self.md.rstrip()
            if tag == 'table':
                self.table_col_max = 0
                self.table_col_cur = 0
                self.table_lin_cur = 0
            if tag == 'tr':
                self.md = self.md.rstrip()
                if self.last_tag == 'table':
                    self.md += '\n'
                self.table_col_cur = 0
                self.table_lin_cur += 1
                if self.table_lin_cur == 2:
                    self.md += '\n|' + ('---|' * self.table_col_max)
            if tag in ['th', 'td']:
                self.md = self.md.rstrip() + ' '
                self.table_col_cur += 1
                self.table_col_max = max(self.table_col_max, self.table_col_cur)
        if tag in self.map_open:
            self.md += self.map_open[tag]
        self.last_tag = tag

    def handle_endtag(self, tag: str) -> None:
        if self.pre and (tag == 'pre'):
            self.pre = False
        if tag in self.map_close:
            value = self.map_close[tag]
            if not self.pre:
                if tag == 'a':
                    value = value.replace('#href', self.last_href)
                    self.last_href = ''
                if tag == 'img':
                    value = value.replace('#src', self.last_src)
                    self.last_src = ''
                if (tag in ['td', 'th']) and (self.last_tag == 'tr'):
                    self.md = self.md.rstrip() + ' '
            self.md += value

    def handle_data(self, data: str) -> None:
        if not self.pre:
            data = pwic_recursive_replace(data.replace('\t', ' '), '  ', ' ', strip=False)
        self.md += data

    @staticmethod
    def get_extensions() -> List[str]:
        return ['htm', 'html']

    def get_md(self, filename: str) -> str:
        # Read the HTML content
        try:
            content = b''
            with open(filename, 'rb') as f:
                content = f.read()
            html = content.decode()
        except Exception:
            return ''

        # Extract the main content
        for tag in ['body', 'article']:
            p1 = html.find('<' + tag)
            p2 = html.rfind('</%s>' % tag)
            if (-1 not in [p1, p2]) and (p1 < p2):
                p1 = html.find('>', p1)
                html = html[p1 + 1:p2].replace('\r', '').strip()

        # Convert
        self.feed(html)
        lines = [e.rstrip() for e in self.md.split('\n')]
        return pwic_recursive_replace('\n'.join(lines), '\n\n\n', '\n\n')


# ===================================================
#  odt2md
# ===================================================

class PwicStylerOdt(HTMLParser):
    def reset(self) -> None:
        HTMLParser.reset(self)
        self.styles: Dict[str, Dict[str, bool]] = {}
        self.reset_marks()

    def reset_marks(self) -> None:
        self.name = ''
        self.bold = False
        self.italic = False
        self.underline = False
        self.strike = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.strip().lower()
        # Block
        if tag == 'style:style':
            self.reset_marks()
            if pwic_read_attr(attrs, 'style:family') == 'text':
                self.name = pwic_read_attr(attrs, 'style:name')
            else:
                self.name = ''
        # Attributes
        elif tag == 'style:text-properties':
            value = pwic_read_attr(attrs, 'fo:font-weight')
            if value != '':
                self.bold = (value != 'normal')
            value = pwic_read_attr(attrs, 'fo:font-style')
            if value != '':
                self.italic = value in ['italic', 'oblique']
            value = pwic_read_attr(attrs, 'style:text-underline-type')
            if value != '':
                self.underline = (value != 'none')
            value = pwic_read_attr(attrs, 'style:text-line-through-style')
            if value != '':
                self.strike = (value != 'none')

    def handle_endtag(self, tag: str) -> None:
        tag = tag.strip().lower()
        if (tag == 'style:style') and (self.name != '') and (self.name[:5] != 'Code_'):
            if self.bold or self.italic or self.underline or self.strike:
                self.styles[self.name] = {'bold': self.bold,
                                          'italic': self.italic,
                                          'underline': self.underline,
                                          'strike': self.strike}

    def get_decorator(self, name: str) -> str:
        deco = ''
        if name in self.styles:
            if self.styles[name]['bold']:
                deco += '**'
            if self.styles[name]['italic']:
                deco += '*'
            if self.styles[name]['underline']:
                deco += '--'
            if self.styles[name]['strike']:
                deco += '~~'
        return deco


class PwicImporterOdt(HTMLParser):
    def __init__(self, base_url: str):
        HTMLParser.__init__(self)
        self.base_url = base_url

    def reset(self) -> None:
        HTMLParser.reset(self)

        # Content
        self.content = ''
        self.styler = PwicStylerOdt()

        # Parser
        self.md = ''
        self.link = ''
        self.listlevel = 0
        self.table = False
        self.table_rows = 0
        self.table_cols = 0
        self.spanstack: List[str] = []
        self.mute = ''

    def load_odt(self, filename: str) -> bool:
        # Read the contents
        content = ''
        styles = ''
        try:
            with ZipFile(filename) as odt:
                with odt.open('content.xml') as f:          # Mandatory
                    content = f.read().decode()
                with odt.open('styles.xml') as f:           # Optional
                    styles = f.read().decode()
        except (FileNotFoundError, KeyError):
            pass
        if content == '':
            return False

        # Extract the main block
        p1 = content.find('<office:body>')                  # Has no attribute
        p2 = content.rfind('</office:body>')
        if (-1 in [p1, p2]) or (p1 > p2):
            return False
        self.content = content[p1 + 13:p2].replace('\r', '').strip()

        # Read the styles
        self.styler.reset()
        self.styler.feed(styles)
        return True

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        # Mute
        if self.mute != '':
            return
        tag = tag.strip().lower()
        # Element
        if tag == 'text:span':
            deco = self.styler.get_decorator(pwic_read_attr(attrs, 'text:style-name'))
            if self.link != '':
                deco = deco.replace('--', '')
            self.md += deco
            self.spanstack.append(deco[::-1])
        elif tag == 'text:a':
            self.md += '['
            self.link = pwic_read_attr(attrs, 'xlink:href')
            if (self.link[:len(self.base_url)] == self.base_url) and (len(self.link) > len(self.base_url)):
                self.link = self.link[len(self.base_url):]
        elif tag == 'draw:frame':
            self.md += '[IMAGE]'
            self.mute = tag                                 # Assumed to be not imbricated
        # Block
        elif tag == 'text:p':
            if (self.listlevel == 0) and not self.table:
                self.md += '\n\n'
        elif tag == 'text:h':
            self.md += '\n\n%s ' % ('#' * pwic_int(pwic_read_attr(attrs, 'text:outline-level')))
        # List
        elif tag == 'text:list':
            self.listlevel += 1
            if self.listlevel == 1:
                self.md += '\n\n'
        elif tag == 'text:list-item':
            self.md += '\n%s- ' % ('    ' * (self.listlevel - 1))
        # Table
        elif tag == 'table:table':
            self.table = True
            self.table_rows = 0
            self.table_cols = 0
            self.md += '\n'
        elif tag == 'table:table-row':
            self.table_rows += 1
            if self.table_rows == 2:
                self.md += '\n|%s' % ('---|' * self.table_cols)
            self.md += '\n| '
        elif tag == 'table:table-cell':
            self.table_cols += 1

    def handle_endtag(self, tag: str) -> None:
        tag = tag.strip().lower()
        if tag == self.mute:
            self.mute = ''
        if tag == 'text:s':
            self.md += ' '
        elif tag == 'text:tab':
            self.md += '\t'
        elif tag == 'text:line-break':
            self.md += '\n'
        elif tag == 'text:span':
            try:
                self.md += self.spanstack.pop()
            except IndexError:
                pass
        elif tag == 'text:a':
            self.md += '](%s)' % self.link
            self.link = ''
        elif tag == 'text:list':
            self.listlevel -= 1
            self.listlevel = max(0, self.listlevel)
        elif tag == 'table:table':
            self.table = False
        elif tag == 'table:table-cell':
            self.md += ' | '

    def handle_data(self, data: str) -> None:
        if self.mute != '':
            data = ''
        elif (self.listlevel > 0) or self.table:
            data = data.replace('\n', ' ')
            data = re.sub(r'^[\s\t]+', ' ', data)   # Soft strip for start
            data = re.sub(r'[\s\t]+$', ' ', data)   # Soft strip for end
        self.md += unescape(data)

    @staticmethod
    def get_extensions() -> List[str]:
        return ['odt']

    def get_md(self, filename) -> str:
        if not self.load_odt(filename):
            return ''
        self.feed(self.content)
        lines = [e.rstrip() for e in self.md.split('\n')]
        return pwic_recursive_replace('\n'.join(lines), '\n\n\n', '\n\n')
