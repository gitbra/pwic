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
import re
from zipfile import ZipFile
from html import unescape
from html.parser import HTMLParser

from pwic_lib import pwic_int, pwic_option, pwic_read_attr, pwic_recursive_replace


# ===================================================
#  odt2md
# ===================================================

class PwicConverter_odt2styles(HTMLParser):
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


class PwicConverter_odt2md(HTMLParser):
    def __init__(self, sql: Optional[sqlite3.Cursor]):
        HTMLParser.__init__(self)
        if sql is not None:
            self.base_url = str(pwic_option(sql, '', 'base_url', ''))
        else:
            self.base_url = ''

    def reset(self) -> None:
        HTMLParser.reset(self)

        # Content
        self.content = ''
        self.styler = PwicConverter_odt2styles()

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
        with ZipFile(filename) as odt:
            try:
                with odt.open('content.xml') as f:          # Mandatory
                    content = f.read().decode()
                with odt.open('styles.xml') as f:           # Optional
                    styles = f.read().decode()
            except KeyError:
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

    def get_md(self) -> str:
        self.feed(self.content)
        lines = [e.rstrip() for e in self.md.split('\n')]
        return pwic_recursive_replace('\n'.join(lines), '\n\n\n', '\n\n')
