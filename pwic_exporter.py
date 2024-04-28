# Pwic.wiki server running on Python and SQLite
# Copyright (C) 2020-2024 Alexandre Bréard
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

from typing import Dict, List, Optional, Tuple, Union
import sqlite3
from zipfile import ZipFile, ZIP_DEFLATED, ZIP_STORED
from io import BytesIO
from os.path import isfile, join
import re
from html import escape

from pwic_md import Markdown, MarkdownError
from pwic_lib import PwicConst, PwicLib, PwicError, PwicBuffer, PwicHTMLParserTL
from pwic_extension import PwicExtension


class PwicExporter():
    ''' Export pages from Pwic.wiki '''

    def __init__(self, app_markdown: Markdown, user: str):
        self.app_markdown = app_markdown
        self.user = user
        self.options = {'relative_html': False}

    # ===========
    #  Interface
    # ===========

    def convert(self,
                sql: Optional[sqlite3.Cursor],
                project: str,
                page: str,
                revision: int,
                extension: str,
                ) -> Optional[Union[str, bytes]]:
        # Read the revision without the cache
        if (sql is None) or (revision == 0) or (extension not in PwicExporter.get_allowed_extensions()):
            return None
        sql.execute(''' SELECT project, page, revision, latest, author,
                               date, time, title, markdown, tags
                        FROM pages
                        WHERE project  = ?
                          AND page     = ?
                          AND revision = ?''',
                    (project, page, revision))
        row = sql.fetchone()
        if row is None:
            return None

        # Dynamic constants
        base_url = str(PwicLib.option(sql, '', 'base_url', ''))
        legal_notice = str(PwicLib.option(sql, project, 'legal_notice', '')).strip()
        legal_notice = re.sub(r'\<[^\>]+\>', '', legal_notice)

        # Convert the revision
        if extension == 'md':
            return PwicExtension.on_markdown_pre(sql, project, page, revision, row['markdown']).replace('\r', '')
        if extension == 'html':
            html = self.md2corehtml(sql, row, export_odt=False)
            return self._corehtml2html(sql, row, html, base_url, legal_notice)
        if extension == 'odt':
            return self._md2odt(sql, row, base_url, legal_notice)
        return None

    def set_option(self, name: str, value: bool) -> None:
        self.options[name] = value

    @staticmethod
    def get_allowed_extensions() -> List[str]:
        return ['md', 'html', 'odt']

    # ======
    #  HTML
    # ======

    def md2corehtml(self, sql: sqlite3.Cursor, row: Dict, export_odt: bool) -> str:
        # Convert MD to HTML without the headers
        markdown = PwicExtension.on_markdown_pre(sql, row['project'], row['page'], row['revision'], row['markdown'])
        try:
            html = self.app_markdown.convert(markdown.replace('\r', ''))
        except MarkdownError:
            html = ''
        (otag, ctag) = ('<blockcode>', '</blockcode>') if export_odt else ('<code>', '</code>')
        html = html.replace('<div class="codehilite">\n<pre><span></span><code>', otag)     # With pygments
        html = html.replace('\n</code></pre>\n</div>', ctag)
        html = html.replace('<pre><code', otag[:-1])                                        # Without pygments
        html = html.replace('\n</code></pre>', ctag)
        cleaner = PwicCleanerHtml(str(PwicLib.option(sql, row['project'], 'skipped_tags', '')),
                                  PwicLib.option(sql, row['project'], 'link_nofollow') is not None)
        cleaner.feed(html)
        html = cleaner.get_html()
        return PwicExtension.on_html(sql, row['project'], row['page'], row['revision'], html).replace('\r', '')

    def _corehtml2html(self, sql: sqlite3.Cursor, row: Dict, html: str, base_url: str, legal_notice: str) -> str:
        # Convert HTML without headers to full HTML
        htmlStyles = PwicStylerHtml()
        html = PwicLib.extended_syntax(html,
                                       PwicLib.option(sql, row['project'], 'heading_mask'),
                                       PwicLib.option(sql, row['project'], 'no_heading') is None)[0]
        html = htmlStyles.html % (row['author'].replace('"', '&quote;'),
                                  row['date'],
                                  row['time'],
                                  row['page'].replace('<', '&lt;').replace('>', '&gt;'),
                                  row['title'].replace('<', '&lt;').replace('>', '&gt;'),
                                  htmlStyles.get_css(rel=self.options['relative_html']).replace('src:url(/', 'src:url(%s/' % escape(base_url)),
                                  '' if legal_notice == '' else ('<!--\n%s\n-->' % legal_notice),
                                  html)
        if not self.options['relative_html']:
            html = html.replace('<a href="/', '<a href="%s/' % escape(base_url))
            html = html.replace('<img src="/special/document/', '<img src="%s/special/document/' % escape(base_url))
        return html

    # =====
    #  ODT
    # =====

    def _odt_get_pict(self, sql: sqlite3.Cursor, row: Dict) -> Dict[int, Dict[str, Union[str, int, bool]]]:
        # Extract the meta-informations of the embedded pictures
        MAX_H = max(0, PwicLib.intval(PwicLib.convert_length(PwicLib.option(sql, row['project'], 'odt_image_height_max', '900px'), '', 0)))
        MAX_W = max(0, PwicLib.intval(PwicLib.convert_length(PwicLib.option(sql, row['project'], 'odt_image_width_max', '600px'), '', 0)))
        docids = ['0']
        subdocs = PwicConst.REGEXES['document'].findall(row['markdown'])
        if subdocs is not None:
            for sd in subdocs:
                sd = str(PwicLib.intval(sd[0]))
                if sd not in docids:
                    docids.append(sd)
        query = ''' SELECT a.id, a.project, a.page, a.filename, a.mime, a.width, a.height, a.exturl
                    FROM documents AS a
                        INNER JOIN roles AS b
                            ON  b.project  = a.project
                            AND b.user     = ?
                            AND b.disabled = ''
                    WHERE a.id   IN (%s)
                      AND a.mime LIKE 'image/%%' '''
        sql.execute(query % ','.join(docids), (self.user, ))
        pict = {}
        while True:
            rowdoc = sql.fetchone()
            if rowdoc is None:
                break

            # Optimize the size of the picture
            try:
                if rowdoc['width'] > MAX_W:
                    rowdoc['height'] *= MAX_W / rowdoc['width']
                    rowdoc['width'] = MAX_W
                if rowdoc['height'] > MAX_H:
                    rowdoc['width'] *= MAX_H / rowdoc['height']
                    rowdoc['height'] = MAX_H
            except ValueError:
                pass

            # Store the meta data
            entry = {}
            entry['filename'] = join(PwicConst.DOCUMENTS_PATH % rowdoc['project'], rowdoc['filename'])
            entry['link'] = 'special/document/%d' % (rowdoc['id'] if rowdoc['exturl'] == '' else rowdoc['exturl'])
            entry['link_odt_img'] = 'special/document_%d' % (rowdoc['id'] if rowdoc['exturl'] == '' else rowdoc['exturl'])     # LibreOffice does not support the paths with multiple folders
            entry['compressed'] = PwicLib.mime_compressed(PwicLib.file_ext(rowdoc['filename']))
            entry['manifest'] = ('<manifest:file-entry manifest:full-path="special/document_%d" manifest:media-type="%s" />' % (rowdoc['id'], rowdoc['mime'])) if rowdoc['exturl'] == '' else ''
            entry['width'] = PwicLib.intval(rowdoc['width'])
            entry['height'] = PwicLib.intval(rowdoc['height'])
            entry['remote'] = rowdoc['exturl'] != ''
            pict[rowdoc['id']] = entry
        return pict

    def _md2odt(self, sql: sqlite3.Cursor, row: Dict, base_url: str, legal_notice: str) -> Optional[bytes]:
        # Convert to ODT
        html = self.md2corehtml(sql, row, export_odt=True)
        if html == '':
            return None
        pict = self._odt_get_pict(sql, row)
        try:
            odtGenerator = PwicMapperOdt(base_url, row['project'], row['page'], pict)
            odtGenerator.feed(html)
        except Exception:
            return None

        # Prepare the ODT file in the memory
        inmemory = BytesIO()
        with ZipFile(inmemory, mode='w', compression=ZIP_DEFLATED) as odt:
            odt.writestr('mimetype', str(PwicLib.mime('odt')), compress_type=ZIP_STORED, compresslevel=0)   # Must be the first file of the ZIP and not compressed

            # Manifest
            buffer = ''
            for i in pict:
                meta = pict[i]
                if not meta['remote'] and isfile(meta['filename']):
                    content = b''
                    with open(meta['filename'], 'rb') as f:
                        content = f.read()
                    if meta['compressed']:
                        odt.writestr(str(meta['link_odt_img']), content, compress_type=ZIP_STORED, compresslevel=0)
                    else:
                        odt.writestr(str(meta['link_odt_img']), content)
                    del content
                    buffer += '%s\n' % meta['manifest']
            odtStyles = PwicStylerOdt()
            odt.writestr('META-INF/manifest.xml', odtStyles.manifest.replace('<!-- attachments -->', buffer))

            # Properties of the file
            dt = PwicLib.dt()
            buffer = odtStyles.meta % (PwicConst.VERSION,
                                       escape(row['title']),
                                       escape(row['project']), escape(row['page']),
                                       ('<meta:keyword>%s</meta:keyword>' % escape(row['tags'])) if row['tags'] != '' else '',
                                       escape(row['author']),
                                       escape(row['date']), escape(row['time']),
                                       escape(self.user),
                                       escape(dt['date']), escape(dt['time']),
                                       row['revision'])
            odt.writestr('meta.xml', buffer)

            # Styles
            xml = odtStyles.styles
            xml = xml.replace('<!-- styles-code -->', odtStyles.getOptimizedCodeStyles(html) if odtGenerator.has_code else '')
            xml = xml.replace('<!-- styles-heading-format -->', odtStyles.getHeadingStyles(PwicLib.option(sql, row['project'], 'heading_mask')))
            if legal_notice != '':
                legal_notice = ''.join(['<text:p text:style-name="Footer">%s</text:p>' % line for line in legal_notice.split('\n')])
            xml = xml.replace('<!-- styles-footer -->', legal_notice)
            pw = PwicLib.convert_length(PwicLib.option(sql, row['project'], 'odt_page_width', '21cm'), 'cm', 1)
            ph = PwicLib.convert_length(PwicLib.option(sql, row['project'], 'odt_page_height', '29.7cm'), 'cm', 1)
            if PwicLib.option(sql, row['project'], 'odt_page_landscape') is not None:
                po = 'landscape'
                pw, ph = ph, pw
            else:
                po = 'portrait'
            xml = xml.replace('{$pw}', pw)
            xml = xml.replace('{$ph}', ph)
            xml = xml.replace('{$po}', po)
            xml = xml.replace('{$pm}', PwicLib.convert_length(PwicLib.option(sql, row['project'], 'odt_page_margin', '2.5cm'), 'cm', 2))
            odt.writestr('styles.xml', xml)

            # Content of the page
            page_url = f'{base_url}/{row["project"]}/{row["page"]}/rev{row["revision"]}'
            xml = odtStyles.content
            xml = xml.replace('<!-- content-url -->', '<text:p text:style-name="Reference"><text:a xlink:href="%s" xlink:type="simple"><text:span text:style-name="Link">%s</text:span></text:a></text:p>' % (page_url, page_url))  # Trick to connect the master layout to the page
            xml = xml.replace('<!-- content-page -->', odtGenerator.buffer.pop())
            odt.writestr('content.xml', xml)

        # Result
        stream = inmemory.getvalue()
        inmemory.close()
        return stream


# ================
#  Tools for HTML
# ================

class PwicCleanerHtml(PwicHTMLParserTL):    # html2html
    def __init__(self, skipped_tags: str, nofollow: bool) -> None:
        self.buffer = PwicBuffer()
        super().__init__()
        self.skipped_tags = PwicLib.list('applet embed iframe link meta noscript object script style ' + skipped_tags.lower())
        self.nofollow = nofollow

    def reset(self) -> None:
        super().reset()
        self.tag_path: List[str] = []
        self.code = ''                      # Special code block
        self.buffer.reset()

    def on_timeout(self) -> None:
        self.buffer.reset()

    def is_mute(self) -> bool:
        for t in self.skipped_tags:
            if t in self.tag_path:
                return True
        return False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        def _list2obj(attrs: List[Tuple[str, Optional[str]]]) -> Dict[str, str]:
            result = {}
            for (k, v) in attrs:
                k = PwicLib.shrink(k)
                if k not in result:
                    result[k] = v or ''
                else:
                    result[k] = f'{result[k]} {v}'.strip()
            return result

        # Tag path
        self.check_timeout()
        tag = tag.lower()
        if tag not in PwicConst.VOID_HTML:
            self.tag_path.append(tag)
        if self.is_mute():
            return
        if (self.code == '') and (tag in ['blockcode', 'code', 'svg']):
            self.code = tag

        # Detect the external links
        props = _list2obj(attrs)
        if (tag == 'a') and self.nofollow and ('://' in props.get('href', '')):
            props['rel'] = 'nofollow'

        # Process the attributes
        buffer = ''
        for (k, v) in props.items():
            if (((k in ['alt', 'checked', 'class', 'colspan', 'data-src', 'disabled', 'height', 'href', 'id', 'rel', 'src', 'style', 'title', 'type', 'width'])
                 or ((self.code == 'svg') and (k[:2] != 'on')))):
                v2 = PwicLib.shrink(v)
                if ('javascript' not in v2) and ('url:' not in v2):
                    buffer += f' {k}="{v}"'
        self.buffer.push(f'<{tag}{buffer}>')

    def handle_endtag(self, tag: str) -> None:
        # Tag path
        tag = tag.lower()
        lastTag = self.tag_path[-1] if len(self.tag_path) > 0 else ''
        if tag != lastTag:
            return

        # Data
        if self.code == tag:    # Not imbricated
            self.code = ''
        if not self.is_mute():
            self.buffer.push(f'</{tag}>')
        self.tag_path.pop()

    def handle_comment(self, data: str) -> None:
        if not self.is_mute():
            self.handle_data(f'<!--{data}-->')

    def handle_data(self, data: str) -> None:
        if not self.is_mute():
            if self.code in ['blockcode', 'code']:
                data = data.replace('<', '&lt;').replace('>', '&gt;')   # No escape()
            self.buffer.push(data)

    def get_html(self) -> str:
        html = self.buffer.pop().replace('<hr></hr>', '<hr>').replace('></img>', '>')
        while True:
            curlen = len(html)
            html = re.sub(PwicConst.REGEXES['empty_tag'], '', html)
            html = re.sub(PwicConst.REGEXES['empty_tag_with_attrs'], r'\3', html)
            html = re.sub(PwicConst.REGEXES['adjacent_tag'], r'\2', html)
            if len(html) == curlen:
                break
        return html


class PwicStylerHtml:
    def __init__(self) -> None:
        self.css = 'static/styles.css'
        self.html = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="author" content="%s">
    <meta name="last-modified" content="%s %s">
    <title>[%s] %s</title>
    %s
</head>
<body>
%s
    <article>%s</article>
</body>
</html>'''

    def get_css(self, rel: bool) -> str:
        if rel:
            return f'<link rel="stylesheet" type="text/css" href="{self.css}" />'
        content = ''
        with open(self.css, 'r', encoding='utf-8') as f:
            content = f.read()
        return f'<style>{content}</style>'


# =========================
#  Tools for OpenDocument
# =========================

class PwicMapperOdt(PwicHTMLParserTL):      # html2odt
    def __init__(self, base_url: str, project: str, page: str, pict: Optional[Dict] = None) -> None:
        self.buffer = PwicBuffer()
        super().__init__()

        # External parameters
        self.base_url = base_url
        self.project = project
        self.page = page
        self.pict = pict

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
                     'input': None,
                     'img': 'draw:image',
                     'ins': 'text:span',
                     'li': 'text:list-item',
                     'ol': 'text:list',
                     'p': 'text:p',
                     's': 'text:span',
                     'span': 'text:span',
                     'strike': 'text:span',
                     'strong': 'text:span',
                     'sub': 'text:span',
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
                           'ins': {'text:style-name': 'Underline'},
                           'ol': {'text:style-name': 'ListStructureNumeric',
                                  'text:continue-numbering': 'true'},
                           'p': {'text:style-name': '#'},
                           's': {'text:style-name': 'Strike'},
                           'span': {'text:style-name': '#class'},
                           'strike': {'text:style-name': 'Strike'},
                           'strong': {'text:style-name': 'Strong'},
                           'sub': {'text:style-name': 'Sub'},
                           'sup': {'text:style-name': 'Sup'},
                           'table': {'table:style-name': 'Table'},
                           'td': {'table:style-name': 'TableCell'},
                           'th': {'table:style-name': 'TableCellHeader'},
                           'u': {'text:style-name': 'Underline'},
                           'ul': {'text:style-name': 'ListStructure',
                                  'text:continue-numbering': 'true'}}
        self.extrasStart = {'a': ('', '<text:span text:style-name="Link">'),
                            'img': ('<draw:frame text:anchor-type="as-char" svg:width="{$w}" svg:height="{$h}" style:rel-width="scale" style:rel-height="scale">', '</draw:frame>'),
                            'td': ('', '<text:p>'),
                            'th': ('', '<text:p>')}
        self.extrasEnd = {'a': '</text:span>',
                          'td': '</text:p>',
                          'th': '</text:p>'}

        # Processing
        self.tag_path: List[str] = []
        self.table_descriptors: List[Dict[str, int]] = []
        self.blockquote_on = False
        self.blockcode_on = False
        self.has_code = False

    def _replace_marker(self, joker: str, content: str) -> None:
        odt = self.buffer.pop()
        pos = odt.rfind(joker)
        if pos != -1:
            self.buffer.override(odt[:pos] + str(content) + odt[pos + len(joker):])
        del odt

    def reset(self) -> None:
        super().reset()
        self.buffer.reset()

    def feed(self, data: str):
        # Find the unsupported tags
        unsupported = []
        for t in PwicConst.REGEXES['tag_name'].findall(data):
            t = t.lower()
            if (t not in self.maps) and (t not in unsupported):
                unsupported.append(t)

        # Recleansing
        cleaner = PwicCleanerHtml(' '.join(unsupported), False)
        cleaner.feed(data)
        super().feed(cleaner.get_html())

    def on_timeout(self):
        raise TimeoutError()

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.check_timeout()
        tag = tag.lower()

        # Rules
        lastTag = self.tag_path[-1] if len(self.tag_path) > 0 else ''
        # ... no imbricated paragraphs
        if tag == lastTag == 'p':
            return
        # ... list item should be enclosed by <p>
        if (tag != 'p') and (lastTag == 'li'):
            self.tag_path.append('p')
            self.buffer.push(f'<{self.maps["p"]}>')
        # ... subitems should close <p>
        elif (tag in ['ul', 'ol']) and (lastTag == 'p'):
            self.tag_path.pop()
            self.buffer.push(f'</{self.maps["p"]}>')
        del lastTag

        # Identify the new tag
        if tag not in PwicConst.VOID_HTML:
            self.tag_path.append(tag)
        if tag == 'blockquote':
            self.blockquote_on = True
        if tag == 'blockcode':
            self.blockcode_on = True
            self.has_code = True

        # Surrounding extra tags
        if tag not in self.maps:
            raise PwicError
        if self.maps[tag] is None:
            if (tag == 'input') and (PwicLib.read_attr(attrs, 'type') == 'checkbox'):
                self.buffer.push('\u2611' if PwicLib.read_attr_key(attrs, 'checked') else '\u2610')
            return
        if tag in self.extrasStart:
            self.buffer.push(self.extrasStart[tag][0])

        # Tag itself
        tag_img = {}
        self.buffer.push('<' + str(self.maps[tag]))
        if tag in self.attributes:
            for property_key in self.attributes[tag]:
                property_value = self.attributes[tag][property_key]
                if property_value[:1] != '#':
                    if property_key[:5] != 'dummy':
                        self.buffer.push(' %s="%s"' % (property_key, escape(property_value)))
                else:
                    property_value = property_value[1:]
                    if tag == 'p':
                        if self.blockquote_on:
                            self.buffer.push(' text:style-name="Blockquote"')
                            break
                    else:
                        for key, value_ns in attrs:
                            value = PwicLib.nns(value_ns)
                            if key == property_value:
                                # Fix the base URL for the links
                                if (tag == 'a') and (key == 'href'):
                                    if value[:1] in ['/']:
                                        value = self.base_url + str(value)
                                    elif value[:1] in ['?', '#', '.']:
                                        value = f'{self.base_url}/{self.project}/{self.page}{value}'
                                    elif value[:2] == './' or value[:3] == '../':
                                        value = f'{self.base_url}/{self.project}/{self.page}/{value}'

                                # Fix the attributes for the pictures
                                if tag == 'img':
                                    if key == 'alt':
                                        tag_img['alt'] = value
                                    elif key == 'title':
                                        tag_img['title'] = value
                                    elif key == 'src':
                                        if value[:1] == '/':
                                            value = value[1:]
                                        if self.pict is not None:
                                            docid_re = PwicConst.REGEXES['document_imgsrc'].match(value)
                                            if docid_re is not None:
                                                width = height = 0
                                                docid = PwicLib.intval(docid_re.group(1))
                                                if docid in self.pict:
                                                    if self.pict[docid]['remote'] or (self.pict[docid]['link'] == value):
                                                        value = self.pict[docid]['link_odt_img']
                                                    width = self.pict[docid]['width']
                                                    height = self.pict[docid]['height']
                                                if 0 in [width, height]:
                                                    width = height = PwicLib.intval(PwicConst.DEFAULTS['odt_img_defpix'])
                                                self._replace_marker('{$w}', PwicLib.convert_length(width, 'cm', 2))
                                                self._replace_marker('{$h}', PwicLib.convert_length(height, 'cm', 2))

                                # Fix the class name for the syntax highlight
                                if (tag == 'span') and self.blockcode_on and (key == 'class'):
                                    value = 'Code_' + value

                                if property_key[:5] != 'dummy':
                                    self.buffer.push(' %s="%s"' % (property_key, escape(value)))
                                break
        if tag in PwicConst.VOID_HTML:
            self.buffer.push('/')
        self.buffer.push('>')

        # Surrounding extra tags
        if tag == 'img':                    # Void tag
            if 'alt' in tag_img:
                self.buffer.push('<svg:title>%s</svg:title>' % escape(tag_img.get('alt', '')))
            if 'title' in tag_img:
                self.buffer.push('<svg:desc>%s</svg:desc>' % escape(tag_img.get('title', '')))
        if tag in self.extrasStart:
            self.buffer.push(self.extrasStart[tag][1])

        # Handle the column descriptors of the tables
        if tag == 'table':
            self.table_descriptors.append({'cursor': self.buffer.length(),
                                           'count': 0,
                                           'max': 0})
        if tag in ['th', 'td']:
            self.table_descriptors[-1]['count'] += 1

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()

        # Rules
        lastTag = self.tag_path[-1] if len(self.tag_path) > 0 else ''
        # ... no void tag
        if tag in PwicConst.VOID_HTML:
            return
        # ... no imbricated paragraphs
        if (tag == 'p') and (lastTag != 'p'):
            return
        # ... list item should be enclosed by <p>
        if (tag == 'li') and (lastTag == 'p'):
            self.tag_path.pop()
            self.buffer.push(f'</{self.maps["p"]}>')
        del lastTag

        # Identify the tag
        if self.tag_path[-1] != tag:
            raise PwicError
        self.tag_path.pop()

        # Surrounding extra tags
        if tag in self.extrasEnd:
            self.buffer.push(self.extrasEnd[tag])

        # Final mapping
        if tag in self.maps:
            if tag not in PwicConst.VOID_HTML:
                if tag == 'blockquote':
                    self.blockquote_on = False
                if tag == 'blockcode':
                    self.blockcode_on = False
                if self.maps[tag] is not None:
                    self.buffer.push(f'</{self.maps[tag]}>')

                    # Handle the descriptors of the tables
                    if tag == 'tr':
                        self.table_descriptors[-1]['max'] = max(self.table_descriptors[-1]['count'],
                                                                self.table_descriptors[-1]['max'])
                        self.table_descriptors[-1]['count'] = 0
                    if tag == 'table':
                        cursor = self.table_descriptors[-1]['cursor']
                        odt = self.buffer.pop()
                        self.buffer.override(odt[:cursor]
                                             + '<table:table-columns>'
                                             + ''.join(['<table:table-column/>' for _ in range(self.table_descriptors[-1]['max'])])
                                             + '</table:table-columns>'
                                             + odt[cursor:])
                        del odt
                        self.table_descriptors.pop()

    def handle_data(self, data: str) -> None:
        data = escape(data)
        # List item should be enclosed by <p>
        if (self.tag_path[-1] if len(self.tag_path) > 0 else '') == 'li':
            self.tag_path.append('p')
            self.buffer.push(f'<{self.maps["p"]}>')
        # Text alignment for the code
        if self.blockcode_on:
            data = data.replace('\r', '')
            data = data.replace('\n', '<text:line-break/>')
            data = data.replace('\t', '<text:tab/>')
            data = data.replace(' ', '<text:s/>')
        # Default behavior
        self.buffer.push(data)

    def handle_comment(self, data: str) -> None:
        # The ODT annotations must be surrounded by <text:p> or <text:list>
        # Sometimes md2html does not render <p> for block annotations
        # The missing tag is then added dynamically here
        missing = len(self.tag_path) == 0
        if missing:
            self.buffer.push('<text:p>')
        self.buffer.push('<office:annotation><dc:creator>Unknown</dc:creator><text:p>%s</text:p></office:annotation>' % escape(data))
        if missing:
            self.buffer.push('</text:p>')


class PwicStylerOdt:
    def __init__(self) -> None:
        self.manifest = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
    <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text" />
    <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml" />
    <manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml" />
    <manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml" />
    <!-- attachments -->
</manifest:manifest>'''

        self.meta = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
                      xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"
                      xmlns:dc="http://purl.org/dc/elements/1.1/"
                      xmlns:xlink="http://www.w3.org/1999/xlink"
                      office:version="1.2">
<office:meta>
    <meta:generator>Pwic.wiki version %s</meta:generator>
    <dc:title>%s</dc:title>
    <dc:subject>/%s/%s</dc:subject>
    %s
    <dc:creator>%s</dc:creator>
    <dc:date>%sT%sZ</dc:date>
    <meta:printed-by>%s</meta:printed-by>
    <meta:print-date>%sT%sZ</meta:print-date>
    <meta:editing-cycles>%d</meta:editing-cycles>
</office:meta>
</office:document-meta>'''

        self.styles_code = {'bp': '<style:style style:name="Code_bp" style:display-name="Code BP" style:family="text"><style:text-properties fo:color="#008000" /></style:style>',
                            'c': '<style:style style:name="Code_c" style:display-name="Code C" style:family="text"><style:text-properties fo:color="#008000" fo:font-style="italic" /></style:style>',
                            'c1': '<style:style style:name="Code_c1" style:display-name="Code C1" style:family="text"><style:text-properties fo:color="#008000" fo:font-style="italic" /></style:style>',
                            'ch': '<style:style style:name="Code_ch" style:display-name="Code CH" style:family="text"><style:text-properties fo:color="#808080" fo:font-style="italic" /></style:style>',
                            'cm': '<style:style style:name="Code_cm" style:display-name="Code CM" style:family="text"><style:text-properties fo:color="#008000" fo:font-style="italic" /></style:style>',
                            'cp': '<style:style style:name="Code_cp" style:display-name="Code CP" style:family="text"><style:text-properties fo:color="#BC7A00" fo:font-weight="bold" /></style:style>',
                            'cpf': '<style:style style:name="Code_cpf" style:display-name="Code CPF" style:family="text"><style:text-properties fo:color="#408080" /></style:style>',
                            'cs': '<style:style style:name="Code_cs" style:display-name="Code CS" style:family="text"><style:text-properties fo:color="#008000" fo:font-style="italic" /></style:style>',
                            'dl': '<style:style style:name="Code_dl" style:display-name="Code DL" style:family="text"><style:text-properties fo:color="#FF0000" /></style:style>',
                            'err': '<style:style style:name="Code_err" style:display-name="Code ERR" style:family="text"><style:text-properties fo:color="#FF0000" fo:background-color="#FFC0C0" /></style:style>',
                            'gd': '<style:style style:name="Code_gd" style:display-name="Code GD" style:family="text"><style:text-properties fo:color="#FF0000" /></style:style>',
                            'ge': '<style:style style:name="Code_ge" style:display-name="Code GE" style:family="text"><style:text-properties fo:font-style="italic" /></style:style>',
                            'gh': '<style:style style:name="Code_gh" style:display-name="Code GH" style:family="text"><style:text-properties fo:color="#4040FF" fo:font-weight="bold" /></style:style>',
                            'gi': '<style:style style:name="Code_gi" style:display-name="Code GI" style:family="text"><style:text-properties fo:color="#008000" /></style:style>',
                            'gp': '<style:style style:name="Code_gp" style:display-name="Code GP" style:family="text"><style:text-properties fo:color="#4040FF" fo:font-weight="bold" /></style:style>',
                            'gr': '<style:style style:name="Code_gr" style:display-name="Code GR" style:family="text"><style:text-properties fo:color="#FF0000" fo:background-color="#FFC0C0" /></style:style>',
                            'gs': '<style:style style:name="Code_gs" style:display-name="Code GS" style:family="text"><style:text-properties fo:font-weight="bold" /></style:style>',
                            'gu': '<style:style style:name="Code_gu" style:display-name="Code GU" style:family="text"><style:text-properties fo:background-color="#D3D3D3" fo:font-weight="bold" fo:font-style="italic" /></style:style>',
                            'hll': '<style:style style:name="Code_hll" style:display-name="Code HLL" style:family="text"><style:text-properties fo:background-color="#FFFFCC" /></style:style>',
                            'il': '<style:style style:name="Code_il" style:display-name="Code IL" style:family="text"><style:text-properties fo:color="#0000FF" /></style:style>',
                            'k': '<style:style style:name="Code_k" style:display-name="Code K" style:family="text"><style:text-properties fo:color="#800080" fo:font-weight="bold" /></style:style>',
                            'kc': '<style:style style:name="Code_kc" style:display-name="Code KC" style:family="text"><style:text-properties fo:color="#800080" fo:font-weight="bold" /></style:style>',
                            'kd': '<style:style style:name="Code_kd" style:display-name="Code KD" style:family="text"><style:text-properties fo:color="#800080" fo:font-weight="bold" /></style:style>',
                            'kn': '<style:style style:name="Code_kn" style:display-name="Code KN" style:family="text"><style:text-properties fo:color="#800080" fo:font-weight="bold" /></style:style>',
                            'kp': '<style:style style:name="Code_kp" style:display-name="Code KP" style:family="text"><style:text-properties fo:color="#800080" /></style:style>',
                            'kr': '<style:style style:name="Code_kr" style:display-name="Code KR" style:family="text"><style:text-properties fo:color="#800080" fo:font-weight="bold" /></style:style>',
                            'kt': '<style:style style:name="Code_kt" style:display-name="Code KT" style:family="text"><style:text-properties fo:color="#B00040" /></style:style>',
                            'l': '<style:style style:name="Code_l" style:display-name="Code L" style:family="text"><style:text-properties fo:color="#0000FF" /></style:style>',
                            'ld': '<style:style style:name="Code_ld" style:display-name="Code LD" style:family="text"><style:text-properties fo:color="#0000FF" /></style:style>',
                            'm': '<style:style style:name="Code_m" style:display-name="Code M" style:family="text"><style:text-properties fo:color="#0000FF" /></style:style>',
                            'mb': '<style:style style:name="Code_mb" style:display-name="Code MB" style:family="text"><style:text-properties fo:color="#0000FF" /></style:style>',
                            'mf': '<style:style style:name="Code_mf" style:display-name="Code MF" style:family="text"><style:text-properties fo:color="#0000FF" /></style:style>',
                            'mh': '<style:style style:name="Code_mh" style:display-name="Code MH" style:family="text"><style:text-properties fo:color="#0000FF" /></style:style>',
                            'mi': '<style:style style:name="Code_mi" style:display-name="Code MI" style:family="text"><style:text-properties fo:color="#0000FF" /></style:style>',
                            'mo': '<style:style style:name="Code_mo" style:display-name="Code MO" style:family="text"><style:text-properties fo:color="#0000FF" /></style:style>',
                            'na': '<style:style style:name="Code_na" style:display-name="Code NA" style:family="text"><style:text-properties fo:color="#008080" /></style:style>',
                            'nb': '<style:style style:name="Code_nb" style:display-name="Code NB" style:family="text"><style:text-properties fo:font-weight="bold" /></style:style>',
                            'nc': '<style:style style:name="Code_nc" style:display-name="Code NC" style:family="text"><style:text-properties fo:font-weight="bold" /></style:style>',
                            'nd': '<style:style style:name="Code_nd" style:display-name="Code ND" style:family="text"><style:text-properties fo:color="#AA22FF" /></style:style>',
                            'ne': '<style:style style:name="Code_ne" style:display-name="Code NE" style:family="text"><style:text-properties fo:font-weight="bold" /></style:style>',
                            'ni': '<style:style style:name="Code_ni" style:display-name="Code NI" style:family="text"><style:text-properties fo:color="#999999" fo:font-weight="bold" /></style:style>',
                            'nl': '<style:style style:name="Code_nl" style:display-name="Code NL" style:family="text"><style:text-properties fo:color="#BC7A00" /></style:style>',
                            'no': '<style:style style:name="Code_no" style:display-name="Code NO" style:family="text"><style:text-properties fo:color="#880000" /></style:style>',
                            'nt': '<style:style style:name="Code_nt" style:display-name="Code NT" style:family="text"><style:text-properties fo:color="#2080C0" fo:font-weight="bold" /></style:style>',
                            'nv': '<style:style style:name="Code_nv" style:display-name="Code NV" style:family="text"><style:text-properties fo:color="#2F4F4F" /></style:style>',
                            'ow': '<style:style style:name="Code_ow" style:display-name="Code OW" style:family="text"><style:text-properties fo:color="#800080" fo:font-weight="bold" /></style:style>',
                            's': '<style:style style:name="Code_s" style:display-name="Code S" style:family="text"><style:text-properties fo:color="#FF0000" /></style:style>',
                            's1': '<style:style style:name="Code_s1" style:display-name="Code S1" style:family="text"><style:text-properties fo:color="#FF0000" /></style:style>',
                            's2': '<style:style style:name="Code_s2" style:display-name="Code S2" style:family="text"><style:text-properties fo:color="#FF0000" /></style:style>',
                            'sa': '<style:style style:name="Code_sa" style:display-name="Code SA" style:family="text"><style:text-properties fo:color="#FF0000" /></style:style>',
                            'sb': '<style:style style:name="Code_sb" style:display-name="Code SB" style:family="text"><style:text-properties fo:color="#FF0000" /></style:style>',
                            'sc': '<style:style style:name="Code_sc" style:display-name="Code SC" style:family="text"><style:text-properties fo:color="#FF0000" /></style:style>',
                            'sd': '<style:style style:name="Code_sd" style:display-name="Code SD" style:family="text"><style:text-properties fo:color="#FF8000" /></style:style>',
                            'se': '<style:style style:name="Code_se" style:display-name="Code SE" style:family="text"><style:text-properties fo:color="#FF8000" fo:font-weight="bold" /></style:style>',
                            'sh': '<style:style style:name="Code_sh" style:display-name="Code SH" style:family="text"><style:text-properties fo:color="#FF0000" /></style:style>',
                            'si': '<style:style style:name="Code_si" style:display-name="Code SI" style:family="text"><style:text-properties fo:color="#FF0000" /></style:style>',
                            'sr': '<style:style style:name="Code_sr" style:display-name="Code SR" style:family="text"><style:text-properties fo:color="#800000" /></style:style>',
                            'ss': '<style:style style:name="Code_ss" style:display-name="Code SS" style:family="text"><style:text-properties fo:color="#FF0000" /></style:style>',
                            'sx': '<style:style style:name="Code_sx" style:display-name="Code SX" style:family="text"><style:text-properties fo:color="#FF0000" /></style:style>'}

        self.styles = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<office:document-styles xmlns:anim="urn:oasis:names:tc:opendocument:xmlns:animation:1.0"
                        xmlns:chart="urn:oasis:names:tc:opendocument:xmlns:chart:1.0"
                        xmlns:config="urn:oasis:names:tc:opendocument:xmlns:config:1.0"
                        xmlns:db="urn:oasis:names:tc:opendocument:xmlns:database:1.0"
                        xmlns:dc="http://purl.org/dc/elements/1.1/"
                        xmlns:dr3d="urn:oasis:names:tc:opendocument:xmlns:dr3d:1.0"
                        xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"
                        xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"
                        xmlns:form="urn:oasis:names:tc:opendocument:xmlns:form:1.0"
                        xmlns:grddl="http://www.w3.org/2003/g/data-view#"
                        xmlns:math="http://www.w3.org/1998/Math/MathML"
                        xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"
                        xmlns:number="urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0"
                        xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
                        xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0"
                        xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0"
                        xmlns:smil="urn:oasis:names:tc:opendocument:xmlns:smil-compatible:1.0"
                        xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"
                        xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
                        xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"
                        xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
                        xmlns:xforms="http://www.w3.org/2002/xforms"
                        xmlns:xhtml="http://www.w3.org/1999/xhtml"
                        xmlns:xlink="http://www.w3.org/1999/xlink"
                        office:version="1.2">
    <office:font-face-decls>
        <style:font-face style:name="Courier New"
                         style:font-family-generic="system"
                         style:font-pitch="fixed" />
    </office:font-face-decls>
    <office:styles>
        <style:style style:name="Standard"
                     style:family="paragraph"
                     style:class="text"
                     style:parent-style-name="Normal" />
        <style:style style:name="Normal"
                     style:display-name="Normal"
                     style:family="paragraph">
            <style:paragraph-properties fo:margin-top="3pt"
                                        fo:margin-bottom="3pt" />
            <style:text-properties fo:font-size="12pt" />
        </style:style>
        <style:default-style style:family="table-column">
            <style:table-column-properties style:use-optimal-column-width="false" />
        </style:default-style>
        <style:default-style style:family="table-row">
            <style:table-row-properties style:use-optimal-row-height="true" />
        </style:default-style>
        <style:default-style style:family="table-cell">
            <style:table-cell-properties style:vertical-align="middle"
                                         fo:background-color="transparent"
                                         fo:wrap-option="wrap" />
        </style:default-style>

        <style:style style:name="Heading"
                     style:family="paragraph"
                     style:class="text"
                     style:parent-style-name="Normal">
            <style:paragraph-properties fo:keep-with-next="always" />
        </style:style>
        <style:style style:name="H1"
                     style:display-name="Heading 1"
                     style:family="paragraph"
                     style:parent-style-name="Heading"
                     style:next-style-name="Normal"
                     style:default-outline-level="1">
            <style:paragraph-properties fo:margin-top="12pt"
                                        fo:margin-bottom="6pt" />
            <style:text-properties fo:font-size="18pt"
                                   fo:font-weight="bold" />
        </style:style>
        <style:style style:name="H2"
                     style:display-name="Heading 2"
                     style:family="paragraph"
                     style:parent-style-name="Heading"
                     style:next-style-name="Normal"
                     style:default-outline-level="2">
            <style:paragraph-properties fo:margin-top="9pt"
                                        fo:margin-bottom="6pt" />
            <style:text-properties fo:font-size="16pt"
                                   fo:font-weight="bold" />
        </style:style>
        <style:style style:name="H3"
                     style:display-name="Heading 3"
                     style:family="paragraph"
                     style:parent-style-name="Heading"
                     style:next-style-name="Normal"
                     style:default-outline-level="3">
            <style:paragraph-properties fo:margin-top="6pt"
                                        fo:margin-bottom="6pt" />
            <style:text-properties fo:font-size="14pt"
                                   fo:font-weight="bold" />
        </style:style>
        <style:style style:name="H4"
                     style:display-name="Heading 4"
                     style:family="paragraph"
                     style:parent-style-name="Heading"
                     style:next-style-name="Normal"
                     style:default-outline-level="4">
            <style:paragraph-properties fo:margin-top="6pt"
                                        fo:margin-bottom="6pt" />
            <style:text-properties fo:font-size="13pt"
                                   fo:font-weight="bold" />
        </style:style>
        <style:style style:name="H5"
                     style:display-name="Heading 5"
                     style:family="paragraph"
                     style:parent-style-name="Heading"
                     style:next-style-name="Normal"
                     style:default-outline-level="5">
            <style:paragraph-properties fo:margin-top="6pt"
                                        fo:margin-bottom="6pt" />
            <style:text-properties fo:font-size="12pt"
                                   fo:font-weight="bold" />
        </style:style>
        <style:style style:name="H6"
                     style:display-name="Heading 6"
                     style:family="paragraph"
                     style:parent-style-name="Heading"
                     style:next-style-name="Normal"
                     style:default-outline-level="6">
            <style:paragraph-properties fo:margin-top="6pt"
                                        fo:margin-bottom="6pt" />
            <style:text-properties fo:font-size="12pt"
                                   fo:font-weight="bold" />
        </style:style>

        <style:style style:name="Blockquote"
                     style:display-name="Quote"
                     style:family="paragraph"
                     style:parent-style-name="Normal">
            <style:paragraph-properties fo:border-left="5px solid #bfbfbf"
                                        fo:background-color="#f2f2f2"
                                        fo:padding="0.05in"
                                        fo:margin-left="0.4in" />
        </style:style>
        <style:style style:name="Code"
                     style:display-name="Code"
                     style:family="text">
            <style:text-properties style:font-name="Courier New"
                                   fo:font-size="10pt" />
        </style:style>
        <style:style style:name="CodeBlock"
                     style:display-name="Code Block"
                     style:family="paragraph"
                     style:parent-style-name="Normal">
            <style:paragraph-properties fo:border="1px solid #000000"
                                        fo:padding="1mm"
                                        fo:keep-together="always" />
            <style:text-properties style:font-name="Courier New"
                                   fo:font-size="10pt" />
        </style:style>
        <style:style style:name="Error"
                     style:display-name="Error"
                     style:family="text">
            <style:text-properties fo:color="#FF0000" />
        </style:style>
        <style:style style:name="Footer"
                     style:display-name="Footer"
                     style:family="paragraph">
            <style:paragraph-properties fo:text-align="center" />
            <style:text-properties fo:font-size="9pt"
                                   fo:font-style="italic"
                                   fo:color="#808080" />
        </style:style>
        <style:style style:name="HR"
                     style:display-name="Horizontal line"
                     style:family="paragraph"
                     style:parent-style-name="Normal">
            <style:paragraph-properties fo:border-bottom="0.0104in solid #000000"
                                        fo:padding-bottom="0.0138in" />
        </style:style>
        <style:style style:name="Italic"
                     style:display-name="Italic"
                     style:family="text">
            <style:text-properties fo:font-style="italic" />
        </style:style>
        <style:style style:name="Link"
                     style:display-name="Hyperlink"
                     style:family="text">
            <style:text-properties fo:color="#0000FF"
                                   style:text-underline-type="single"
                                   style:text-underline-style="solid"
                                   style:text-underline-width="auto"
                                   style:text-underline-mode="continuous" />
        </style:style>
        <style:style style:name="Strike"
                     style:display-name="Strike"
                     style:family="text">
            <style:text-properties style:text-line-through-style="solid"
                                   style:text-line-through-width="auto"
                                   style:text-line-through-color="font-color"
                                   style:text-line-through-mode="continuous"
                                   style:text-line-through-type="single" />
        </style:style>
        <style:style style:name="Strong"
                     style:display-name="Strong"
                     style:family="text">
            <style:text-properties fo:font-weight="bold" />
        </style:style>
        <style:style style:name="Sub"
                     style:display-name="Subscript"
                     style:family="text">
            <style:text-properties style:text-position="sub 66%" />
        </style:style>
        <style:style style:name="Sup"
                     style:display-name="Superscript"
                     style:family="text">
            <style:text-properties style:text-position="super 66%" />
        </style:style>
        <style:style style:name="Table"
                     style:display-name="Table"
                     style:family="table">
            <style:table-properties table:border-model="collapsing"
                                    style:rel-width="100%"
                                    table:align="center" />
        </style:style>
        <style:style style:name="TableCell"
                     style:display-name="Table Cell"
                     style:family="table-cell">
            <style:table-cell-properties fo:padding-top="0in"
                                         fo:padding-left="0.075in"
                                         fo:padding-bottom="0in"
                                         fo:padding-right="0.075in"
                                         fo:border="1px solid #000000" />
        </style:style>
        <style:style style:name="TableCellHeader"
                     style:display-name="Table Cell Header"
                     style:family="table-cell"
                     style:parent-style-name="TableCell">
            <style:table-cell-properties fo:background-color="#f0f0f0" />
            <style:text-properties fo:font-weight="bold" />
        </style:style>
        <style:style style:name="Underline"
                     style:display-name="Underline"
                     style:family="text"
                     style:parent-style-name="Normal">
            <style:text-properties style:text-underline-color="font-color"
                                   style:text-underline-style="solid"
                                   style:text-underline-mode="continuous"
                                   style:text-underline-type="single"
                                   style:text-underline-width="auto" />
        </style:style>

        <!-- styles-code -->

        <text:outline-style style:name="TitleStructure">
            <!-- styles-heading-format -->
        </text:outline-style>

        <text:list-style style:name="ListStructure"
                         style:display-name="List structure">
            <text:list-level-style-bullet text:level="1"
                                          text:bullet-char="&#x2022;">
                <style:list-level-properties text:space-before="0.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="0.5in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="2"
                                          text:bullet-char="o">
                <style:list-level-properties text:space-before="0.75in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="1in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="3"
                                          text:bullet-char="&#x25AA;">
                <style:list-level-properties text:space-before="1.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="1.5in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="4"
                                          text:bullet-char="&#x2023;">
                <style:list-level-properties text:space-before="1.75in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="2in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="5"
                                          text:bullet-char="-">
                <style:list-level-properties text:space-before="2.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="2.5in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="6"
                                          text:bullet-char="&#x2022;">
                <style:list-level-properties text:space-before="2.75in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="3in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="7"
                                          text:bullet-char="o">
                <style:list-level-properties text:space-before="3.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="3.5in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="8"
                                          text:bullet-char="&#x25AA;">
                <style:list-level-properties text:space-before="3.75in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="4in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="9"
                                          text:bullet-char="&#x2023;">
                <style:list-level-properties text:space-before="4.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="4.5in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-bullet>
        </text:list-style>
        <text:list-style style:name="ListStructureNumeric">
            <text:list-level-style-number text:level="1"
                                          style:num-suffix="."
                                          style:num-format="1">
                <style:list-level-properties text:space-before="0.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="0.5in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-number>
            <text:list-level-style-number text:level="2"
                                          style:num-suffix="."
                                          style:num-format="a"
                                          style:num-letter-sync="true">
                <style:list-level-properties text:space-before="0.75in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="1in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-number>
            <text:list-level-style-number text:level="3"
                                          style:num-suffix="."
                                          style:num-format="i">
                <style:list-level-properties fo:text-align="end"
                                             text:space-before="1.375in"
                                             text:min-label-width="0.125in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="1.5in"
                                                      fo:text-indent="-0.125in" />
                </style:list-level-properties>
            </text:list-level-style-number>
            <text:list-level-style-number text:level="4"
                                          style:num-suffix="."
                                          style:num-format="1">
                <style:list-level-properties text:space-before="1.75in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="2in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-number>
            <text:list-level-style-number text:level="5"
                                          style:num-suffix="."
                                          style:num-format="a"
                                          style:num-letter-sync="true">
                <style:list-level-properties text:space-before="2.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="2.5in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-number>
            <text:list-level-style-number text:level="6"
                                          style:num-suffix="."
                                          style:num-format="i">
                <style:list-level-properties fo:text-align="end"
                                             text:space-before="2.875in"
                                             text:min-label-width="0.125in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="3in"
                                                      fo:text-indent="-0.125in" />
                </style:list-level-properties>
            </text:list-level-style-number>
            <text:list-level-style-number text:level="7"
                                          style:num-suffix="."
                                          style:num-format="1">
                <style:list-level-properties text:space-before="3.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="3.5in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-number>
            <text:list-level-style-number text:level="8" style:num-suffix="."
                                                         style:num-format="a"
                                                         style:num-letter-sync="true">
                <style:list-level-properties text:space-before="3.75in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="4in"
                                                      fo:text-indent="-0.25in" />
                </style:list-level-properties>
            </text:list-level-style-number>
            <text:list-level-style-number text:level="9"
                                          style:num-suffix="."
                                          style:num-format="i">
                <style:list-level-properties fo:text-align="end"
                                             text:space-before="4.375in"
                                             text:min-label-width="0.125in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="4.5in"
                                                      fo:text-indent="-0.125in" />
                </style:list-level-properties>
            </text:list-level-style-number>
        </text:list-style>
    </office:styles>
    <office:automatic-styles>
        <style:page-layout style:name="DocumentPage">
            <style:page-layout-properties fo:page-width="{$pw}"
                                          fo:page-height="{$ph}"
                                          style:print-orientation="{$po}"
                                          fo:margin-top="{$pm}"
                                          fo:margin-left="{$pm}"
                                          fo:margin-bottom="{$pm}"
                                          fo:margin-right="{$pm}"
                                          style:num-format="1">
                <style:footnote-sep style:width="0.007in"
                                    style:rel-width="33%"
                                    style:color="#000000"
                                    style:line-style="solid"
                                    style:adjustment="left" />
            </style:page-layout-properties>
        </style:page-layout>
    </office:automatic-styles>
    <office:master-styles>
        <style:master-page style:name="Standard"
                           style:page-layout-name="DocumentPage">
            <style:footer>
                <!-- styles-footer -->
            </style:footer>
        </style:master-page>
    </office:master-styles>
</office:document-styles>'''

        self.content = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<office:document-content xmlns:anim="urn:oasis:names:tc:opendocument:xmlns:animation:1.0"
                         xmlns:chart="urn:oasis:names:tc:opendocument:xmlns:chart:1.0"
                         xmlns:config="urn:oasis:names:tc:opendocument:xmlns:config:1.0"
                         xmlns:db="urn:oasis:names:tc:opendocument:xmlns:database:1.0"
                         xmlns:dc="http://purl.org/dc/elements/1.1/"
                         xmlns:dr3d="urn:oasis:names:tc:opendocument:xmlns:dr3d:1.0"
                         xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"
                         xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"
                         xmlns:form="urn:oasis:names:tc:opendocument:xmlns:form:1.0"
                         xmlns:grddl="http://www.w3.org/2003/g/data-view#"
                         xmlns:math="http://www.w3.org/1998/Math/MathML"
                         xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"
                         xmlns:number="urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0"
                         xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
                         xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0"
                         xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0"
                         xmlns:smil="urn:oasis:names:tc:opendocument:xmlns:smil-compatible:1.0"
                         xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0"
                         xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0"
                         xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"
                         xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
                         xmlns:xforms="http://www.w3.org/2002/xforms"
                         xmlns:xhtml="http://www.w3.org/1999/xhtml"
                         xmlns:xlink="http://www.w3.org/1999/xlink"
                         office:version="1.2">
    <office:body>
        <office:text>
            <!-- content-url -->
            <!-- content-page -->
        </office:text>
    </office:body>
</office:document-content>'''

    def getOptimizedCodeStyles(self, code: str) -> str:
        output = ''
        for k in self.styles_code:
            if '<span class="%s">' % k in code:
                output += self.styles_code[k] + '\n'
        return output

    def getHeadingStyles(self, mask: Optional[str]) -> str:
        # Complete the mask
        if mask is None:
            mask = ''
        a = len(mask)
        b = len(PwicConst.DEFAULTS['heading'])
        if a < b:
            mask += PwicConst.DEFAULTS['heading'][a - b:]

        # Build the XML section
        template = '''<text:outline-level-style text:level="%d"
                                                text:display-levels="%d"
                                                style:num-format="%s"
                                                style:num-suffix="%s"
                                                text:style-name="H%d">
                        <style:list-level-properties text:list-level-position-and-space-mode="label-alignment">
                            <style:list-level-label-alignment text:label-followed-by="listtab"
                                                              fo:margin-left="%dcm" />
                        </style:list-level-properties>
                    </text:outline-level-style>\n'''
        buffer = ''
        for i in range(6):
            buffer += template % (i + 1,
                                  i + 1,
                                  mask[2 * i].strip().replace('"', '\\"'),
                                  mask[2 * i + 1].strip().replace('"', '\\"'),
                                  i + 1,
                                  i)
        return buffer
