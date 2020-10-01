
# ===============================
#  Helper for the export to HTML
# ===============================

class pwic_styles_html:
    def __init__(self):
        self.mime = 'text/html'
        self.css = 'static/styles.css'
        self.html = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="author" content="%s">
    <meta name="last-modified" content="%s %s">
    <title>%s %s</title>
    %s
</head>
<body>
    <article>%s</article>
</body>
</html>'''

    def getCss(self, rel):
        if rel:
            return '<link rel="stylesheet" type="text/css" href="%s" />' % self.css
        else:
            content = ''
            with open(self.css, 'r') as f:
                content = f.read()
            return '<style>%s</style>' % content


# =======================================
#  Helper for the export to OpenDocument
# =======================================

class pwic_styles_odt:
    def __init__(self):
        self.mime = 'application/vnd.oasis.opendocument.text'

        self.manifest = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
    <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>
    <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
    <manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"/>
    <manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/>
</manifest:manifest>'''

        self.meta = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
                      xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"
                      xmlns:dc="http://purl.org/dc/elements/1.1/"
                      xmlns:xlink="http://www.w3.org/1999/xlink"
                      office:version="1.2">
<office:meta>
    <meta:generator>Pwic version %s</meta:generator>
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

        # Warning: column position matters
        self.styles_code = ['<style:style style:name="Code_hll" style:display-name="Code HLL" style:family="text" style:parent-style-name="Normal"><style:text-properties fo:background-color="#ffffcc"/></style:style>',
                            '<style:style style:name="Code_c"   style:display-name="Code C"   style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#888888"/></style:style>',
                            '<style:style style:name="Code_err" style:display-name="Code ERR" style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#a61717" fo:background-color="#e3d2d2"/></style:style>',
                            '<style:style style:name="Code_k"   style:display-name="Code K"   style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#008800" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_ch"  style:display-name="Code CH"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#888888"/></style:style>',
                            '<style:style style:name="Code_cm"  style:display-name="Code CM"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#888888"/></style:style>',
                            '<style:style style:name="Code_cp"  style:display-name="Code CP"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#cc0000" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_cpf" style:display-name="Code CPF" style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#888888"/></style:style>',
                            '<style:style style:name="Code_c1"  style:display-name="Code C1"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#888888"/></style:style>',
                            '<style:style style:name="Code_cs"  style:display-name="Code CS"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#cc0000" fo:font-weight="bold" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_gd"  style:display-name="Code GD"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#000000" fo:background-color="#ffdddd"/></style:style>',
                            '<style:style style:name="Code_ge"  style:display-name="Code GE"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:font-style="italic"/></style:style>',
                            '<style:style style:name="Code_gr"  style:display-name="Code GR"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#aa0000"/></style:style>',
                            '<style:style style:name="Code_gh"  style:display-name="Code GH"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#333333"/></style:style>',
                            '<style:style style:name="Code_gi"  style:display-name="Code GI"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#000000" fo:background-color="#ddffdd"/></style:style>',
                            '<style:style style:name="Code_go"  style:display-name="Code GO"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#888888"/></style:style>',
                            '<style:style style:name="Code_gp"  style:display-name="Code GP"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#555555"/></style:style>',
                            '<style:style style:name="Code_gs"  style:display-name="Code GS"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_gu"  style:display-name="Code GU"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#666666"/></style:style>',
                            '<style:style style:name="Code_gt"  style:display-name="Code GT"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#aa0000"/></style:style>',
                            '<style:style style:name="Code_kc"  style:display-name="Code KC"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#008800" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_kd"  style:display-name="Code KD"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#008800" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_kn"  style:display-name="Code KN"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#008800" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_kp"  style:display-name="Code KP"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#008800"/></style:style>',
                            '<style:style style:name="Code_kr"  style:display-name="Code KR"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#008800" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_kt"  style:display-name="Code KT"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#888888" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_m"   style:display-name="Code M"   style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#0000dd" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_s"   style:display-name="Code S"   style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#dd2200" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_na"  style:display-name="Code NA"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#336699"/></style:style>',
                            '<style:style style:name="Code_nb"  style:display-name="Code NB"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#003388"/></style:style>',
                            '<style:style style:name="Code_nc"  style:display-name="Code NC"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#bb0066" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_no"  style:display-name="Code NO"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#003366" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_nd"  style:display-name="Code ND"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#555555"/></style:style>',
                            '<style:style style:name="Code_ne"  style:display-name="Code NE"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#bb0066" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_nf"  style:display-name="Code NF"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#0066bb" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_nl"  style:display-name="Code NL"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#336699" fo:font-style="italic"/></style:style>',
                            '<style:style style:name="Code_nn"  style:display-name="Code NN"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#bb0066" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_py"  style:display-name="Code PY"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#336699" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_nt"  style:display-name="Code NT"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#bb0066" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_nv"  style:display-name="Code NV"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#336699"/></style:style>',
                            '<style:style style:name="Code_ow"  style:display-name="Code OW"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#008800"/></style:style>',
                            '<style:style style:name="Code_w"   style:display-name="Code W"   style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#bbbbbb"/></style:style>',
                            '<style:style style:name="Code_mb"  style:display-name="Code MB"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#0000dd" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_mf"  style:display-name="Code MF"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#0000dd" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_mh"  style:display-name="Code MH"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#0000dd" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_mi"  style:display-name="Code MI"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#0000dd" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_mo"  style:display-name="Code MO"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#0000dd" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_sa"  style:display-name="Code SA"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#dd2200" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_sb"  style:display-name="Code SB"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#dd2200" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_sc"  style:display-name="Code SC"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#dd2200" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_dl"  style:display-name="Code DL"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#dd2200" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_sd"  style:display-name="Code SD"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#dd2200" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_s2"  style:display-name="Code S2"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#dd2200" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_se"  style:display-name="Code SE"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#0044dd" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_sh"  style:display-name="Code SH"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#dd2200" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_si"  style:display-name="Code SI"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#3333bb" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_sx"  style:display-name="Code SX"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#22bb22" fo:background-color="#f0fff0"/></style:style>',
                            '<style:style style:name="Code_sr"  style:display-name="Code SR"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#008800" fo:background-color="#fff0ff"/></style:style>',
                            '<style:style style:name="Code_s1"  style:display-name="Code S1"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#dd2200" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_ss"  style:display-name="Code SS"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#aa6600" fo:background-color="#fff0f0"/></style:style>',
                            '<style:style style:name="Code_bp"  style:display-name="Code BP"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#003388"/></style:style>',
                            '<style:style style:name="Code_fm"  style:display-name="Code FM"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#0066bb" fo:font-weight="bold"/></style:style>',
                            '<style:style style:name="Code_vc"  style:display-name="Code VC"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#336699"/></style:style>',
                            '<style:style style:name="Code_vg"  style:display-name="Code VG"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#dd7700"/></style:style>',
                            '<style:style style:name="Code_vi"  style:display-name="Code VI"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#3333bb"/></style:style>',
                            '<style:style style:name="Code_vm"  style:display-name="Code VM"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#336699"/></style:style>',
                            '<style:style style:name="Code_il"  style:display-name="Code IL"  style:family="text" style:parent-style-name="Normal"><style:text-properties fo:color="#0000dd" fo:font-weight="bold"/></style:style>']

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
                         style:font-pitch="fixed"/>
    </office:font-face-decls>
    <office:styles>
        <style:style style:name="Normal"
                     style:display-name="Normal"
                     style:family="paragraph"
                     style:master-page-name="MasterDocumentPage">
            <style:paragraph-properties fo:margin-top="3pt"
                                        fo:margin-bottom="3pt"/>
            <style:text-properties fo:font-size="12pt"/>
        </style:style>
        <style:default-style style:family="table-column">
            <style:table-column-properties style:use-optimal-column-width="false"/>
        </style:default-style>
        <style:default-style style:family="table-row">
            <style:table-row-properties style:use-optimal-row-height="true" />
        </style:default-style>
        <style:default-style style:family="table-cell">
            <style:table-cell-properties style:vertical-align="middle"
                                         fo:background-color="transparent"
                                         fo:wrap-option="wrap"/>
        </style:default-style>

        <style:style style:name="H1"
                     style:display-name="Heading 1"
                     style:family="paragraph"
                     style:parent-style-name="Normal"
                     style:next-style-name="Normal"
                     style:default-outline-level="1">
            <style:paragraph-properties fo:break-before="page"
                                        fo:margin-top="12pt"
                                        fo:margin-bottom="6pt"
                                        fo:margin-left="0cm"/>
            <style:text-properties fo:font-size="24pt"
                                   fo:font-weight="bold"/>
        </style:style>
        <style:style style:name="H2"
                     style:display-name="Heading 2"
                     style:family="paragraph"
                     style:parent-style-name="Normal"
                     style:next-style-name="Normal"
                     style:default-outline-level="2">
            <style:paragraph-properties fo:margin-top="9pt"
                                        fo:margin-bottom="6pt"
                                        fo:margin-left="1cm"/>
            <style:text-properties fo:font-size="20pt"
                                   fo:font-weight="bold"/>
        </style:style>
        <style:style style:name="H3"
                     style:display-name="Heading 3"
                     style:family="paragraph"
                     style:parent-style-name="Normal"
                     style:next-style-name="Normal"
                     style:default-outline-level="3">
            <style:paragraph-properties fo:margin-top="6pt"
                                        fo:margin-bottom="6pt"
                                        fo:margin-left="2cm"/>
            <style:text-properties fo:font-size="16pt"
                                   fo:font-weight="bold"/>
        </style:style>
        <style:style style:name="H4"
                     style:display-name="Heading 4"
                     style:family="paragraph"
                     style:parent-style-name="Normal"
                     style:next-style-name="Normal"
                     style:default-outline-level="4">
            <style:paragraph-properties fo:margin-top="6pt"
                                        fo:margin-bottom="6pt"
                                        fo:margin-left="3cm"/>
            <style:text-properties fo:font-size="12pt"
                                   fo:font-weight="bold"/>
        </style:style>
        <style:style style:name="H5"
                     style:display-name="Heading 5"
                     style:family="paragraph"
                     style:parent-style-name="Normal"
                     style:next-style-name="Normal"
                     style:default-outline-level="5">
            <style:paragraph-properties fo:margin-top="6pt"
                                        fo:margin-bottom="6pt"
                                        fo:margin-left="4cm"/>
            <style:text-properties fo:font-size="12pt"
                                   fo:font-weight="bold"/>
        </style:style>
        <style:style style:name="H6"
                     style:display-name="Heading 6"
                     style:family="paragraph"
                     style:parent-style-name="Normal"
                     style:next-style-name="Normal"
                     style:default-outline-level="6">
            <style:paragraph-properties fo:margin-top="6pt"
                                        fo:margin-bottom="6pt"
                                        fo:margin-left="5cm"/>
            <style:text-properties fo:font-size="12pt"
                                   fo:font-weight="bold"/>
        </style:style>

        <style:style style:name="Bold"
                     style:display-name="Bold"
                     style:family="text"
                     style:parent-style-name="Normal">
            <style:text-properties fo:font-weight="bold"/>
        </style:style>
        <style:style style:name="Blockquote"
                     style:display-name="Quote"
                     style:family="paragraph"
                     style:parent-style-name="Normal">
            <style:paragraph-properties fo:border-left="5px solid #bfbfbf"
                                        fo:background-color="#f2f2f2"
                                        fo:padding-left="0.05in"
                                        fo:margin-left="0.4in"/>
        </style:style>
        <style:style style:name="Code"
                     style:display-name="Code"
                     style:family="text"
                     style:parent-style-name="Normal">
            <style:text-properties style:font-name="Courier New"
                                   fo:font-size="10pt"/>
        </style:style>
        <style:style style:name="CodeBlock"
                     style:display-name="Code Block"
                     style:family="paragraph"
                     style:parent-style-name="Normal">
            <style:paragraph-properties fo:border="1px solid #000000"
                                        fo:padding="1mm"/>
            <style:text-properties style:font-name="Courier New"
                                   fo:font-size="10pt"/>
        </style:style>
        <style:style style:name="Error"
                     style:display-name="Error"
                     style:family="text"
                     style:parent-style-name="Normal">
            <style:text-properties fo:color="#FF0000"/>
        </style:style>
        <style:style style:name="HR"
                     style:display-name="Horizontal line"
                     style:family="paragraph"
                     style:parent-style-name="Normal">
            <style:paragraph-properties fo:border-bottom="0.0104in solid #000000"
                                        fo:padding-bottom="0.0138in" />
        </style:style>
        <style:style style:name="Inf"
                     style:display-name="Inferior"
                     style:family="text"
                     style:parent-style-name="Normal">
            <style:text-properties style:text-position="sub 66%"/>
        </style:style>
        <style:style style:name="Italic"
                     style:display-name="Italic"
                     style:family="text"
                     style:parent-style-name="Normal">
            <style:text-properties fo:font-style="italic"/>
        </style:style>
        <style:style style:name="Link"
                     style:display-name="Hyperlink"
                     style:family="text"
                     style:parent-style-name="Normal">
            <style:text-properties fo:color="#0000FF"
                                   style:text-underline-type="single"
                                   style:text-underline-style="solid"
                                   style:text-underline-width="auto"
                                   style:text-underline-mode="continuous"/>
        </style:style>
        <style:style style:name="Strike"
                     style:display-name="Strike"
                     style:family="text"
                     style:parent-style-name="Normal">
            <style:text-properties style:text-line-through-style="solid"
                                   style:text-line-through-width="auto"
                                   style:text-line-through-color="font-color"
                                   style:text-line-through-mode="continuous"
                                   style:text-line-through-type="single"/>
        </style:style>
        <style:style style:name="Sup"
                     style:display-name="Superior"
                     style:family="text"
                     style:parent-style-name="Normal">
            <style:text-properties style:text-position="super 66%"/>
        </style:style>
        <style:style style:name="Table"
                     style:display-name="Table"
                     style:family="table">
            <style:table-properties table:border-model="collapsing"
                                    table:align="center"/>
        </style:style>
        <style:style style:name="TableCell"
                     style:display-name="Table Cell"
                     style:family="table-cell">
            <style:table-cell-properties fo:padding-top="0in"
                                         fo:padding-left="0.075in"
                                         fo:padding-bottom="0in"
                                         fo:padding-right="0.075in"
                                         fo:border="1px solid #000000"/>
        </style:style>

        ##

        <text:list-style style:name="ListStructure"
                         style:display-name="List structure">
            <text:list-level-style-bullet text:level="1"
                                          text:bullet-char="&#x2022;">
                <style:list-level-properties text:space-before="0.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="0.5in"
                                                      fo:text-indent="-0.25in"/>
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="2"
                                          text:bullet-char="o">
                <style:list-level-properties text:space-before="0.75in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="1in"
                                                      fo:text-indent="-0.25in"/>
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="3"
                                          text:bullet-char="&#x25AA;">
                <style:list-level-properties text:space-before="1.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="1.5in"
                                                      fo:text-indent="-0.25in"/>
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="4"
                                          text:bullet-char="&#x2023;">
                <style:list-level-properties text:space-before="1.75in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="2in"
                                                      fo:text-indent="-0.25in"/>
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="5"
                                          text:bullet-char="-">
                <style:list-level-properties text:space-before="2.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="2.5in"
                                                      fo:text-indent="-0.25in"/>
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="6"
                                          text:bullet-char="&#x2022;">
                <style:list-level-properties text:space-before="2.75in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="3in"
                                                      fo:text-indent="-0.25in"/>
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="7"
                                          text:bullet-char="o">
                <style:list-level-properties text:space-before="3.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="3.5in"
                                                      fo:text-indent="-0.25in"/>
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="8"
                                          text:bullet-char="&#x25AA;">
                <style:list-level-properties text:space-before="3.75in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="4in"
                                                      fo:text-indent="-0.25in"/>
                </style:list-level-properties>
            </text:list-level-style-bullet>
            <text:list-level-style-bullet text:level="9"
                                          text:bullet-char="&#x2023;">
                <style:list-level-properties text:space-before="4.25in"
                                             text:min-label-width="0.25in"
                                             text:list-level-position-and-space-mode="label-alignment">
                    <style:list-level-label-alignment text:label-followed-by="listtab"
                                                      fo:margin-left="4.5in"
                                                      fo:text-indent="-0.25in"/>
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
                                                      fo:text-indent="-0.25in"/>
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
                                                      fo:text-indent="-0.25in"/>
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
                                                      fo:text-indent="-0.125in"/>
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
                                                      fo:text-indent="-0.25in"/>
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
                                                      fo:text-indent="-0.25in"/>
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
                                                      fo:text-indent="-0.125in"/>
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
                                                      fo:text-indent="-0.25in"/>
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
                                                      fo:text-indent="-0.25in"/>
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
                                                      fo:text-indent="-0.125in"/>
                </style:list-level-properties>
            </text:list-level-style-number>
        </text:list-style>
    </office:styles>
    <office:automatic-styles>
        <style:page-layout style:name="DocumentPage">
            <style:page-layout-properties fo:page-width="21cm"
                                          fo:page-height="29.7cm"
                                          fo:margin-top="1in"
                                          fo:margin-left="1in"
                                          fo:margin-bottom="1in"
                                          fo:margin-right="1in"
                                          style:num-format="1">
            </style:page-layout-properties>
        </style:page-layout>
    </office:automatic-styles>
    <office:master-styles>
        <style:master-page style:name="MasterDocumentPage"
                           style:page-layout-name="DocumentPage"/>
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
            %s
        </office:text>
    </office:body>
</office:document-content>'''

    def getOptimizedCodeStyles(self, code):
        output = ''
        for line in self.styles_code:
            ref = '<span class="%s">' % (line[30:34].replace('"', '').strip())
            if ref in code:
                output += line + '\n'
        return output
