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

from typing import Any, Dict, List, Optional, Tuple
import sqlite3
from datetime import tzinfo
from multidict import MultiDict
from aiohttp import web

from pwic_lib import PwicConst


class PwicExtension():
    ''' Extensions for Pwic.wiki

        The behavior of Pwic.wiki is changeable in this file through a logic of events
        positioned at critical positions in the code base. It is easier and safer to
        implement some changes here but it remains technically sensible.

        Each method is always active and generally returns from 0 to 2 results.
        The first one usually tells if something happened. The second one provides
        the new result. With no result, the parameters of the method are changeable
        if they are passed as a reference, else raise an exception.
    '''

    # ============
    #  User exits
    # ============

    @staticmethod
    def on_api_document_convert(sql: sqlite3.Cursor,                    # Cursor to query the database
                                project: str,                           # Name of the project
                                user: str,                              # Name of the user
                                page: str,                              # Name of the page
                                doc_id: int,                            # Identifier of the document
                                markdown: str,                          # Converted Markdown
                                ) -> str:
        ''' Event when a file is converted to Markdown.
            The result is the new converted text.
        '''
        return markdown

    @staticmethod
    def on_api_document_create_end(sql: sqlite3.Cursor,                 # Cursor to query the database
                                   request: web.Request,                # HTTP request
                                   document: Dict[str, Any],            # Document as defined in the database and extra fields
                                   ) -> None:
        ''' Event after a file is loaded on the server. The database is committed already.
            You can trigger an asynchronous task to do what you want with the new/updated file.
            It is up to you to update safely the table of the documents and do the appropriate audit.
            By using the field "documents.exturl", the file must not exist locally anymore.
        '''

    @staticmethod
    def on_api_document_create_start(sql: sqlite3.Cursor,               # Cursor to query the database
                                     request: web.Request,              # HTTP request
                                     document: Dict[str, Any],          # Submitted document (changeable)
                                     ) -> bool:
        ''' Event when a new document is submitted and before many internal checks are executed.
            The result tells if the creation of the document is possible.
        '''
        return True

    @staticmethod
    def on_api_document_delete(sql: sqlite3.Cursor,                     # Cursor to query the database
                               request: Optional[web.Request],          # HTTP request
                               project: str,                            # Name of the project
                               user: str,                               # Name of the user
                               page: Optional[str],                     # Name of the page
                               doc_id: Optional[int],                   # Identifier of the document
                               filename: str,                           # Name of the file
                               ) -> bool:
        ''' Event when the file must be deleted.
            For the local files, the result tells if the deletion of the document is possible and Pwic.wiki will perform the deletion.
            For the external files, you must delete the file with your custom logic, so the result tells if the operation is successful.
            The page and id may be None when a mandatorily allowed technical maintenance occurs on the repository.
        '''
        # local_path = os.path.join(PwicConst.DOCUMENTS_PATH % project, filename)
        return True

    @staticmethod
    def on_api_document_list(sql: sqlite3.Cursor,                       # Cursor to query the database
                             request: web.Request,                      # HTTP request
                             project: str,                              # Name of the project
                             page: str,                                 # Name of the page
                             documents: List[Dict[str, Any]],           # List of the documents (changeable)
                             ) -> None:
        ''' Event when the list of the documents of a page is requested.
            Modify the parameter 'documents' without reallocating it.
        '''

    @staticmethod
    def on_api_document_rename(sql: sqlite3.Cursor,         # Cursor to query the database
                               request: web.Request,        # HTTP request
                               project: str,                # Name of the project
                               user: str,                   # Name of the user
                               page: str,                   # Name of the page
                               doc_id: int,                 # Identifier of the document
                               old_filename: str,           # Current file name
                               new_filename: str,           # Target file name
                               ) -> bool:
        ''' Event when a local file is renamed.
            The result tells if the renaming of the document is possible.
        '''
        # local_path = os.path.join(PwicConst.DOCUMENTS_PATH % project, filename)
        return True

    @staticmethod
    def on_api_page_create(sql: sqlite3.Cursor,             # Cursor to query the database
                           request: web.Request,            # HTTP request
                           project: str,                    # Name of the project
                           user: str,                       # Name of the user
                           page: str,                       # Name of the page
                           kb: bool,                        # Is knowledge base article
                           tags: str,                       # Tags
                           milestone: str,                  # Milestone
                           ) -> bool:
        ''' Event when a new page is created.
            The result tells if the creation of the page is possible.
        '''
        return True

    @staticmethod
    def on_api_page_delete(sql: sqlite3.Cursor,             # Cursor to query the database
                           request: web.Request,            # HTTP request
                           project: str,                    # Name of the project
                           user: str,                       # Name of the user
                           page: str,                       # Name of the page
                           revision: int,                   # Number of the revision
                           ) -> bool:
        ''' Event when a given revision of a page is about to be deleted.
            The result tells if the deletion of the page is possible.
        '''
        return True

    @staticmethod
    def on_api_page_edit(sql: sqlite3.Cursor,               # Cursor to query the database
                         request: web.Request,              # HTTP request
                         project: str,                      # Name of the project
                         user: str,                         # Name of the user
                         page: str,                         # Name of the page
                         title: str,                        # Title of the page
                         markdown: str,                     # Content of the page
                         tags: str,                         # Tags
                         comment: str,                      # Reason for the commit
                         milestone: str,                    # Milestone
                         draft: bool,                       # Flag for draft
                         final: bool,                       # Flag for final
                         header: bool,                      # Flag for header
                         protection: bool,                  # Flag for protection
                         ) -> bool:
        ''' Event when a new revision is submitted.
            The result tells if the update of the page is possible.
        '''
        return True

    @staticmethod
    def on_api_page_export(sql: sqlite3.Cursor,             # Cursor to query the database
                           request: web.Request,            # HTTP request
                           project: str,                    # Name of the project
                           user: str,                       # Name of the user
                           page: str,                       # Name of the page
                           revision: int,                   # Number of the revision
                           extension: str,                  # Extension of the file format
                           name: str                        # Target file name
                           ) -> Tuple[bool, Any, Dict]:
        ''' Event when a single page is exported.
            The first result tells if the own implementation overrides the standard download.
            The second result gives the new content to be downloaded. The value None denotes a forbidden download.
            The third result configures the HTTP response to ease the download with a correct format.
            An exception can be raised to cancel the download.
        '''
        return False, None, {}

    @staticmethod
    def on_api_page_move(sql: sqlite3.Cursor,               # Cursor to query the database
                         request: web.Request,              # HTTP request
                         project: str,                      # Source project
                         user: str,                         # Name of the user
                         page: str,                         # Source page
                         dst_project: str,                  # Destination project
                         dst_page: str,                     # Destination page
                         ) -> bool:
        ''' Event when a given page is renamed and/or moved to another project.
            The result tells if both the rename and the move of the page is possible.
            No other extension is called during the operation.
        '''
        return True

    @staticmethod
    def on_api_page_requested(sql: sqlite3.Cursor,          # Cursor to query the database
                              request: web.Request,         # HTTP request
                              action: str,                  # Performed action
                              project: str,                 # Name of the project
                              page: str,                    # Name of the page
                              revision: int,                # Number of the revision
                              ) -> None:
        ''' Event when a page is accessed.
            An exception can be raised to guide the navigation.
        '''

    @staticmethod
    def on_api_page_validate(sql: sqlite3.Cursor,           # Cursor to query the database
                             request: web.Request,          # HTTP request
                             project: str,                  # Name of the project
                             user: str,                     # Name of the user
                             page: str,                     # Name of the page
                             revision: int,                 # Number of the revision
                             ) -> bool:
        ''' Event when a given revision of a page is validated.
            The result tells if the validation of the page is possible.
        '''
        return True

    @staticmethod
    def on_api_project_env_set(sql: sqlite3.Cursor,         # Cursor to query the database
                               request: web.Request,        # HTTP request
                               project: str,                # Name of the project
                               user: str,                   # Name of the user
                               key: str,                    # Name of the option modified for the project
                               value: str,                  # New value of the option
                               ) -> Optional[str]:
        ''' Event when a project-dependent option is about to be changed.
            The result gives the new value of the variaable.
            Setting the value None or an empty string will delete the option.
        '''
        return value

    @staticmethod
    def on_api_project_info_get(sql: sqlite3.Cursor,                                # Cursor to query the database
                                request: web.Request,                               # HTTP request
                                project: str,                                       # Name of the project
                                user: str,                                          # Name of the user
                                page: str,                                          # Name of a precise page
                                data: Dict[str, Dict[str, List[Dict[str, Any]]]],   # Output data (changeable)
                                ) -> None:
        ''' Event when the project information are queried through the API.
            Modify the parameter 'data' to change the returned content.
        '''

    @staticmethod
    def on_api_user_create(sql: sqlite3.Cursor,             # Cursor to query the database
                           request: web.Request,            # HTTP request
                           project: str,                    # Name of the project
                           admin: str,                      # Name of the administrator
                           user: str,                       # Sanitized name of the new user account
                           ) -> bool:
        ''' Event when an administrator requests the creation of a new user account (if needed) and its assignment to the project.
            The result tells if the full operation is permitted.
            This check is important because there is no native way to remove a misspelled user account.
        '''
        return True

    @staticmethod
    def on_api_user_password_change(sql: sqlite3.Cursor,    # Cursor to query the database
                                    request: web.Request,   # HTTP request
                                    user: str,              # Name of the user whose password is modified
                                    new_password: str,      # New desired password
                                    ) -> bool:
        ''' Event when a user changes his password.
            The result tells if the modification of the password is allowed.
        '''
        return True

    @staticmethod
    def on_api_user_roles_set(sql: sqlite3.Cursor,          # Cursor to query the database
                              request: web.Request,         # HTTP request
                              project: str,                 # Name of the project
                              admin: str,                   # Name of the administrator
                              user: str,                    # Name of the user whose rights are modified
                              role: str,                    # Affected role: admin, manager, editor, validator, reader, disabled, delete
                              state: Optional[str],         # New value of the role
                              ) -> bool:
        ''' Event when an administrator deletes or modifies a role of a user account.
            The result tells if the modification of the role is allowed.
        '''
        return True

    @staticmethod
    def on_audit(sql: sqlite3.Cursor,                       # Cursor to query the database
                 request: Optional[web.Request],            # HTTP request, None if called from the console
                 event: Dict[str, Any],                     # Details of the event
                 ) -> None:
        ''' Event after an auditable operation is just executed:
                archive-audit   change-password  clear-cache      create-backup     create-document    create-project   create-revision
                create-user     delete-document  delete-page      delete-project    delete-revision    delete-user      execute-sql
                export-project  grant-admin      grant-editor     grant-manager     grant-reader       grant-validator  init-db
                login           logout           rename-document  repair-documents  reset-password     set-*            shutdown-server
                split-project   start-server     ungrant-admin    ungrant-editor    ungrant-manager    ungrant-reader   ungrant-validator
                unlock-db       unset-*          update-document  update-revision   validate-revision
            You cannot change the content of the event that is saved already.
            You should not write yourself to the table 'audit'.
            The database is not committed yet.
            You cannot raise any exception.
        '''

    @staticmethod
    def on_audit_skip(sql: sqlite3.Cursor,                  # Cursor to query the database
                      request: Optional[web.Request],       # HTTP request, None if called from the console
                      event: Dict[str, Any],                # Details of the event
                      ) -> bool:
        ''' Event to block some audit events. You have no possibility to recover the rejected events.
            The result tells if the audit event is skipped.
        '''
        return False

    @staticmethod
    def on_cache(sql: sqlite3.Cursor,                       # Cursor to query the database
                 request: web.Request,                      # HTTP request
                 project: str,                              # Name of the project
                 user: str,                                 # Name of the user
                 page: str,                                 # Name of the page
                 revision: int,                             # Revision of the page
                 ) -> bool:
        ''' Event when a page is calling the cache.
            The result tells if the cache can be used, so if the page should not be regenerated.
        '''
        return True

    @staticmethod
    def on_document_get(sql: sqlite3.Cursor,                # Cursor to query the database
                        request: web.Request,               # HTTP request
                        project: str,                       # Name of the project
                        user: str,                          # Name of the user
                        filename: str,                      # Name of the file
                        mime: str,                          # Mime type of the file
                        filesize: int,                      # Size of the file
                        ) -> bool:
        ''' Event when a document is requested.
            The result tells if the download of the document is allowed.
        '''
        return True

    @staticmethod
    def on_html(sql: sqlite3.Cursor,                        # Cursor to query the database
                project: str,                               # Name of the project
                page: Optional[str],                        # Name of the page
                revision: int,                              # Revision of the page
                html: str,                                  # Current converted Markdown to HTML code
                ) -> str:
        ''' Event when a page is converted to HTML and cached, or previewed during its edition.
            The result is the converted HTML code.
            Warning: the conversion to HTML is used in the export to OpenDocument (odt). Changing
                     the HTML inappropriately may result in a technical failure of this feature.
        '''
        return html

    @staticmethod
    def on_html_headers(sql: sqlite3.Cursor,                # Cursor to query the database
                        request: web.Request,               # HTTP request
                        headers: MultiDict,                 # Output HTTP headers
                        project: str,                       # Name of the project
                        template: Optional[str],            # Layout of the page. 'None' denotes a file download
                        ) -> None:
        ''' Event when a page or a document is delivered, excluding the API and the static files.
            To change the HTTP headers, modify the parameter 'headers' without reallocating it.
        '''
        headers['Server'] = 'Pwic.wiki v%s' % PwicConst.VERSION
        if template == 'login':
            headers['X-Frame-Options'] = 'deny'

    @staticmethod
    def on_ip_check(ip: str,                                # Remote IP address
                    authorized: bool,                       # Current status of the authorization
                    ) -> bool:
        ''' Event when the IP address of the user is checked.
            The result tells if the IP address is authorized.
        '''
        return authorized

    @staticmethod
    def on_ip_header(request: Optional[web.Request],        # HTTP request
                     ) -> str:
        ''' Event when the remote IP address must be retrieved from the HTTP headers.
            With internal proxies, you should not rely on the remote address of the TCP connection only.
            The single result is the IP fetched according to your logic.
        '''
        if request is None:
            return ''
        # return str(request.headers.get('X-Forwarded-For', request.remote))    # Enable this line if you use a reverse proxy
        return str(request.remote)

    @staticmethod
    def on_language_detected(request: web.Request,          # HTTP request
                             language: str,                 # Current language
                             available_langs: List[str],    # All the available languages
                             sso: bool,                     # True from the federated authentication
                             ) -> str:
        ''' Event when a default language is suggested.
            The result gives the new default language that must belong to the authorized languages.
        '''
        return language

    @staticmethod
    def on_login(sql: sqlite3.Cursor,                       # Cursor to query the database
                 request: web.Request,                      # HTTP request
                 user: str,                                 # Name of the user
                 language: str,                             # Selected language
                 ip: str,                                   # IP address
                 ) -> bool:
        ''' Event when a user successfully connects with a password.
            The result tells if the connection is possible.
        '''
        return True

    @staticmethod
    def on_markdown_pre(sql: sqlite3.Cursor,                # Cursor to query the database
                        project: str,                       # Name of the project
                        page: Optional[str],                # Name of the page
                        revision: int,                      # Revision of the page
                        markdown: str,                      # Current Markdown
                        ) -> str:
        ''' Event when a Markdown text is selected prior to conversion.
            The result is the new Markdown text to be processed.
            The control hash key is not affected.
        '''
        return markdown

    @staticmethod
    def on_oauth(sql: sqlite3.Cursor,                       # Cursor to query the database
                 request: web.Request,                      # HTTP request
                 emails: List[str],                         # Array of candidate email addresses (changeable)
                 ) -> None:
        ''' Event when email addresses are fetched from the remote OAuth server.
            Modify the parameter 'emails' without reallocating it.
        '''

    @staticmethod
    def on_project_export_documents(sql: sqlite3.Cursor,                # Cursor to query the database
                                    request: web.Request,               # HTTP request
                                    project: str,                       # Name of the project
                                    user: str,                          # Name of the user
                                    documents: List[Dict[str, Any]],    # List of the documents to be exported (changeable)
                                    ) -> None:
        ''' Event when a list of documents is to be exported as an archive for a given project.
            Modify the parameter 'documents' without reallocating it.
        '''

    @staticmethod
    def on_project_split(sql: sqlite3.Cursor,               # Cursor for the source database
                         newsql: sqlite3.Cursor,            # Cursor for the target database
                         projects: List[str],               # List of the impacted projects
                         ) -> None:
        ''' Event when a database is split.
            You can execute additional operations for your custom tables.
        '''

    @staticmethod
    def on_related_pages(sql: sqlite3.Cursor,               # Cursor to query the database
                         request: web.Request,              # HTTP request
                         project: str,                      # Name of the project
                         user: str,                         # Name of the user
                         page: str,                         # Name of the page
                         relations: List[Tuple[str, str]],  # Related pages
                         ) -> None:
        ''' Event to determine the related pages of a page.
            Modify the parameter 'relations' without reallocating it.
            A related link is a tuple made of the URI and its description.
            The URI should respect the formats "/project/page" or "http://your-site.tld/page".
        '''

    @staticmethod
    def on_render_post(app: web.Application,                # Access to the application (do not change)
                       sql: sqlite3.Cursor,                 # Cursor to query the database
                       request: web.Request,                # HTTP request
                       pwic: Dict[str, Any],                # Rendered content (not changeable)
                       html: str,                           # Current output to HTML
                       ) -> str:
        ''' Event after a page is rendered to HTML.
            The result returns the new output.
            Beware to be as efficient as possible in your custom logic.
            Raise an exception web.HTTP* to cancel the rendering.
        '''
        return html

    @staticmethod
    def on_render_pre(app: web.Application,                 # Access to the application (do not change)
                      sql: sqlite3.Cursor,                  # Cursor to query the database
                      request: web.Request,                 # HTTP request
                      pwic: Dict[str, Any],                 # Content to be rendered (changeable)
                      ) -> None:
        ''' Event when a page is about to be rendered.
            The variable 'pwic' contains all the calculated data and you can interact with it.
            Raise an exception web.HTTP* to cancel the rendering.
        '''

    @staticmethod
    def on_search_documents(sql: sqlite3.Cursor,            # Cursor to query the database
                            request: web.Request,           # HTTP request
                            user: str,                      # Name of the user
                            pwic: Dict[str, Any],           # Work area
                            query: Dict[str, List[str]],    # Search terms
                            ) -> bool:
        ''' Event to delegate the search of the documents.
            Populate pwic['documents'] to return the found documents.
            The result tells if you implemented a custom logic.
        '''
        return False

    @staticmethod
    def on_search_pages(sql: sqlite3.Cursor,                # Cursor to query the database
                        request: web.Request,               # HTTP request
                        user: str,                          # Name of the user
                        pwic: Dict[str, Any],               # Work area
                        query: Dict[str, List[str]],        # Search terms
                        ) -> bool:
        ''' Event to delegate the search of the pages.
            Populate pwic['pages'] to return the found pages, without reallocating it.
            The result tells if you implemented a custom logic.
        '''
        return False

    @staticmethod
    def on_search_terms(sql: sqlite3.Cursor,                            # Cursor to query the database
                        request: web.Request,                           # HTTP request
                        project: str,                                   # Name of the project
                        user: str,                                      # Name of the user
                        query: Optional[Dict[str, List[str]]],          # Not-null parsed search terms (changeable)
                        with_rev: bool,                                 # Search in the old revisions too?
                        ) -> None:
        ''' Event when a search is launched by a user.
            The variable 'query' is the changeable result.
        '''

    @staticmethod
    def on_server_ready(app: web.Application,               # Full access to the application (changeable)
                        sql: sqlite3.Cursor,                # Cursor to query the database
                        ) -> bool:
        ''' Event when the server is ready to start.
            The result tells if the server can start.
        '''
        return True

    @staticmethod
    def on_timezone() -> Optional[tzinfo]:
        ''' Event when the current date is determined.
            The result is the timezone to be used for the determination.
            The local date is used by default.
        '''
        # from pytz import utc                              # UTC+0
        # return utc
        return None                                         # Local time

    # ===============
    #  Custom routes
    # ===============

    @staticmethod
    def load_custom_routes() -> List[web.RouteDef]:
        # return [web.static('/.well-known/acme-challenge/', '/path/to/acme/challenge/'),
        #         web.get('/special/sample', PwicExtension.on_special_sample)]
        return []

    # @staticmethod
    # async def on_special_sample(request: web.Request) -> web.Response:
    #     # from pwic_lib import PwicLib
    #     return web.Response(text='Hello world!', content_type=PwicLib.mime('html'))
