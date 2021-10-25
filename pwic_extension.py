
'''
    The behavior of Pwic is changeable in this file through a logic of events
    positioned at critical positions in the code base. It is easier to implement
    some changes here but it remains sensible from a technical perspective.

    Each method is always active and generally returns from 0 to 2 results.
    The first one usually tells if something happened. The second one provides
    the new result. With no result, the parameters of the method are changeable
    if they are passed as a reference, else raise an exception.
'''

from typing import Any, Dict, List, Optional, Tuple
from aiohttp import web
import sqlite3


class PwicExtension():
    @staticmethod
    def on_api_document_create(sql: sqlite3.Cursor,         # Cursor to query the database
                               document: Dict[str, Any],    # Submitted document (changeable)
                               ) -> None:
        ''' Event when a new document is submitted and before many internal checks are executed.
            Raise an exception web.HTTP* to cancel the upload.
            Warning: the filename won't be reverified if you change it.
        '''
        pass

    @staticmethod
    def on_api_document_delete(sql: sqlite3.Cursor,         # Cursor to query the database
                               project: str,                # Name of the project
                               user: str,                   # Name of the user
                               page: str,                   # Name of the page
                               id: int,                     # Identifier of the document
                               filename: str,               # Name of the file
                               ) -> None:
        ''' Event when is file is deleted.
            Raise an exception web.HTTP* to cancel the deletion.
        '''
        pass

    @staticmethod
    def on_api_document_list(sql: sqlite3.Cursor,                       # Cursor to query the database
                             project: str,                              # Name of the project
                             page: str,                                 # Name of the page
                             documents: List[Dict[str, Any]],           # List of the documents (changeable)
                             ) -> None:
        ''' Event when the list of the documents of a page is requested.
            Modify the parameter 'documents' without reallocating it.
        '''
        pass

    @staticmethod
    def on_api_page_delete(sql: sqlite3.Cursor,             # Cursor to query the database
                           project: str,                    # Name of the project
                           user: str,                       # Name of the user
                           page: str,                       # Name of the page
                           revision: int,                   # Number of the revision
                           ) -> Tuple[bool, bool]:
        ''' Event when a given revision of a page is deleted through the API.
            The first result tells if the status of the deletion must be modified.
            The second result tells if the deletion is possible.
        '''
        return False, True

    @staticmethod
    def on_api_page_export_start(sql: sqlite3.Cursor,       # Cursor to query the database
                                 project: str,              # Name of the project
                                 user: str,                 # Name of the user
                                 page: str,                 # Name of the page
                                 revision: int,             # Number of the revision
                                 format: str,               # Extension of the file format
                                 ) -> None:
        ''' Event when the export of a page begins.
            Raise an exception to cancel the download.
        '''
        pass

    @staticmethod
    def on_api_page_validate(sql: sqlite3.Cursor,           # Cursor to query the database
                             project: str,                  # Name of the project
                             user: str,                     # Name of the user
                             page: str,                     # Name of the page
                             revision: int,                 # Number of the revision
                             ) -> Tuple[bool, bool]:
        ''' Event when a given revision of a page is validated through the API.
            The first result tells if the status of the validation must be modified.
            The second result tells if the validation is possible.
        '''
        return False, True

    @staticmethod
    def on_api_project_env_set(sql: sqlite3.Cursor,         # Cursor to query the database
                               project: str,                # Name of the project
                               user: str,                   # Name of the user
                               key: str,                    # Name of the option modified for the project
                               value: str,                  # New value of the option
                               ) -> Tuple[bool, Optional[str]]:
        ''' Event when a project-dependent option is about to be changed.
            The first result tells if the value must be modified.
            The second result gives the new value. None or an empty value will delete the option.
        '''
        return False, ''

    @staticmethod
    def on_api_project_info_get(sql: sqlite3.Cursor,                                # Cursor to query the database
                                project: str,                                       # Name of the project
                                user: str,                                          # Name of the user
                                page: str,                                          # Name of a precise page
                                data: Dict[str, Dict[str, List[Dict[str, Any]]]],   # Output data (changeable)
                                ) -> None:
        ''' Event when the project information are queried through the API.
            Modify the parameter 'data' to change the returned content.
        '''
        pass

    @staticmethod
    def on_api_user_create(sql: sqlite3.Cursor,             # Cursor to query the database
                           project: str,                    # Name of the project
                           admin: str,                      # Name of the administrator
                           user: str,                       # Sanitized name of the new user account
                           ) -> bool:
        ''' Event when an administrator requests the creation of a new user account (if needed)
            and its assignment to the project.
            The result tells if the operation is permitted.
        '''
        return True

    @staticmethod
    def on_api_user_roles_set(sql: sqlite3.Cursor,          # Cursor to query the database
                              project: str,                 # Name of the project
                              admin: str,                   # Name of the administrator
                              user: str,                    # Name of the user whose rights are modified
                              role: str,                    # Affected role
                              state: Optional[str],         # New value of the role
                              ) -> None:
        ''' Event when an administrator deletes or modifies a role of a user account.
            Raise an exception web.HTTP* to cancel the modification of the role.
        '''
        pass

    @staticmethod
    def on_audit(sql: sqlite3.Cursor,                       # Cursor to query the database
                 event: Dict[str, Any],                     # Details of the event
                 online: bool,                              # Event coming from the Internet (True) or the console (False)
                 ) -> None:
        ''' Event after an auditable operation is just executed:
                change-password   clear-cache        create-document     create-page    create-project    create-user      delete-document
                delete-drafts     delete-project     delete-revision     delete-user    execute-sql       export-project   generate-ssl
                grant-admin       grant-editor       grant-manager       grant-reader   grant-validator   init-db          logon
                logout            replace-document   reset-password      set-*          start-server      ungrant-admin    ungrant-editor
                ungrant-manager   ungrant-reader     ungrant-validator   unset-*        update-page       validate-page
            You cannot change the content of the event that is saved already.
            You should not write yourself to the table 'audit'.
            The database is not committed yet.
        '''
        pass

    @staticmethod
    def on_document_get(sql: sqlite3.Cursor,                # Cursor to query the database
                        project: str,                       # Name of the project
                        user: str,                          # Name of the user
                        filename: str,                      # Name of the file
                        mime: str,                          # Mime type of the file
                        filesize: int,                      # Size of the file
                        ) -> None:
        ''' Event when a document is requested.
            Raise an exception web.HTTP* to cancel the access to the file.
        '''
        pass

    @staticmethod
    def on_html(sql: sqlite3.Cursor,                        # Cursor to query the database
                project: str,                               # Name of the project
                page: Optional[str],                        # Name of the page
                revision: int,                              # Revision of the page
                html: str,                                  # Current converted Markdown to HTML code
                ) -> Tuple[bool, str]:
        ''' Event when a page is converted to HTML and cached.
            The first result tells if the HML code must be changed.
            The second result provides the new HTML code adapted from the first one.
            Warning: the conversion to HTML is used in the export to OpenDocument. Changing the HTML
                     inappropriately may result in a technical failure of this feature.
        '''
        return False, ''

    @staticmethod
    def on_ip_check(ip: str,                                # Remote IP address
                    authorized: bool,                       # Current status of the authorization
                    ) -> Tuple[bool, bool]:
        ''' Event when the IP address of the user is checked.
            The first result tells if the authorization must be changed.
            The second result tells if the user is authorized.
        '''
        return False, True

    @staticmethod
    def on_ip_header(request: web.Request,                  # HTTP request
                     ) -> str:
        ''' Event when the remote IP is retrieved from the HTTP headers if the option 'xff' is enabled.
            The single result is the name of the header to read.
        '''
        return 'X-Forwarded-For'

    @staticmethod
    def on_logon(sql: sqlite3.Cursor,                       # Cursor to query the database
                 user: str,                                 # Name of the user
                 language: str,                             # Selected language
                 ) -> bool:
        ''' Event when a user successfully connects to Pwic with a password.
            The result overrides the acceptability of the connection.
        '''
        return True

    @staticmethod
    def on_oauth(sql: sqlite3.Cursor,                       # Cursor to query the database
                 emails: List[str],                         # Array of candidate email addresses (changeable)
                 ) -> None:
        ''' Event when email addresses are fetched from the remote OAuth server.
            Modify the parameter 'emails' without reallocating it.
        '''
        pass

    @staticmethod
    def on_project_export_documents(sql: sqlite3.Cursor,                # Cursor to query the database
                                    project: str,                       # Name of the project
                                    user: str,                          # Name of the user
                                    documents: List[Dict[str, Any]],    # List of the documents to be exported (changeable)
                                    ) -> None:
        ''' Event when a list of documents is to be exported as an archive for a given project.
            Modify the parameter 'documents' without reallocating it.
        '''
        pass

    @staticmethod
    def on_render_post(app: web.Application,                # Access to the application (do not change)
                       sql: sqlite3.Cursor,                 # Cursor to query the database
                       pwic: Dict[str, Any],                # Rendered content (not changeable)
                       html: str,                           # Current output to HTML
                       ) -> Tuple[bool, str]:
        ''' Event after a page is rendered to HTML.
            The first result tells if the output must be changed.
            The second result gives the new output. Beware to be as efficient as possible in your custom logic.
            Raise an exception web.HTTP* to cancel the rendering.
        '''
        return False, ''

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
        pass

    @staticmethod
    def on_search_documents(sql: sqlite3.Cursor,            # Cursor to query the database
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
                        project: str,                                   # Name of the project
                        user: str,                                      # Name of the user
                        query: Optional[Dict[str, List[str]]],          # Not-null parsed search terms (changeable)
                        with_rev: bool,                                 # Search in the old revisions too?
                        ) -> None:
        ''' Event when a search is launched by a user.
            The variable 'query' is the changeable result.
        '''
        pass

    @staticmethod
    def on_server_ready(app: web.Application,               # Full access to the application (changeable)
                        sql: sqlite3.Cursor,                # Cursor to query the database
                        ) -> Tuple[bool, bool]:
        ''' Event when Pwic server is ready to start.
            The first result tells if the behavior must be changed.
            The second result tells if the server can start.
        '''
        return False, True
