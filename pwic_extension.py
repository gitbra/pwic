
'''
    The behavior of Pwic is changeable in this file through a logic of events
    positioned at critical positions in the code base. It is easier to implement
    some changes here but it remains sensible from a technical perspective.

    Each method is always active and generally returns from 0 to 2 results.
    The first one usually tells if something happened. The second one provides
    the new result. With no result, the parameters of the method are changeable
    if they are passed as a reference, else raise an exception.
'''

from aiohttp import web
import sqlite3


class PwicExtension():
    def __init__(self: object):
        ''' Initialize everything you need for the class. '''
        # self.my_value = 123
        pass

    def on_html(self: object,
                sql: sqlite3.Cursor,                        # Cursor to query the database
                project: str,                               # Name of the project
                page: str,                                  # Name of the page (may be None)
                html: str,                                  # Current converted Markdown to HTML code
                ) -> (bool, str):
        ''' Event when a page is converted to HTML.
            The first result tells if the HML code must be changed.
            The second result provides the new HTML code adapted from the first one.
            Warning: the conversion to HTML is used in the export to OpenDocument. Changing the HTML
                     inappropriately may result in a technical failure of this feature.
        '''
        return False, ''

    def on_ip_header(self: object,
                     request: web.Request,                  # HTTP request
                     ) -> str:
        ''' Event when the remote IP is retrieved from the HTTP headers if the option 'xff' is enabled.
            The single result is the name of the header to read.
        '''
        return 'X-Forwarded-For'

    def on_ip_check(self: object,
                    ip: str,                                # Remote IP address
                    authorized: bool,                       # Current status of the authorization
                    ) -> (bool, bool):
        ''' Event when the IP address of the user is checked.
            The first result tells if the authorization must be changed.
            The second result tells if the user is authorized.
        '''
        return False, True

    def on_render(self: object,
                  app: object,                              # Access to the application (do not change)
                  sql: sqlite3.Cursor,                      # Cursor to query the database
                  pwic: object,                             # Content to be rendered (changeable)
                  ) -> None:
        ''' Event when a page is about to be rendered.
            The variable 'pwic' contains all the calculated data and you can interact with it.
            Raise an exception web.HTTP* to cancel the rendering.
        '''
        pass

    def on_search_terms(self: object,
                        sql: sqlite3.Cursor,                # Cursor to query the database
                        project: str,                       # Name of the project
                        user: str,                          # Name of the user
                        query: object,                      # Not-null parsed search terms (changeable)
                        with_rev: bool,                     # Search in the old revisions too?
                        ) -> None:
        ''' Event when a search is launched by a user.
            The variable 'query' is the changeable result.
        '''
        pass

    def on_project_export_documents(self: object,
                                    sql: sqlite3.Cursor,    # Cursor to query the database
                                    project: str,           # Name of the project
                                    user: str,              # Name of the user
                                    documents: list,        # List of the documents to be exported (changeable)
                                    ) -> None:
        ''' Event when a list of documents is to be exported as an archive for a given project.
            Modify the parameter 'documents' without reallocating it.
        '''
        pass

    def on_document_get(self: object,
                        sql: sqlite3.Cursor,                # Cursor to query the database
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

    def on_logon(self: object,
                 sql: sqlite3.Cursor,                       # Cursor to query the database
                 user: str,                                 # Name of the user
                 password: str,                             # Hashed password
                 language: str,                             # Selected language
                 ) -> (bool, bool):
        ''' Event when a user wants to connect with a password out of the OAuth logic.
            The first result tells if the status of the connection must be modified.
            The second result tells if the connection is authorized.
        '''
        return False, True

    def on_oauth(self: object,
                 sql: sqlite3.Cursor,                       # Cursor to query the database
                 emails: list,                              # Array of candidate email addresses (changeable)
                 ) -> None:
        ''' Event when email addresses are fetched from the remote OAuth server.
            Modify the parameter 'emails' without reallocating it.
        '''
        pass

    def on_api_project_info_get(self: object,
                                sql: sqlite3.Cursor,        # Cursor to query the database
                                project: str,               # Name of the project
                                user: str,                  # Name of the user
                                page: str,                  # Name of a precise page
                                data: object,               # Output data (changeable)
                                ) -> None:
        ''' Event when the project information are queried through the API.
            Modify the parameter 'data' to change the returned content.
        '''
        pass

    def on_api_page_validate(self: object,
                             sql: sqlite3.Cursor,           # Cursor to query the database
                             project: str,                  # Name of the project
                             user: str,                     # Name of the user
                             page: str,                     # Name of the page
                             revision: int,                 # Number of the revision
                             ) -> (bool, bool):
        ''' Event when a given revision of a page is validated through the API.
            The first result tells if the status of the validation must be modified.
            The second result tells if the validation is possible.
        '''
        return False, True

    def on_api_page_delete(self: object,
                           sql: sqlite3.Cursor,             # Cursor to query the database
                           project: str,                    # Name of the project
                           user: str,                       # Name of the user
                           page: str,                       # Name of the page
                           revision: int,                   # Number of the revision
                           ) -> (bool, bool):
        ''' Event when a given revision of a page is deleted through the API.
            The first result tells if the status of the deletion must be modified.
            The second result tells if the deletion is possible.
        '''
        return False, True

    def on_api_page_export_start(self: object,
                                 sql: sqlite3.Cursor,       # Cursor to query the database
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

    def on_api_user_create(self: object,
                           sql: sqlite3.Cursor,             # Cursor to query the database
                           project: str,                    # Name of the project
                           admin: str,                      # Name of the administrator
                           user: str,                       # Sanitized name of the new user account
                           ) -> bool:
        ''' Event when an administrator requests the creation of a new user account (if needed)
            and its assignment to the project.
            The result tells if the operation is permitted.
        '''
        return True

    def on_api_user_roles_set(self: object,
                              sql: sqlite3.Cursor,          # Cursor to query the database
                              project: str,                 # Name of the project
                              admin: str,                   # Name of the administrator
                              user: str,                    # Name of the user whose rights are modified
                              role: str,                    # Affected role
                              state: str,                   # New value of the role
                              ) -> None:
        ''' Event when an administrator deletes or modifies a role of a user account.
            Raise an exception web.HTTP* to cancel the modification of the role.
        '''
        pass

    def on_api_document_create(self: object,
                               sql: sqlite3.Cursor,         # Cursor to query the database
                               document: object,            # Submitted document (changeable)
                               ) -> None:
        ''' Event when a new document is submitted and before many internal checks are executed.
            Raise an exception web.HTTP* to cancel the upload.
            Warning: the filename won't be reverified if you change it.
        '''
        pass

    def on_api_document_list(self: object,
                             sql: sqlite3.Cursor,           # Cursor to query the database
                             project: str,                  # Name of the project
                             page: str,                     # Name of the page
                             documents: list,               # List of the documents (changeable)
                             ):
        ''' Event when the list of the documents of a page is requested.
            Modify the parameter 'documents' without reallocating it.
        '''
        pass

    def on_api_document_delete(self: object,
                               sql: sqlite3.Cursor,         # Cursor to query the database
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

    def on_server_ready(self: object,
                        app: web.Application,               # Full access to the application (changeable)
                        sql: sqlite3.Cursor,                # Cursor to query the database
                        ) -> (bool, bool):
        ''' Event when Pwic server is ready to start.
            The first result tells if the behavior must be changed.
            The second result tells if the server can start.
        '''
        return False, True
