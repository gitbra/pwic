# PWIC - Python Wiki Information Center

**Pwic** is an easy-to-use stand-alone monolithic Wiki server fully written in Python and backed by SQLite. In the process to support the knowledge, it has some advantages for a professional use.

** Project proficiency **
- Central repository for an online and up-to-date documentation
- Linear and undoable versioning of the documents for a proper customer validation
- Lean documents with no rainbow colors or overloaded revision marks
- Display of the differences between two versions
- New pages created by the project managers only
- Follow-up of the deliverable documents
- Unified look and feel among all the pages
- In-text search

** Cost effectiveness **
- Extra fast setup
- Low technical requirements
- Easy backup and recovery

** Custom use **
- Internationalization: English
- Customizable UI with Jinja2 templates


## Licenses

Proprietary software
Copyright (C) Alexandre Bréard, 2020

- SQLite is released in the public domain
- Jinja2 is released under 3-Clause BSD License
- Markdown2 is released under MIT license
- Parsimonious is released under MIT license
- PrettyTable is released under BSD license
- FavIcon by [Pixel Perfect](https://www.flaticon.com/free-icon/verify_2910756)


## Install

- Install Python.org: `apt-get install python3`
- Install the dependencies: `pip install cryptography aiohttp aiohttp-session jinja2 sqlite3 parsimonious PrettyTable`
- Generate your self-signed SSL keys: `python pwic_admin.py ssl`
- Initialize the SQLite database: `python pwic_admin.py init-db`
- Run the server: `python pwic.py --ssl`
- Open your browser at `https://localhost:1234`

If you intend to change the cascading style sheets (CSS), you need SASS :
- Install NodeJS.org: `apt-get install node`
- Install the dependencies: `npm install -g sass`
- Run the watcher: `sass --no-source-map --style=compressed --watch static/styles.sass static/styles.css`
- Adapt the templates and CSS stored in the folder `static` until you get the desired output


## Support

Please use the issue tracker on Github to report bugs or request new features.
