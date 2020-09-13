# PWIC - Python Wiki Information Center

**Pwic** is an easy-to-use stand-alone monolithic Wiki server fully written in Python and backed by SQLite. In the process to support the knowledge, it has some advantages for a professional use.

**Project proficiency**

- Central repository for an online and up-to-date documentation
- Ready for Unicode and built on Emojis
- New pages, broken links and orphaned pages supervised by the project managers
- Linear and partially undoable versioning of the pages for a proper customer's validation
- Unified look and feel among all the pages
- Automatic highlight of the lines of code
- Follow-up of the deliverable pages
- Lean documents with no rainbow color or overloaded revision mark
- Display of the differences between two versions
- File attachments with normalized names
- In-text search with inclusion, exclusion and special keywords
- IP filtering


**Cost effectiveness**

- Extra fast setup
- Low technical requirements
- Easy backup and recovery

**Custom use**

- Internationalization: English for now
- Customizable UI with Jinja2 templates
- API to perform operations by bots or scripts


## Licenses

Proprietary software
Copyright (C) Alexandre Bréard, 2020

- SQLite is released in the public domain
- Jinja2 is released under 3-Clause BSD License
- Markdown2 is released under MIT license
	- PwicMarkdown is a modified version to consider all the links as valid
- Parsimonious is released under MIT license
- PrettyTable is released under BSD license
- FavIcon by [Pixel Perfect](https://www.flaticon.com/free-icon/verify_2910756)
- Baloo 2 is released under Open Font License


## Install

- Install Python: `apt-get install python3`
- Install the dependencies: `pip install cryptography aiohttp aiohttp-session jinja2 sqlite3 parsimonious PrettyTable pygments`
- Generate your self-signed SSL keys: `python pwic_admin.py ssl`
- Ideally define your secret salt `PWIC_SALT` in `pwic_lib.py` with a text editor
- Initialize the SQLite database: `python pwic_admin.py init-db`
- Create a new project: `python pwic_admin.py create-project --help`
- Run the server: `python pwic.py --ssl`
- Open your browser at `https://localhost:1234`

If you intend to change the cascading style sheets (CSS), you need SASS:

- Install Node.js: `apt-get install node`
- Install the dependencies: `npm install -g sass`
- Run the watcher: `sass --no-source-map --style=compressed --watch static/styles.sass static/styles.css`
- Adapt the templates and CSS stored in the folder `static` until you get the desired output


## Support

Please use the issue tracker on Github to report bugs or request new features.
