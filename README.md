# PWIC - Python Wiki Information Center

**Pwic** is an easy-to-use stand-alone monolithic Wiki server fully written in Python and backed by SQLite. In the process to support the knowledge, it has many advantages for a professional use.

**Project proficiency**

- Central repository for an online and up-to-date documentation
- Ready for Unicode and built on Emojis
- New pages, broken links, orphaned pages and graph supervised by the project managers
- Linear and partially undoable versioning of the pages for a proper customer's validation
- Unified look and feel among all the pages
- Automatic highlight of the lines of code
- Follow-up of the deliverable pages
- Lean pages with no rainbow color or overloaded revision mark
- Display of the differences between two versions
- File attachments with normalized names
- In-text search with inclusion, exclusion and special keywords
- Export to OpenDocument (ODT)


**Cost effectiveness and technicity**

- Extra fast setup
- Low technical requirements
- Easy backup and recovery
- Ready for TLS v1.3
- IP filtering
- Cross Origin Resource Sharing (CORS)


**Custom use**

- Internationalization: English for now
- Customizable UI with Jinja2 templates
- API to perform operations by bots or scripts


## Licenses

Proprietary software
Copyright (C) Alexandre Bréard, 2020

- [aiohttp](https://github.com/aio-libs/aiohttp) is released under Apache 2.0 License
- [Baloo 2](https://fonts.google.com/specimen/Baloo+2) is released under Open Font License
- [EasyMDE](https://github.com/Ionaru/easy-markdown-editor) is released under MIT License
	- The file is version 2.11 and patched against the issue #217
- Favorite icon by [Pixel Perfect](https://www.flaticon.com/free-icon/verify_2910756)
- [FontAwesome](https://github.com/FortAwesome/Font-Awesome) is released under both SIL OFL 1.1 (font) and MIT License (CSS)
- [Jinja2](https://github.com/pallets/jinja) is released under BSD-3-Clause License
- [Markdown2](https://github.com/trentm/python-markdown2) is released under MIT License
	- Pwic implements a modified version to support some types of link when the safe mode is activated
- [Parsimonious](https://github.com/erikrose/parsimonious) is released under MIT License
- [PrettyTable](https://github.com/jazzband/prettytable) is released under BSD License
- [pygments](https://github.com/pygments/pygments) is released under BSD-2-Clause License
- [Python](https://github.com/python/cpython/) is released under Python Software Foundation License
- [SQLite](https://www.sqlite.org) is released in the public domain
- [SVG pan & zoom](https://github.com/ariutta/svg-pan-zoom) is released under BSD-2-Clause License
- [Swagger UI](https://github.com/swagger-api/swagger-ui) is released under Apache 2.0 License
- [Viz.js](https://github.com/mdaines/viz.js) is released under MIT License


## Install

- Install Python: `apt-get install python3`
- Install the dependencies: `pip install aiohttp aiohttp-cors aiohttp-session jinja2 sqlite3 parsimonious PrettyTable pygments`
	- Additionally `cryptography` is required if you want to generate your self-signed certificates
- Generate your self-signed SSL keys: `python pwic_admin.py ssl`
- Ideally define your secret salt `PWIC_SALT` in `pwic_lib.py` with a text editor
- Initialize the SQLite database: `python pwic_admin.py init-db`
- Eventually refine the global variables: `python pwic_admin.py set-env --help` (refer to the online help)
- Create a new project: `python pwic_admin.py create-project --help`
- Run the server: `python pwic.py`
- Open your browser at `https://localhost:1234`

If you intend to change the cascading style sheets (CSS), you need SASS:

- Install Node.js: `apt-get install node`
- Install the dependencies: `npm install -g sass`
- Run the watcher: `sass --no-source-map --style=compressed --watch static/styles.sass static/styles.css`
- Adapt the templates and CSS stored in the folder `static` until you get the desired output


## Support

Please use the issue tracker on Github to report bugs or request new features.
