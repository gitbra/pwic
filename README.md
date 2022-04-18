# Pwic.wiki server powered by Python and SQLite


## Presentation

**Pwic.wiki** (pronounce /puik/) is a lightweight wiki server to support the documentation of your projects through comprehensive features and 5 basic roles. Its purpose is to serve as a common repository where the essential documentation can be easily located, accessed, edited, compared, validated, shared, exported and eventually analyzed by your own scripts.

*Pwic.wiki* is an advanced concept that attempts to fix frequent caveats that you can face when you participate to an IT project. If you ever wasted your time on managing your files, templates, styles and validations, you are probably searching for a fresh solution to support your process!

The [official homepage](https://pwic.wiki) is running the latest version.


## Some supported features

### For the readers

- Access with a user account on both desktop and mobile devices
- Lightweight user interface illustrated with emojis
- Dark mode
- Homogeneous look and feel across the pages
- Encyclopedic mode to browse the latest validated revisions only
- Automatic summary of the page
- In-text search with inclusion, exclusion, hash tags and special keywords
- Search link for the browsers
- Highlight of the lines of code
- Export of a page to Markdown (.md), web page (.html) and OpenDocument (.odt)
- RSS feed
- Share by link
- Share by email
- Internationalization (English only for now)

### For the validators

- Text comparison between two revisions
- No change or no deletion possible after a page is validated
- Visible control hash key

### For the editors

- Page layout supervised with Markdown and HTML
- Wysiwyg editor for Markdown
- Classification of the pages with hashtags
- Automatic numbering of the headers with no gap
- Mandatory, linear and partially undoable versioning
- Hashtags and statuses

### For the managers

- Dynamic tables to track the progress of the documentation by project and tag
- Copyable templates between projects
- Possible automatic KB identifier
- Detection of the orphaned pages
- Detection of the broken links
- Visual graph of the links between the pages

### For the administrators

**System**

- Low technical requirements and bandwidth
- Affordable solution based on open-source applications
- Fast setup with Python 3 in 10 minutes
- No data stored in proprietary formats
- Local storage of the uploaded files and SQLite database
- Possible deployment with command lines
- Critical administration not available online
- Support for HTTP, HTTPS and reverse proxy
- Unicode content and URL
- HTTP logging
- IP filtering

**Pwic.wiki**

- Multi-projects with dedicated authorizations by user
- Global and project-dependent settings
- OAuth2-based federated authentication with control of the state (SSO)
- Cache system
- Management of the attached documents by name, mime, size and magic bytes
- Private and public modes
- Custom CSS and templates
- Export of an entire project to Markdown and HTML
- Traceable activities
- API and command line to automate the operations
- Extension points in the code
- Possible integration with external storage providers
- No JavaScript needed to read the pages


## Install

### Mandatory technical setup

- Install Python >=3.7: `apt-get install python3 python3-pip --no-install-recommends`
- Install the dependencies: `python3 -m pip install --upgrade "aiohttp>=3.8" aiohttp-cors "aiohttp-session>=2.10" imagesize jinja2 parsimonious PrettyTable pygments`
- Clone the repository `git clone https://github.com/gitbra/pwic.git` or uncompress the [latest modifications](https://github.com/gitbra/pwic/archive/refs/heads/master.zip) in a folder of your choice
- Optionally modify some default values in the file `pwic_lib.py` with a text editor to increase the security:
	- Change the default password in `PWIC_DEFAULTS['password']`
	- Write random characters in the secret salt `PWIC_SALT` forever
- Initialize the database: `python3 pwic_admin.py init-db`
	- A sub-folder `db/` is created for all your data

### Quick local setup

- Create a new project `demo` for the user `admin`: `python3 pwic_admin.py create-project demo "Demo project" admin`
- Run the server: `python3 pwic.py`
- Open your browser at `http://127.0.0.1:8080` by default

Once you have well tested Pwic.wiki and defined the global and project-dependent variables described in the embedded help file, you can use the bind address `0.0.0.0` and change the port in the main command line.


## Support

Please use the issue tracker on Github to ask questions, report bugs and request new features.


## Licenses

### Main

- Pwic.wiki server running on Python and SQLite
- Copyright (C) 2020-2022 Alexandre Bréard
	- <https://pwic.wiki>
	- <https://github.com/gitbra/pwic>
- Released under the terms of the GNU Affero General Public License v3+

### Third-party software

- [aiohttp](https://github.com/aio-libs/aiohttp) is released under Apache 2.0 License
- [aiohttp-cors](https://github.com/aio-libs/aiohttp-cors) is released under Apache 2.0 License
- [aiohttp-session](https://github.com/aio-libs/aiohttp-session) is released under Apache 2.0 License
- [cash.js](https://github.com/fabiospampinato/cash) is released under MIT License
- [EasyMDE](https://github.com/Ionaru/easy-markdown-editor) is released under MIT License
- [FontAwesome](https://github.com/FortAwesome/Font-Awesome) is released under both SIL OFL 1.1 (font) and MIT License (CSS)
- [ImageSize](https://github.com/shibukawa/imagesize_py) is released under MIT License
- [Jinja2](https://github.com/pallets/jinja) is released under BSD-3-Clause License
- [Markdown2](https://github.com/trentm/python-markdown2) is released under MIT License
- [MathJax](https://github.com/mathjax/MathJax-src) is released under Apache 2.0 License
- [Noto Sans](https://fonts.google.com/specimen/Noto+Sans) is released under Open Font License
- [Parsimonious](https://github.com/erikrose/parsimonious) is released under MIT License
- [PrettyTable](https://github.com/jazzband/prettytable) is released under BSD License
- [pygments](https://github.com/pygments/pygments) is released under BSD-2-Clause License
- [Python](https://github.com/python/cpython/) is released under Python Software Foundation License
- [SQLite](https://www.sqlite.org) is released in the public domain
- [SVG pan & zoom](https://github.com/ariutta/svg-pan-zoom) is released under BSD-2-Clause License
- [Swagger UI](https://github.com/swagger-api/swagger-ui) is released under Apache 2.0 License
- [Viz.js](https://github.com/mdaines/viz.js) is released under MIT License

Note: EasyMDE and Markdown2 contain little modifications to adapt to Pwic.wiki. You cannot upgrade them automatically.
