# PWIC - Python Wiki Information Center


## Presentation

**Pwic** is a wiki server to support your personal and professional documentation. Its paradigm is to put the documentation at the center of your methodology through comprehensive features and 5 basic roles (reader, editor, validator, manager and administrator). The users are focused on writing the documentation, not on changing the styles. The managers supervise the progress. The technical team can reject any uncomplient document.


## Some supported features

Who can do the most can do the least!

### For the readers

- Access with a user account on both desktop and mobile devices
- Lightweight user interface illustrated with emojis
- Dark mode
- Homogeneous look and feel across the pages
- Encyclopedic mode to browse the latest validated revisions only
- Automatic summary of the page
- In-text search with inclusion, exclusion, hash tags and special keywords
- Highlight of the lines of code
- Export of a page to OpenDocument (*.odt)
- Export of a page to Markdown (*.md)
- Share by link
- Share by email
- Internationalization (English only for now)

### For the editors

- Page layout supervised with Markdown
- Wysiwyg editor for Markdown
- Classification of the pages with hashtags
- Automatic numbering of the headers
- Linear and partially undoable versioning for a proper customer's validation
- Status follow-up by page and hashtag

### For the validators

- Text comparison between two revisions
- No change or no deletion possible after a page is validated
- Visible control hash key

### For the managers

- Dynamic tables to track the progress of the documentation by project or tag
- Write the templates in a dedicated project
- Create the pages with a manual name or automatic KB identifier
- Detection of the orphaned pages
- Detection of the broken links
- Visual graph of the links between the pages

### For the administrators

**System**

- Low technical requirements and bandwidth
- Affordable solution based on open-source applications
- Fast setup with Python 3 in 10 minutes
- Local storage of the uploaded files and SQLite database
- Support for HTTP and HTTPS
- Unicode content and URL
- HTTP logging
- IP filtering

**Pwic**

- Multi-projects with dedicated authorizations for the users
- Global and project-dependent settings
- OAuth2-based federated authentication with control of the state
- Cache system
- Management of the attached documents by name, mime, size and magic bytes
- Private and public modes
- Custom CSS and templates
- Export of an entire project to Markdown and HTML
- Traceable activities
- API and command line to automate the classical operations
- Extension points in the code


## Install

- Install Python: `apt-get install python3 python3-pip`
	- Depending on your operating system, use `python` or `python3` below to invoke Python version 3
- Install the dependencies: `python -m pip install aiohttp aiohttp-cors aiohttp-session cryptography imagesize jinja2 parsimonious PrettyTable pygments`
- Optionally install your SSL certificate or generate your self-signed one: `python pwic_admin.py generate-ssl`
- Optionally but definitively write random characters in the secret salt `PWIC_SALT` in `pwic_lib.py` with a text editor
- Make sure that the subfolder `db/` is writable
- Initialize the SQLite database: `python pwic_admin.py init-db`
- Create a new project: `python pwic_admin.py create-project --help`
	- The default password of the users is `initial` as defined in `PWIC_DEFAULT_PASSWORD`.
- Define the global and project-dependent variables, at least `base_url`: `python pwic_admin.py set-env --help` (details available in the help page)
- Run the server: `python pwic.py`
	- The bind address `0.0.0.0` and port can be modified in the command line if you need a public exposure for your server
- Open your browser at `http://127.0.0.1:8080`

If you intend to change the cascading style sheets (CSS), you need SASS:

- Install Node.js: `apt-get install node`
- Install the dependencies: `npm install -g sass`
- Adapt the templates in `templates/` and the SASS files in `static/`
- Compile the CSS files:
	- `sass --no-source-map --style=compressed static/styles.sass static/styles.css`
	- `sass --no-source-map --style=compressed static/styles_dark.sass static/styles_dark.css`

Note: overriding the default CSS is possible in the options by linking to custom CSS files, and then you won't need SASS.


## Support

Please use the issue tracker on Github to ask questions, report bugs or request new features.


## Licenses

Proprietary software
Copyright (C) Alexandre Bréard, 2020-2021

- [aiohttp](https://github.com/aio-libs/aiohttp) is released under Apache 2.0 License
- [aiohttp-cors](https://github.com/aio-libs/aiohttp-cors) is released under Apache 2.0 License
- [aiohttp-session](https://github.com/aio-libs/aiohttp-session) is released under Apache 2.0 License
- [cash.js](https://github.com/fabiospampinato/cash) is released under MIT License
- [EasyMDE](https://github.com/Ionaru/easy-markdown-editor) is released under MIT License
- Favorite icon by [Pixel Perfect](https://www.flaticon.com/free-icon/verify_2910756)
- [FontAwesome](https://github.com/FortAwesome/Font-Awesome) is released under both SIL OFL 1.1 (font) and MIT License (CSS)
- [ImageSize](https://github.com/shibukawa/imagesize_py) is released under MIT License
- [Jinja2](https://github.com/pallets/jinja) is released under BSD-3-Clause License
- [Markdown2](https://github.com/trentm/python-markdown2) is released under MIT License
- [MathJax](https://github.com/mathjax/MathJax-src) is released under Apache 2.0 License
- [Noto Sans](https://fonts.google.com/specimen/Noto+Sans) is released under Open Font License
- [Parsimonious](https://github.com/erikrose/parsimonious) is released under MIT License
- [PrettyTable](https://github.com/jazzband/prettytable) is released under BSD License
- [pygments](https://github.com/pygments/pygments) is released under BSD-2-Clause License
- [pygments CSS](https://github.com/richleland/pygments-css) is released under Unlicense License
- [Python](https://github.com/python/cpython/) is released under Python Software Foundation License
- [SQLite](https://www.sqlite.org) is released in the public domain
- [SVG pan & zoom](https://github.com/ariutta/svg-pan-zoom) is released under BSD-2-Clause License
- [Swagger UI](https://github.com/swagger-api/swagger-ui) is released under Apache 2.0 License
- [Viz.js](https://github.com/mdaines/viz.js) is released under MIT License

Note: EasyMDE and Markdown2 contain little modifications to adapt to Pwic. You cannot upgrade them automatically.
