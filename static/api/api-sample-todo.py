#!/usr/bin/env python

# This demo program queries the API to fetch the work in progress left in the content of the pages.
# Programmers generally leave lines starting with "TODO" or "BUG", and followed by a comment.
# This technique highlights the remaining things to do before the documentation is complete.
# This script summarizes these actions in a table. Note that it is written to not handle the errors.

from urllib.request import Request, urlopen
from urllib.parse import urlencode
import json
from prettytable import PrettyTable

# Changeable configuration
host = 'http://127.0.0.1:8080'
user = 'your@user.name'
password = 'your.password'
project = 'your_project'

# Authentication
headers = {'Origin': host}
response = urlopen(Request(host + '/api/logon',
                           urlencode({'user': user,
                                      'password': password}).encode(),
                           headers=headers,
                           method='POST'))
headers['Cookie'] = response.headers.get('Set-Cookie', '')

# Get some information
tab = PrettyTable()
response = urlopen(Request(host + '/api/project/info/get',
                           urlencode({'project': project}).encode(),
                           headers=headers,
                           method='POST'))
if response.status == 200:
    data = response.read().decode('utf-8')
    jsonData = json.loads(data)
    for key in jsonData:
        entry = jsonData[key]['revisions'][0]
        if 'markdown' not in entry:
            print('Error: the option "api_expose_markdown" must be enabled for the project.')
            break

        # Parse the page
        lines = entry['markdown'].replace('\r', '').split('\n')
        for line in lines:
            line = line.strip()
            if line[:4] == 'BUG ':
                p = 4
            elif line[:5] == 'TODO ':
                p = 5
            else:
                continue
            tab.add_row([project,
                         key,
                         line[:p - 1],
                         line[p:]])

# Display the results
if tab.rowcount == 0:
    print('There is no work in progress.')
else:
    tab.field_names = ['Project', 'Page', 'Type', 'Action']
    for i in range(len(tab.field_names)):
        tab.align[tab.field_names[i]] = 'l'
    tab.header = True
    tab.border = True
    print(tab.get_string())
