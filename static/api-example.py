#!/usr/bin/env python

from urllib.request import Request, urlopen
from urllib.parse import urlencode
import json

host = 'http://127.0.0.1:8080'
headers = {'Origin': host}

# Authentication
response = urlopen(Request(host + '/api/logon',
                           urlencode({'logon_user': 'your@user.name',
                                      'logon_password': 'your.password'}).encode(),
                           headers=headers,
                           method='POST'))
headers['Cookie'] = response.headers.get('Set-Cookie', '')

# Get some information
response = urlopen(Request(host + '/api/project/info/get',
                           urlencode({'info_project': 'your_project'}).encode(),
                           headers=headers,
                           method='POST'))
if response.status == 200:
    data = response.read().decode('utf-8')
    jsonData = json.loads(data)
    for key in jsonData:
        # Do what you want with the result
        print('%s: %s' % (key, str(jsonData[key])[:64]))
