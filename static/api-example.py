#!/usr/bin/env python

from urllib.request import Request, urlopen
from urllib.parse import urlencode
import json

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
response = urlopen(Request(host + '/api/project/info/get',
                           urlencode({'project': project}).encode(),
                           headers=headers,
                           method='POST'))
if response.status == 200:
    data = response.read().decode('utf-8')
    jsonData = json.loads(data)
    for key in jsonData:
        # Do what you want with the result
        print('%s: %s' % (key, str(jsonData[key])[:64]))
