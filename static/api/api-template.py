#!/usr/bin/env python

from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import URLError, HTTPError
import json

# Changeable configuration
host = 'http://127.0.0.1:8080'
user = 'your@user.name'
password = 'your.password'
project = 'your_project'

# Authentication
headers = {'Origin': host}
try:
    response = urlopen(Request(host + '/api/login',
                               urlencode({'user': user,
                                          'password': password}).encode(),
                               headers=headers,
                               method='POST'))
except (URLError, HTTPError) as e:
    if isinstance(e, HTTPError):
        print('Error: %d %s' % (e.getcode(), e.reason))
    else:
        print(e.reason)
    exit(1)
headers['Cookie'] = response.headers.get('Set-Cookie', '')

# Retrieve the data
try:
    response = urlopen(Request(host + '/api/project/info/get',
                               urlencode({'project': project}).encode(),
                               headers=headers,
                               method='POST'))
except HTTPError as e:
    print('Error: %d %s' % (e.getcode(), e.reason))
    exit(1)

# Read the output
print('Do what you want with the result in JSON format:')
data = response.read().decode('utf-8')
jsonData = json.loads(data)
for key in jsonData:
    print('> %s: %s...' % (key, str(jsonData[key])[:96]))
