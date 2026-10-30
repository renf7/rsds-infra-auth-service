"""Provision/verify only this public repository's public Sonar project; never log credentials."""
import base64
import json
import os
import http.client
import urllib.parse

KEY = os.environ['SONAR_PROJECT_KEY']
TOKEN = os.environ['SONAR_TOKEN']
if not TOKEN:
    raise SystemExit('SONAR_TOKEN is required')
HEADERS = {'Authorization': 'Basic ' + base64.b64encode((TOKEN + ':').encode()).decode()}


def call(path, parameters, post=False):
    data = urllib.parse.urlencode(parameters).encode()
    connection = http.client.HTTPSConnection('sonarcloud.io', timeout=30)
    try:
        connection.request('POST' if post else 'GET', path + ('' if post else '?' + data.decode()),
                           body=data if post else None,
                           headers={**HEADERS, 'Content-Type': 'application/x-www-form-urlencoded'})
        response = connection.getresponse()
        if response.status == 404:
            raise LookupError('Sonar project does not exist')
        if response.status >= 400:
            raise SystemExit(f'Sonar project API failed with HTTP {response.status}')
        return json.load(response) if response.getheader('Content-Type', '').startswith('application/json') else {}
    finally:
        connection.close()


try:
    component = call('/api/components/show', {'component': KEY})['component']
except LookupError:
    call('/api/projects/create', {'organization': 'renf7', 'project': KEY, 'name': KEY, 'visibility': 'public'}, True)
    component = call('/api/components/show', {'component': KEY})['component']
if component.get('visibility') != 'public':
    call('/api/projects/update_visibility', {'project': KEY, 'visibility': 'public'}, True)
if call('/api/components/show', {'component': KEY})['component'].get('visibility') != 'public':
    raise SystemExit('Sonar project is not public; refusing analysis')
print('Verified public Sonar project: ' + KEY)
