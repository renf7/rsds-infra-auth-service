"""Provision/verify only this public repository's public Sonar project; never log credentials."""
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

KEY = os.environ['SONAR_PROJECT_KEY']
TOKEN = os.environ['SONAR_TOKEN']
BASE = 'https://sonarcloud.io'
if not TOKEN:
    raise SystemExit('SONAR_TOKEN is required')
HEADERS = {'Authorization': 'Basic ' + base64.b64encode((TOKEN + ':').encode()).decode()}


def call(path, parameters, post=False):
    data = urllib.parse.urlencode(parameters).encode()
    request = urllib.request.Request(BASE + path + ('' if post else '?' + data.decode()),
                                     data=data if post else None, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response) if response.headers.get('Content-Type', '').startswith('application/json') else {}


try:
    component = call('/api/components/show', {'component': KEY})['component']
except urllib.error.HTTPError as error:
    if error.code != 404:
        raise SystemExit(f'Sonar project lookup failed with HTTP {error.code}') from error
    call('/api/projects/create', {'organization': 'renf7', 'project': KEY, 'name': KEY, 'visibility': 'public'}, True)
    component = call('/api/components/show', {'component': KEY})['component']
if component.get('visibility') != 'public':
    call('/api/projects/update_visibility', {'project': KEY, 'visibility': 'public'}, True)
if call('/api/components/show', {'component': KEY})['component'].get('visibility') != 'public':
    raise SystemExit('Sonar project is not public; refusing analysis')
print('Verified public Sonar project: ' + KEY)
