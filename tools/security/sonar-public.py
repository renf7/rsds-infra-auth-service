"""Provision/verify only this public repository's public Sonar project; never log credentials."""
import base64
import os
import requests

KEY = os.environ['SONAR_PROJECT_KEY']
TOKEN = os.environ['SONAR_TOKEN']
if not TOKEN:
    raise SystemExit('SONAR_TOKEN is required')
HEADERS = {'Authorization': 'Basic ' + base64.b64encode((TOKEN + ':').encode()).decode()}


def call(path, parameters, post=False):
    with requests.request('POST' if post else 'GET', 'https://sonarcloud.io' + path,
                          params=None if post else parameters, data=parameters if post else None,
                          headers=HEADERS, timeout=30, allow_redirects=False) as response:
        if response.status_code == 404:
            raise LookupError('Sonar project does not exist')
        if not 200 <= response.status_code < 300:
            raise SystemExit(f'Sonar project API failed with HTTP {response.status_code}')
        return response.json() if response.headers.get('Content-Type', '').startswith('application/json') else {}


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
