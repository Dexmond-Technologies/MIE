#!/usr/bin/env python3
"""Known-vulnerability check of the pinned third-party libraries (r-01 condition M-6).

    vuln_check.py <path to the vcpkg checkout at the pinned commit>

For every library in engine/third_party/pins.json:
  1. reads its version from the vcpkg port file of the pinned checkout,
  2. resolves the upstream release tag to a commit (git ls-remote),
  3. asks the OSV database (api.osv.dev) which known vulnerabilities affect that commit.
Fails (exit 1) when
  - a shipped library has a vulnerability that is not listed under accepted_vulnerabilities,
  - a version or commit differs from the recorded expected value,
  - a version, tag or answer cannot be obtained (unknown is not "no vulnerabilities").
A null expected value is reported as NOT YET RECORDED and does not fail; the printed
values are then copied into pins.json.
"""
import json
import os
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PINS = os.path.join(os.path.dirname(HERE), 'third_party', 'pins.json')
OSV_URL = 'https://api.osv.dev/v1/query'


def port_version(vcpkg, name, port_dir=None):
    # A library with a recipe of our own (an overlay port) is read from that recipe.
    path = (os.path.join(os.path.dirname(os.path.dirname(HERE)), port_dir, 'vcpkg.json') if port_dir
            else os.path.join(vcpkg, 'ports', name, 'vcpkg.json'))
    with open(path, encoding='utf-8') as f:
        port = json.load(f)
    for key in ('version', 'version-semver', 'version-string', 'version-date'):
        if key in port:
            return str(port[key]), port.get('port-version', 0)
    raise ValueError(f'no version field in the port file of {name}')


def tag_commit(repository, tag):
    out = subprocess.run(['git', 'ls-remote', repository, f'refs/tags/{tag}', f'refs/tags/{tag}^{{}}'],
                         capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise ValueError(f'git ls-remote failed for {repository}: {out.stderr.strip()}')
    plain = peeled = None
    for line in out.stdout.splitlines():
        sha, ref = line.split()
        if ref.endswith('^{}'):
            peeled = sha
        else:
            plain = sha
    commit = peeled or plain
    if not commit:
        raise ValueError(f'tag {tag} not found in {repository}')
    return commit


def osv_vulnerabilities(commit):
    ids, token = [], None
    for _ in range(20):
        body = {'commit': commit}
        if token:
            body['page_token'] = token
        request = urllib.request.Request(OSV_URL, data=json.dumps(body).encode('utf-8'),
                                         headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status != 200:
                raise ValueError(f'OSV answered HTTP {response.status}')
            answer = json.loads(response.read().decode('utf-8'))
        for vuln in answer.get('vulns', []):
            ids.append((vuln.get('id', '?'), vuln.get('summary', '')))
        token = answer.get('next_page_token')
        if not token:
            return ids
    raise ValueError('OSV answer has too many pages')


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    vcpkg = sys.argv[1]
    with open(PINS, encoding='utf-8') as f:
        pins = json.load(f)
    accepted = {entry['id'] for entry in pins.get('accepted_vulnerabilities', [])}
    failed = False

    for name, lib in pins['libraries'].items():
        try:
            version, port_revision = port_version(vcpkg, name, lib.get('port_dir'))
            tag = lib['tag'].format(version=version)
            commit = tag_commit(lib['repository'], tag)
            vulns = osv_vulnerabilities(commit)
        except (OSError, ValueError, KeyError) as e:
            print(f'FAIL  {name}: cannot be checked: {e}')
            failed = True
            continue

        print(f'{name}: version {version} (port revision {port_revision}), tag {tag}, commit {commit}')
        for key, value in (('expected_version', version), ('expected_commit', commit)):
            if lib.get(key) is None:
                print(f'      {key}: NOT YET RECORDED (record {value})')
            elif lib[key] != value:
                print(f'FAIL  {name}: {key} is {lib[key]} in pins.json but the pinned vcpkg gives {value}')
                failed = True
        open_vulns = [(i, s) for i, s in vulns if i not in accepted]
        if not vulns:
            print('      OSV: no known vulnerability for this commit')
        for vuln_id, summary in vulns:
            state = 'accepted' if vuln_id in accepted else 'OPEN'
            print(f'      OSV: {vuln_id} [{state}] {summary}')
        if open_vulns and lib.get('shipped', True):
            print(f'FAIL  {name}: {len(open_vulns)} known vulnerabilities not accepted')
            failed = True
        elif open_vulns:
            print(f'      {name} is not shipped (tests only): reported, not failing')

    print('RESULT:', 'FAIL' if failed else 'PASS')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
