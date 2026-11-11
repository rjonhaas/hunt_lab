#!/usr/bin/env python3
"""Preload and verify the workshop profile; never create or start operations."""
import json
import os
from pathlib import Path
import sys
from build import api, build

ROOT = Path(__file__).resolve().parents[3]

def configuration():
    private = ROOT / '.war-wagon' / 'config.json'
    path = private if private.exists() else Path(__file__).with_name('practice.json')
    return json.loads(path.read_text(encoding='utf-8-sig'))

def equivalent(actual, wanted, kind):
    if kind == 'adversaries':
        return (actual.get('name') == wanted['name'] and
                actual.get('atomic_ordering') == wanted['atomic_ordering'])
    fields = ('name', 'platform', 'command', 'cleanup')
    def executors(obj):
        return [{k: e.get(k, [] if k == 'cleanup' else None) for k in fields}
                for e in obj.get('executors', [])]
    return actual.get('name') == wanted['name'] and executors(actual) == executors(wanted)

def ensure_package(package, url, key):
    groups = [('abilities', 'ability_id', package['abilities']),
              ('adversaries', 'adversary_id', [package['adversary']])]
    # Inspect all collisions before any writes. Reuse matching objects only.
    existing = {}
    for kind, id_key, wanted in groups:
        existing[kind] = {obj[id_key]: obj for obj in api(url, key, 'GET', kind)}
        for obj in wanted:
            found = existing[kind].get(obj[id_key])
            if found is not None and not equivalent(found, obj, kind):
                raise RuntimeError('Existing workshop object differs; inspect it or use a new run_label. Nothing overwritten.')
    for kind, id_key, wanted in groups:
        for obj in wanted:
            if obj[id_key] not in existing[kind]:
                api(url, key, 'POST', kind, obj)
            found = api(url, key, 'GET', kind + '/' + obj[id_key])
            if not equivalent(found, obj, kind):
                raise RuntimeError('Workshop read-back mismatch; inspect partial import before proceeding.')

def main():
    package = build(configuration())
    ensure_package(package, os.environ.get('CALDERA_URL', 'http://caldera:8888'),
                   os.environ.get('CALDERA_API_KEY', 'ADMIN123'))
    print('Verified four workshop abilities and profile: ' + package['adversary']['name'])
    print('No operation created or started.')

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Do not expose configurations, commands, flags or remote response bodies.
        print('Workshop preload failed (' + type(exc).__name__ + '). Check configuration and Caldera; no operation started.', file=sys.stderr)
        sys.exit(1)
