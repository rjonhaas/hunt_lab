#!/usr/bin/env python3
"""Build a private Caldera reference package. Import never starts an operation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request
import uuid

NAMESPACE = uuid.UUID('3cf0c982-7ca2-43fc-98e6-d5d54143ebe9')

def validate(config):
    if set(config) != {'run_label', 'discovery_flag', 'staging_flag'}:
        raise ValueError('Expected run_label, discovery_flag, staging_flag only')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', config['run_label']):
        raise ValueError('run_label must be 1–40 lowercase letters, digits or hyphens')
    for key in ('discovery_flag', 'staging_flag'):
        if not re.fullmatch(r'\{[A-Za-z0-9_-]{1,80}\}', config[key]):
            raise ValueError('Flags must use {flag} format with 1–80 letters, digits, underscores or hyphens inside the braces')
    if config['discovery_flag'] == config['staging_flag']:
        raise ValueError('Flags must differ')

def build(config):
    validate(config)
    run = config['run_label']
    # Configuration-specific IDs prevent one student's import overwriting another.
    fingerprint = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    def uid(label):
        return str(uuid.uuid5(NAMESPACE, fingerprint + ':' + label))
    root = 'C:\\WarWagonTraining\\' + run
    staging = ("$ErrorActionPreference='Stop'; "
        f"$root='{root}'; "
        "if(Test-Path -LiteralPath $root){throw 'Run directory exists; choose a fresh run_label'}; "
        "New-Item -ItemType Directory -Path $root | Out-Null; "
        "$source=Join-Path $root 'synthetic-source.txt'; "
        "Set-Content -LiteralPath $source -Value 'Synthetic War Wagon training document. No real data.'; "
        "$destDir=Join-Path $root 'staging'; New-Item -ItemType Directory -Path $destDir | Out-Null; "
        f"$dest=Join-Path $destDir '{config['staging_flag']}.txt'; "
        "Copy-Item -LiteralPath $source -Destination $dest; "
        "if((Get-FileHash $source).Hash -ne (Get-FileHash $dest).Hash){throw 'Copy verification failed'}; "
        "Write-Output 'Synthetic staging verified'")
    rows = [
        ('user', 'Discover current user', 'T1033', 'System Owner/User Discovery',
         f'cmd.exe /d /c "echo {config["discovery_flag"]} & whoami.exe"'),
        ('host', 'Discover computer name', 'T1082', 'System Information Discovery', 'hostname.exe'),
        ('network', 'Discover network configuration', 'T1016', 'System Network Configuration Discovery', 'ipconfig.exe /all'),
        ('staging', 'Stage a synthetic document', 'T1074.001', 'Local Data Staging', staging),
    ]
    abilities = []
    for slug, name, tid, technique, command in rows:
        abilities.append({
            'ability_id': uid(slug), 'name': f'WW-TRAIN-001 {run}: {name}',
            'description': 'Synthetic workshop reference; review before use. No real user data.',
            'tactic': 'collection' if slug == 'staging' else 'discovery',
            'technique_id': tid, 'technique_name': technique,
            'executors': [{'name':'psh','platform':'windows','command':command,
                           'timeout':60,'payloads':[],'uploads':[],'parsers':[],
                           'cleanup':[],'variations':[]}],
            'requirements':[], 'privilege':'', 'repeatable':False,
            'singleton':True, 'additional_info':{}, 'tags':['war-wagon','WW-TRAIN-001'],
        })
    adversary = {'adversary_id':uid('profile'), 'name':f'WW-TRAIN-001 {run}',
                 'description':'Discovery before synthetic local staging. Single lab target only.',
                 'atomic_ordering':[a['ability_id'] for a in abilities]}
    return {'schema_version':1,'report':'WW-TRAIN-001','run_label':run,
            'abilities':abilities,'adversary':adversary}

def api(url, key, method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url.rstrip('/')+'/api/v2/'+path, data=data,
          headers={'KEY':key,'Content-Type':'application/json'}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        # Do not echo API bodies, which may contain flags or commands.
        raise RuntimeError(f'Caldera {method} {path} returned HTTP {e.code}') from None

def import_package(package, url, key):
    existing_a = {a['ability_id']:a for a in api(url,key,'GET','abilities')}
    existing_p = {a['adversary_id']:a for a in api(url,key,'GET','adversaries')}
    # Refuse collisions before mutating anything. Use a fresh run label for reruns.
    if any(a['ability_id'] in existing_a for a in package['abilities']) or package['adversary']['adversary_id'] in existing_p:
        raise ValueError('Package IDs already exist; inspect existing objects or use a new run_label')
    for a in package['abilities']:
        api(url,key,'POST','abilities',a)
        check=api(url,key,'GET','abilities/'+a['ability_id'])
        if not any(e.get('command') == a['executors'][0]['command'] for e in check['executors']):
            raise RuntimeError('Ability read-back did not match; stop and inspect partial import')
    adv=package['adversary']
    api(url,key,'POST','adversaries',adv)
    check=api(url,key,'GET','adversaries/'+adv['adversary_id'])
    if check['atomic_ordering'] != adv['atomic_ordering']:
        raise RuntimeError('Profile read-back did not match')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',required=True,type=Path)
    p.add_argument('--out',required=True,type=Path)
    p.add_argument('--import',dest='do_import',action='store_true')
    args=p.parse_args()
    package=build(json.loads(args.config.read_text()))
    repo=Path(__file__).resolve().parents[3]
    if args.out.resolve().is_relative_to(repo):
        p.error('Write generated packages outside the Git checkout (they contain flags)')
    args.out.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(args.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump(package,f,indent=2)
    print('Package written; four reference abilities. No operation started.')
    if args.do_import:
        url=os.environ.get('CALDERA_URL')
        key=os.environ.get('CALDERA_API_KEY')
        if not url or not key:p.error('Set CALDERA_URL and CALDERA_API_KEY for import')
        import_package(package,url,key)
        print('Import and read-back verified. No operation created or started.')

if __name__=='__main__':
    main()
