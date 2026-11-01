#!/usr/bin/env python3
"""Verify both markers and file/process correlation in indexed endpoint evidence."""
import argparse
import base64
import json
import os
from pathlib import Path
import urllib.request
import build


def verify(config, host, start, end, url, user, password):
    build.validate(config)
    auth=base64.b64encode((user+':'+password).encode()).decode()
    def search(filters):
        body={'size':5000,'track_total_hits':True,'query':{'bool':{'filter':filters}}}
        req=urllib.request.Request(url.rstrip('/')+'/logs-*/_search',data=json.dumps(body).encode(),
            headers={'Authorization':'Basic '+auth,'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=30) as r:data=json.load(r)
        if data.get('timed_out') or data.get('_shards',{}).get('failed',0):
            raise RuntimeError('Search incomplete')
        if data['hits']['total']['value']>5000:
            raise RuntimeError('Too many events; narrow the evidence window')
        return data['hits']['hits']
    common=[{'term':{'host.name':host}}, {'term':{'data_stream.dataset':'windows.sysmon_operational'}},
            {'range':{'@timestamp':{'gte':start,'lte':end}}}]
    hits=search(common+[{'terms':{'event.code':['1','11']}}])
    discovery=[];files=[];processes={}
    expected='C:\\WarWagonTraining\\'+config['run_label']+'\\staging\\'+config['staging_flag']+'.txt'
    for h in hits:
        s=h['_source'];event=str(s.get('event',{}).get('code',''));proc=s.get('process',{})
        if event=='1':
            if proc.get('entity_id'):processes[proc['entity_id']]=h
            if config['discovery_flag'] in proc.get('command_line',''):
                discovery.append(h)
        if event=='11' and s.get('file',{}).get('path','').lower()==expected.lower():files.append(h)
    correlated=[(f,processes[f['_source'].get('process',{}).get('entity_id')]) for f in files
                if f['_source'].get('process',{}).get('entity_id') in processes]
    def ref(h):
        s=h['_source'];return {'index':h['_index'],'id':h['_id'],'timestamp':s['@timestamp'],
                              'event_code':s['event']['code'],'process_entity_id':s.get('process',{}).get('entity_id')}
    return {'host':host,'start':start,'end':end,'discovery_verified':bool(discovery),
            'staging_verified':bool(correlated),'discovery_events':[ref(h) for h in discovery],
            'staging_correlations':[{'file':ref(f),'creator':ref(c)} for f,c in correlated]}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['config','host','start','end']:p.add_argument('--'+name,required=True)
    a=p.parse_args()
    result=verify(json.loads(Path(a.config).read_text()),a.host,a.start,a.end,
                  os.environ['ELASTICSEARCH_URL'],os.environ.get('ELASTIC_USER','elastic'),os.environ['ELASTIC_PASSWORD'])
    print(json.dumps(result,indent=2))
    raise SystemExit(0 if result['discovery_verified'] and result['staging_verified'] else 1)

if __name__=='__main__':main()
