#!/usr/bin/env python3
"""GitHub-wide secret sweep — code search for high-signal leak patterns.
Read-only OSINT. Aldri print fulle secrets — kun repo/path/format."""
import json, re, subprocess, sys, time, base64, urllib.request

QUERIPS = [
    'sb_secret_',
    'sbp_',
    'NGROK_AUTHTOKEN',
    'SUPABASE_SERVICE_ROLE_KEY=eyJ',
    'sk_live_',
    'xoxb-',
    'glpat-',
    'GOCSPX-',
    'AKIAIOSFODNN7EXAMPLE',  # placeholder check — skip actually
    'dop_v1_',
    'shpat_',
    'SG.',
    'lin_api_',
    'AuthKey_',
]

def gh(path):
    r = subprocess.run(['gh','api',path,'--paginate=false'],capture_output=True,text=True)
    if r.returncode!=0: return None
    try: return json.loads(r.stdout)
    except Exception: return None

def search(q):
    import urllib.parse
    return gh('search/code?q='+urllib.parse.quote(q)+'&per_page=50')

def fetch_file(repo,path):
    d=gh(f'repos/{repo}/contents/{repo and path}?ref=HEAD')
    return d

results=[]
for q in QUERIPS:
    if q=='AKIAIOSFODNN7EXAMPLE': continue
    d=search(q)
    if not d: print(f"[{q}] search failed",file=sys.stderr); time.sleep(6); continue
    items=d.get('items',[])
    print(f"[{q}] {d.get('total_count','?')} hits, showing {len(items)}")
    for it in items:
        repo=it['repository']['full_name']; path=it['path']
        results.append({'q':q,'repo':repo,'path':path,'html':it.get('html_url','')})
    time.sleep(6.5)  # 10/min code search

json.dump(results,open('/tmp/gh-sweep-hits.json','w'),indent=1)
print(f"\n{len(results)} hits -> /tmp/gh-sweep-hits.json")
