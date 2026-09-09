"""Run as root on the deployment host. Never prints invite URLs or cookies.
Creates and expires only its own test record. Manually rotates the invite once.
"""
import http.client
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import time

origin=os.environ.get('RUENDROP_ORIGIN','https://novachat.ruenitservices.com')
root=Path(os.environ.get('RUENDROP_DATA','/var/lib/ruendrop'))
def request(method,path,body=None,headers=None):
    conn=http.client.HTTPConnection('127.0.0.1',8787,timeout=20)
    conn.request(method,path,body,headers or {})
    response=conn.getresponse()
    result=(response.status,dict(response.getheaders()),response.read())
    conn.close()
    return result

def auth(token):
    status,headers,body=request('POST','/drop/api/auth',json.dumps({'token':token}),{'Origin':origin,'Content-Type':'application/json'})
    assert status==200,status
    return headers['Set-Cookie'].split(';')[0]

def main():
    assert os.geteuid()==0
    url=subprocess.check_output(['ruendrop','show-url'],text=True).strip()
    token=url.split('#')[1]
    status,headers,body=request('GET','/drop/')
    assert status==200 and b'Select Photo' not in body
    cookie=auth(token)
    status,headers,body=request('GET','/drop/api/session',headers={'Cookie':cookie})
    csrf=json.loads(body)['csrf']
    headers={'Cookie':cookie,'X-CSRF-Token':csrf,'Origin':origin,'Content-Type':'application/octet-stream'}
    assert request('POST','/drop/api/photos',b'not an image',headers)[0]==400
    assert request('POST','/drop/api/photos',None,{**headers,'Content-Length':str(7*1024*1024)})[0]==413
    # Envelope validation only: the server deliberately cannot inspect plaintext.
    payload=b'RD01'+secrets.token_bytes(128)
    status,_,body=request('POST','/drop/api/photos',payload,headers)
    assert status==201,status
    pid=json.loads(body)['id']
    assert (root/'data'/pid).read_bytes()==payload
    with sqlite3.connect(root/'ruendrop.db') as db:
        created,expires=db.execute('SELECT created,expires FROM photos WHERE id=?',(pid,)).fetchone()
        assert expires-created==86400
    new_url=subprocess.check_output(['ruendrop','rotate-url'],text=True).strip()
    assert new_url!=url
    assert subprocess.check_output(['ruendrop','show-url'],text=True).strip()==new_url
    assert request('GET','/drop/api/session',headers={'Cookie':cookie})[0]==401
    assert request('POST','/drop/api/auth',json.dumps({'token':token}),{'Origin':origin,'Content-Type':'application/json'})[0]==403
    auth(new_url.split('#')[1])
    assert request('GET','/drop/api/photos/'+pid)[2]==payload
    with sqlite3.connect(root/'ruendrop.db') as db:
        db.execute('UPDATE photos SET expires=? WHERE id=?',(time.time()-1,pid))
    assert request('GET','/drop/api/photos/'+pid)[0]==404
    assert request('GET','/drop/p/'+pid)[0]==404
    subprocess.run(['systemctl','start','ruendrop-cleanup.service'],check=True)
    assert not (root/'data'/pid).exists()
    with sqlite3.connect(root/'ruendrop.db') as db:
        assert not db.execute('SELECT 1 FROM photos WHERE id=?',(pid,)).fetchone()
    print('PASS: deployed access controls, upload/envelope checks, private storage, 24h expiry, cleanup, real CLI rotation/show, old invite/session revocation, existing share survival.')

if __name__=='__main__': main()
