import secrets
import time
from concurrent.futures import ThreadPoolExecutor
import pytest
from ruendrop.app import create_app, connect, digest, cleanup
from ruendrop.text import MAX_TEXT

ORIGIN={'Origin':'https://novachat.ruenitservices.com'}
@pytest.fixture
def env(tmp_path):
    app=create_app({'TESTING':True,'DATA_ROOT':str(tmp_path),'MIN_FREE':0})
    token=secrets.token_urlsafe(32)
    with connect(tmp_path/'ruendrop.db') as db:
        db.execute('INSERT INTO invite VALUES (1,?)',(digest(token),))
    c=app.test_client()
    response=c.post('/text/api/auth',json={'token':token},headers=ORIGIN)
    assert response.status_code==200
    assert all(v in response.headers['Set-Cookie'] for v in ('Secure','HttpOnly','SameSite=Strict','Path=/text/'))
    headers={**ORIGIN,'X-CSRF-Token':c.get('/text/api/session').json['csrf'],'Content-Type':'application/octet-stream'}
    return app,c,tmp_path,headers

def create(env,mode='24h'):
    app,c,root,headers=env
    receipt=secrets.token_urlsafe(32)
    payload=b'RT01'+secrets.token_bytes(120)
    r=c.post('/text/api/texts',data=payload,headers={**headers,'X-Text-Mode':mode,'X-Text-Receipt':digest(receipt)})
    assert r.status_code==201
    return r.json['id'],receipt,payload

def test_text_storage_expiry(env,monkeypatch):
    app,c,root,headers=env
    tid,receipt,payload=create(env)
    with connect(root/'ruendrop.db') as db:
        row=db.execute('SELECT * FROM texts WHERE id=?',(tid,)).fetchone()
        assert row['ciphertext']==payload and row['opened']==0
        assert row['expires']-row['created']==86400
        assert db.execute('PRAGMA encoding').fetchone()[0]=='UTF-8'
        assert row['receipt_hash']==digest(receipt)
    for _ in range(2):
        assert c.get('/text/api/texts/'+tid).data==payload
        assert c.post('/text/api/texts/'+tid+'/opened',json={'receipt':receipt},headers=ORIGIN).status_code==200
    monkeypatch.setattr('time.time',lambda:row['expires']-0.001)
    assert c.get('/text/api/texts/'+tid).status_code==200
    monkeypatch.setattr('time.time',lambda:row['expires'])
    assert c.get('/text/api/texts/'+tid).status_code==404
    cleanup(root)
    with connect(root/'ruendrop.db') as db:
        assert db.execute('SELECT count(*) FROM texts').fetchone()[0]==0

def test_burn_concurrency_and_wrong_receipt(env):
    app,c,root,headers=env
    tid,receipt,payload=create(env,'burn')
    route='/text/api/texts/'+tid
    assert c.post(route+'/opened',json={'receipt':secrets.token_urlsafe(32)},headers=ORIGIN).status_code==403
    assert c.get(route).data==payload
    def open_text(_):
        with app.test_client() as reader:
            return reader.post(route+'/opened',json={'receipt':receipt},headers=ORIGIN).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(open_text,range(2)))==[200,404]
    assert c.get(route).status_code==404
    with connect(root/'ruendrop.db') as db:
        row=db.execute('SELECT * FROM texts WHERE id=?',(tid,)).fetchone()
        assert row['opened']==1 and row['ciphertext'] is None and row['receipt_hash']==''
    assert payload not in (root/'ruendrop.db').read_bytes()

def test_access_limits_headers(env):
    app,c,root,headers=env
    tid,receipt,payload=create(env)
    h={**headers,'X-Text-Mode':'24h','X-Text-Receipt':digest(receipt)}
    outsider=app.test_client()
    assert outsider.post('/text/api/texts',data=payload,headers=h).status_code==401
    assert c.get('/drop/api/session').status_code==401
    assert c.post('/text/api/texts',data=payload,headers={**h,'X-CSRF-Token':'wrong'}).status_code==403
    assert c.post('/text/api/texts/'+tid+'/opened',json={'receipt':receipt}).status_code==403
    assert c.post('/text/api/texts',data=payload,headers={**h,'X-Text-Mode':'forever'}).status_code==400
    assert c.post('/text/api/texts',data=b'RT01'+b'x'*MAX_TEXT,headers=h).status_code==413
    app.config['TEXT_QUOTA']=1
    assert c.post('/text/api/texts',data=payload,headers=h).status_code==503
    for route in ('/text/','/text/t/'+tid,'/text/api/texts/'+tid,'/text/assets/text.js','/text/assets/absent'):
        r=c.get(route)
        assert r.headers['Cache-Control']=='no-store'
        assert r.headers['X-Robots-Tag']=='noindex, nofollow, noarchive'
    assert b'og:' not in c.get('/text/').data
    with connect(root/'ruendrop.db') as db: db.execute('DELETE FROM sessions')
    assert c.post('/text/api/texts',data=payload,headers=h).status_code==401

def test_text_admin(env,monkeypatch,capsys):
    from ruendrop.admin import main
    import sys
    app,c,root,headers=env
    tid,receipt,payload=create(env)
    monkeypatch.setenv('RUENDROP_DATA',str(root))
    monkeypatch.setattr('ruendrop.admin.os.geteuid',lambda:0)
    monkeypatch.setattr(sys,'argv',['ruendrop','text-list']); main()
    output=capsys.readouterr().out
    assert tid in output and receipt not in output and 'available' in output
    monkeypatch.setattr(sys,'argv',['ruendrop','text-revoke',tid]); main(); main()
    assert c.get('/text/api/texts/'+tid).status_code==404
    monkeypatch.setattr(sys,'argv',['ruendrop','text-revoke','../bad'])
    with pytest.raises(SystemExit): main()

def test_text_rate_limit(env):
    app,c,root,headers=env
    for _ in range(30): create(env)
    receipt=secrets.token_urlsafe(32)
    assert c.post('/text/api/texts',data=b'RT01'+secrets.token_bytes(40),headers={**headers,'X-Text-Mode':'burn','X-Text-Receipt':digest(receipt)}).status_code==429

def test_shared_invite_rotation(env,monkeypatch,capsys):
    from ruendrop.admin import main
    import sys
    app,c,root,headers=env
    tid,_,payload=create(env)
    monkeypatch.setenv('RUENDROP_DATA',str(root))
    monkeypatch.setenv('RUENDROP_INVITE_FILE',str(root/'admin'/'invite'))
    monkeypatch.setattr('ruendrop.admin.os.geteuid',lambda:0)
    monkeypatch.setattr(sys,'argv',['ruendrop','rotate-url']);main()
    drop_url=capsys.readouterr().out.strip()
    monkeypatch.setattr(sys,'argv',['ruendrop','text-show-url']);main()
    assert capsys.readouterr().out.strip()==drop_url.replace('/drop/','/text/')
    assert c.get('/text/api/session').status_code==401
    assert c.get('/text/api/texts/'+tid).data==payload
    assert c.post('/text/api/auth',json={'token':drop_url.split('#')[1]},headers=ORIGIN).status_code==200
