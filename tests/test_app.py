import secrets
import time
from pathlib import Path
import pytest
from ruendrop.app import create_app, connect, digest, cleanup, MAX_PAYLOAD

@pytest.fixture
def env(tmp_path):
    app=create_app({'TESTING':True,'DATA_ROOT':str(tmp_path),'MIN_FREE':0})
    token=secrets.token_urlsafe(32)
    with connect(tmp_path/'ruendrop.db') as db:
        db.execute('INSERT INTO invite VALUES (1,?)',(digest(token),))
    return app,app.test_client(),tmp_path,token

ORIGIN={'Origin':'https://novachat.ruenitservices.com'}
def authorize(client,token):
    r=client.post('/drop/api/auth',json={'token':token},headers=ORIGIN)
    assert r.status_code==200
    assert all(x in r.headers['Set-Cookie'] for x in ('Secure','HttpOnly','SameSite=Strict','Path=/drop/'))
    return {**ORIGIN,'X-CSRF-Token':client.get('/drop/api/session').json['csrf'],'Content-Type':'application/octet-stream'}

def test_access_and_security(env):
    app,c,root,token=env
    assert b'Select Photo' not in c.get('/drop/').data
    assert c.post('/drop/api/auth',json={'token':'invalid'},headers=ORIGIN).status_code==403
    assert c.post('/drop/api/auth',json={'token':token}).status_code==403
    headers=authorize(c,token)
    assert b'Select Photo' in c.get('/drop/').data
    assert c.post('/drop/api/photos',data=b'RD01'+secrets.token_bytes(128),headers=ORIGIN).status_code==403
    r=c.get('/drop/')
    assert "frame-ancestors 'none'" in r.headers['Content-Security-Policy']
    assert r.headers['Referrer-Policy']=='no-referrer'

def test_storage_expiry_cleanup_and_rotation(env):
    app,c,root,token=env
    headers=authorize(c,token)
    payload=b'RD01'+secrets.token_bytes(512)
    r=c.post('/drop/api/photos',data=payload,headers=headers)
    assert r.status_code==201
    pid=r.json['id']
    assert (root/'data'/pid).read_bytes()==payload
    with connect(root/'ruendrop.db') as db:
        row=db.execute('SELECT * FROM photos').fetchone()
        assert row['expires']-row['created']==86400
        db.execute('UPDATE invite SET hash=?',(digest(secrets.token_urlsafe(32)),))
        db.execute('DELETE FROM sessions')
    assert c.get('/drop/api/session').status_code==401
    assert c.post('/drop/api/auth',json={'token':token},headers=ORIGIN).status_code==403
    assert c.get('/drop/api/photos/'+pid).data==payload
    with connect(root/'ruendrop.db') as db:
        db.execute('UPDATE photos SET expires=?',(time.time()-1,))
    assert c.get('/drop/api/photos/'+pid).status_code==404
    assert c.get('/drop/p/'+pid).status_code==404
    cleanup(root)
    assert not (root/'data'/pid).exists()
    with connect(root/'ruendrop.db') as db:
        assert db.execute('SELECT count(*) FROM photos').fetchone()[0]==0

def test_limits_and_rejections(env):
    app,c,root,token=env
    headers=authorize(c,token)
    assert c.post('/drop/api/photos',data=b'not a photo',headers=headers).status_code==400
    assert c.post('/drop/api/photos',data=b'x'*(MAX_PAYLOAD+1),headers=headers).status_code==413
    app.config['QUOTA']=10
    assert c.post('/drop/api/photos',data=b'RD01'+secrets.token_bytes(100),headers=headers).status_code==503
    app.config['QUOTA']=1024**3
    app.config['MIN_FREE']=10**20
    assert c.post('/drop/api/photos',data=b'RD01'+secrets.token_bytes(100),headers=headers).status_code==503
    assert not list((root/'data').iterdir())

def test_rate_limit(env):
    app,c,root,token=env
    for _ in range(10):
        assert c.post('/drop/api/auth',json={'token':'bad'},headers=ORIGIN).status_code==403
    assert c.post('/drop/api/auth',json={'token':'bad'},headers=ORIGIN).status_code==429

def test_real_admin_rotation(env,monkeypatch,capsys):
    import sys
    from ruendrop.admin import main
    app,c,root,token=env
    monkeypatch.setenv('RUENDROP_DATA',str(root))
    monkeypatch.setenv('RUENDROP_INVITE_FILE',str(root/'admin'/'invite'))
    monkeypatch.setattr('ruendrop.admin.os.geteuid',lambda:0)
    headers=authorize(c,token)
    payload=b'RD01'+secrets.token_bytes(60)
    pid=c.post('/drop/api/photos',data=payload,headers=headers).json['id']
    monkeypatch.setattr(sys,'argv',['ruendrop','rotate-url'])
    main()
    url=capsys.readouterr().out.strip()
    new_token=url.split('#')[1]
    assert new_token!=token and len(new_token)==43
    assert (root/'admin'/'invite').stat().st_mode&0o777==0o600
    assert c.get('/drop/api/session').status_code==401
    assert c.post('/drop/api/auth',json={'token':token},headers=ORIGIN).status_code==403
    authorize(c,new_token)
    assert c.get('/drop/api/photos/'+pid).data==payload
    monkeypatch.setattr(sys,'argv',['ruendrop','show-url'])
    main()
    assert capsys.readouterr().out.strip()==url

def test_twenty_mib_drop_boundary(env):
    app,c,root,token=env
    headers=authorize(c,token)
    payload=b'RD01'+b'x'*(20*1024*1024-4)
    r=c.post('/drop/api/photos',data=payload,headers=headers)
    assert r.status_code==201
    assert c.get('/drop/api/photos/'+r.json['id']).data==payload
    assert c.post('/drop/api/photos',data=payload+b'x',headers=headers).status_code==413

def test_revoke_drop(env,monkeypatch,capsys):
    import sys
    from ruendrop.admin import main
    app,c,root,token=env
    headers=authorize(c,token)
    payload=b'RD01'+secrets.token_bytes(128)
    ids=[c.post('/drop/api/photos',data=payload,headers=headers).json['id'] for _ in range(2)]
    monkeypatch.setenv('RUENDROP_DATA',str(root))
    monkeypatch.setattr(sys,'argv',['ruendrop','revoke-drop',ids[0]])
    monkeypatch.setattr('ruendrop.admin.os.geteuid',lambda:1000)
    monkeypatch.setenv('RUENDROP_ADMIN_TEST','1')
    with pytest.raises(SystemExit,match='sudo'): main()
    assert c.get('/drop/api/photos/'+ids[0]).status_code==200
    monkeypatch.setattr('ruendrop.admin.os.geteuid',lambda:0)
    main()
    assert not (root/'data'/ids[0]).exists()
    with connect(root/'ruendrop.db') as db:
        assert not db.execute('SELECT 1 FROM photos WHERE id=?',(ids[0],)).fetchone()
    for route in ('/drop/p/','/drop/api/photos/'):
        response=c.get(route+ids[0])
        assert response.status_code==404
        assert response.headers['Cache-Control']=='no-store'
        assert response.headers['X-Robots-Tag']=='noindex, nofollow, noarchive'
    assert c.get('/drop/api/photos/'+ids[1]).data==payload
    assert c.get('/drop/api/session').status_code==200
    main()  # Safe to repeat.
    monkeypatch.setattr(sys,'argv',['ruendrop','revoke-drop','../ruendrop.db'])
    with pytest.raises(SystemExit): main()
    assert (root/'ruendrop.db').exists()

def test_privacy_headers(env):
    _,c,_,token=env
    for path in ('/drop/','/drop/p/'+'A'*43,'/drop/api/photos/'+'A'*43,'/drop/assets/logo.png'):
        r=c.get(path)
        assert r.headers['X-Robots-Tag']=='noindex, nofollow, noarchive'
        assert r.headers['Cache-Control']=='no-store'
    authorize(c,token)
    r=c.get('/drop/')
    assert r.headers['X-Robots-Tag']=='noindex, nofollow, noarchive'
    assert b'og:' not in r.data and b'twitter:' not in r.data
