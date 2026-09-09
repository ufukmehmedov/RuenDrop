"""Ciphertext-only storage. No request bodies, URLs or credentials are logged."""
import hashlib
import hmac
import os
import re
import secrets
import shutil
import sqlite3
import time
from pathlib import Path
from flask import Flask, request, jsonify, make_response, abort, g
from werkzeug.exceptions import HTTPException

ROOT = Path(__file__).parent
TOKEN = re.compile(r'^[A-Za-z0-9_-]{43}$')
MAX_PAYLOAD = 20 * 1024 * 1024
TTL = 86400

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def connect(path):
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA secure_delete=ON')
    return db

def initialize(root):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    (root / 'data').mkdir(mode=0o700, exist_ok=True)
    with connect(root / 'ruendrop.db') as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS invite (id INTEGER PRIMARY KEY CHECK(id=1), hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS photos (id TEXT PRIMARY KEY, size INTEGER NOT NULL, created REAL NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS limits (bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, expires REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS photo_expiry ON photos(expires);
        ''')

def cleanup(root):
    now = time.time()
    with connect(root / 'ruendrop.db') as db:
        db.execute('BEGIN IMMEDIATE')
        for row in db.execute('SELECT id FROM photos WHERE expires<=?', (now,)):
            (root / 'data' / row['id']).unlink(missing_ok=True)
        db.execute('DELETE FROM photos WHERE expires<=?', (now,))
        db.execute('DELETE FROM sessions WHERE expires<=?', (now,))
        db.execute('DELETE FROM limits WHERE expires<=?', (now,))
        known = {r[0] for r in db.execute('SELECT id FROM photos')}
        for path in (root / 'data').iterdir():
            if path.name not in known:
                path.unlink()

def create_app(config=None):
    app = Flask(__name__, static_folder=None)
    app.config.update(DATA_ROOT=os.environ.get('RUENDROP_DATA', '/var/lib/ruendrop'),
                      ORIGIN=os.environ.get('RUENDROP_ORIGIN', 'https://novachat.ruenitservices.com'),
                      MAX_CONTENT_LENGTH=MAX_PAYLOAD, QUOTA=1024**3, MIN_FREE=2*1024**3,
                      MAX_PHOTOS=10000, DAILY_EGRESS=2*1024**3)
    if config:
        app.config.update(config)
    root = Path(app.config['DATA_ROOT'])
    initialize(root)

    def db():
        if 'db' not in g:
            g.db = connect(root / 'ruendrop.db')
        return g.db

    @app.teardown_appcontext
    def close(_):
        if 'db' in g:
            g.db.close()

    def limit(bucket, maximum, seconds, amount=1):
        now = time.time()
        c = db()
        c.execute('BEGIN IMMEDIATE')
        c.execute('DELETE FROM limits WHERE expires<=?', (now,))
        row = c.execute('SELECT count FROM limits WHERE bucket=?', (bucket,)).fetchone()
        if row and row[0] + amount > maximum:
            c.rollback()
            abort(429)
        if not row:
            if c.execute('SELECT count(*) FROM limits').fetchone()[0] >= 20000:
                c.rollback()
                abort(503)
            c.execute('INSERT INTO limits VALUES (?,?,?)', (bucket, amount, now+seconds))
        else:
            c.execute('UPDATE limits SET count=count+? WHERE bucket=?', (amount,bucket))
        c.commit()

    def session():
        raw = request.cookies.get('__Secure-ruendrop', '')
        return db().execute('SELECT * FROM sessions WHERE hash=? AND expires>?',
                            (digest(raw), time.time())).fetchone() if TOKEN.fullmatch(raw) else None

    @app.before_request
    def guard():
        ip = request.headers.get('X-Real-IP', request.remote_addr or '')
        limit('ip:'+digest(ip), 180, 60)
        if request.method == 'POST':
            if request.headers.get('Origin') != app.config['ORIGIN']:
                abort(403)
            if request.path != '/drop/api/auth':
                g.auth = session()
                if not g.auth:
                    abort(401)
                if not hmac.compare_digest(request.headers.get('X-CSRF-Token',''), g.auth['csrf']):
                    abort(403)

    @app.after_request
    def headers(response):
        response.headers.update({
            'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
            'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer',
            'X-Frame-Options':'DENY', 'Cache-Control':'no-store',
            'X-Robots-Tag':'noindex, nofollow, noarchive',
            'Permissions-Policy':'camera=(), microphone=(), geolocation=()'})
        return response

    @app.errorhandler(HTTPException)
    def error(err):
        return jsonify(error={401:'Open your private invite link to continue.',403:'Access denied.',404:'Photo expired or not found.',413:'Photo is too large.',429:'Please try again later.',503:'Storage is temporarily full.'}.get(err.code,'Request rejected.')), err.code

    def page(name):
        return make_response((ROOT/'static'/name).read_text(), 200, {'Content-Type':'text/html; charset=utf-8'})

    @app.get('/drop/')
    def index():
        return page('upload.html' if session() else 'locked.html')

    @app.get('/drop/assets/<name>')
    def asset(name):
        if name in ('logo.png','favicon-32.png','icon-192.png'):
            return make_response((ROOT/'static'/name).read_bytes(),200,{'Content-Type':'image/png'})
        if name not in ('app.js','photo.js','image.js','style.css','auth.js'):
            abort(404)
        return make_response((ROOT/'static'/name).read_text(),200,{'Content-Type':'text/css' if name.endswith('.css') else 'text/javascript'})

    @app.post('/drop/api/auth')
    def auth():
        limit('auth:'+digest(request.headers.get('X-Real-IP',request.remote_addr or '')),10,600)
        if request.content_length is None or request.content_length > 128:
            abort(413)
        body = request.get_json(silent=True)
        if not isinstance(body,dict):
            abort(400)
        token = body.get('token','')
        if not isinstance(token,str) or not TOKEN.fullmatch(token):
            abort(403)
        c = db()
        c.execute('BEGIN IMMEDIATE')
        row = c.execute('SELECT hash FROM invite WHERE id=1').fetchone()
        if not row or not hmac.compare_digest(row[0],digest(token)):
            c.rollback()
            abort(403)
        c.execute('DELETE FROM sessions WHERE expires<=?',(time.time(),))
        if c.execute('SELECT count(*) FROM sessions').fetchone()[0]>=1000:
            c.rollback()
            abort(429)
        raw = secrets.token_urlsafe(32)
        c.execute('INSERT INTO sessions VALUES (?,?,?)',(digest(raw),secrets.token_urlsafe(32),time.time()+TTL))
        c.commit()
        response = jsonify(ok=True)
        response.set_cookie('__Secure-ruendrop',raw,max_age=TTL,secure=True,httponly=True,samesite='Strict',path='/drop/')
        return response

    @app.get('/drop/api/session')
    def get_session():
        row = session()
        if not row:
            abort(401)
        return jsonify(csrf=row['csrf'])

    @app.post('/drop/api/photos')
    def upload():
        limit('uploads:'+g.auth['hash'],30,3600)
        if request.content_type != 'application/octet-stream':
            abort(415)
        if not request.content_length or request.content_length>MAX_PAYLOAD:
            abort(413)
        payload = request.get_data()
        if len(payload)<33 or payload[:4]!=b'RD01':
            abort(400)
        c=db()
        c.execute('BEGIN IMMEDIATE')
        # Recheck under the same write lock as rotation so revocation is immediate.
        if not c.execute('SELECT 1 FROM sessions WHERE hash=? AND expires>?',(g.auth['hash'],time.time())).fetchone():
            c.rollback()
            abort(401)
        size,count=c.execute('SELECT coalesce(sum(size),0),count(*) FROM photos').fetchone()
        if size+len(payload)>app.config['QUOTA'] or count>=app.config['MAX_PHOTOS'] or shutil.disk_usage(root).free-len(payload)<app.config['MIN_FREE']:
            c.rollback()
            abort(503)
        photo_id=secrets.token_urlsafe(32)
        path=root/'data'/photo_id
        try:
            with path.open('xb') as f:
                os.chmod(path,0o600)
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            now=time.time()
            c.execute('INSERT INTO photos VALUES (?,?,?,?)',(photo_id,len(payload),now,now+TTL))
            c.commit()
        except Exception:
            c.rollback()
            path.unlink(missing_ok=True)
            raise
        return jsonify(id=photo_id,expires_at=now+TTL),201

    def photo_row(photo_id):
        if not TOKEN.fullmatch(photo_id):
            abort(404)
        row=db().execute('SELECT * FROM photos WHERE id=? AND expires>?',(photo_id,time.time())).fetchone()
        if not row:
            abort(404)
        return row

    @app.get('/drop/p/<photo_id>')
    def photo_page(photo_id):
        try:
            photo_row(photo_id)
        except HTTPException:
            return page('expired.html'),404
        return page('photo.html')

    @app.get('/drop/api/photos/<photo_id>')
    def download(photo_id):
        row=photo_row(photo_id)
        limit('egress',app.config['DAILY_EGRESS'],86400,row['size'])
        try:
            payload=(root/'data'/photo_id).read_bytes()
        except FileNotFoundError:
            abort(404)
        if row['expires']<=time.time():
            abort(404)
        return make_response(payload,200,{'Content-Type':'application/octet-stream'})
    return app
