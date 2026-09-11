"""RuenText endpoints; keys and message plaintext never enter this module."""
import hmac
import re
import secrets
import shutil
import time
from flask import abort, g, jsonify, make_response, request
from .app import ROOT, TOKEN, TTL, digest

MAX_TEXT = 1024 * 1024  # Encrypted envelope, including UTF-8 JSON overhead.

def register_text(app, db, session, limit, page, root):
    @app.get('/text/')
    def text_index():
        return page('text.html' if session() else 'text-locked.html')

    @app.get('/text/assets/<name>')
    def text_asset(name):
        if name not in ('text.js', 'text.css'):
            abort(404)
        return make_response((ROOT/'static'/name).read_text(encoding='utf-8'), 200,
                             {'Content-Type': ('text/css' if name.endswith('.css') else 'text/javascript')+'; charset=utf-8'})

    @app.get('/text/t/<text_id>')
    def text_view(text_id):
        if not TOKEN.fullmatch(text_id):
            abort(404)
        return page('text-view.html')

    @app.post('/text/api/texts')
    def text_create():
        limit('text-uploads:'+g.auth['hash'], 30, 3600)
        if request.content_type != 'application/octet-stream':
            abort(415)
        if not request.content_length or request.content_length > MAX_TEXT:
            abort(413)
        mode = request.headers.get('X-Text-Mode', '')
        receipt_hash = request.headers.get('X-Text-Receipt', '')
        if mode not in ('24h', 'burn') or not re.fullmatch('[0-9a-f]{64}', receipt_hash):
            abort(400)
        payload = request.get_data()
        if len(payload) < 33 or payload[:4] != b'RT01':
            abort(400)
        c = db()
        c.execute('BEGIN IMMEDIATE')
        if not c.execute('SELECT 1 FROM sessions WHERE hash=? AND expires>?', (g.auth['hash'], time.time())).fetchone():
            c.rollback()
            abort(401)
        size, count = c.execute('SELECT coalesce(sum(length(ciphertext)),0),count(*) FROM texts').fetchone()
        if size+len(payload) > app.config['TEXT_QUOTA'] or count >= app.config['MAX_TEXTS'] or shutil.disk_usage(root).free-len(payload) < app.config['MIN_FREE']:
            c.rollback()
            abort(503)
        text_id, now = secrets.token_urlsafe(32), time.time()
        c.execute('INSERT INTO texts VALUES (?,?,?,?,0,?,?)', (text_id, payload, now, now+TTL, mode, receipt_hash))
        c.commit()
        return jsonify(id=text_id, expires_at=now+TTL), 201

    def available(text_id):
        if not TOKEN.fullmatch(text_id):
            abort(404)
        row = db().execute('SELECT * FROM texts WHERE id=? AND expires>? AND opened=0', (text_id, time.time())).fetchone()
        if not row:
            abort(404)
        return row

    @app.get('/text/api/texts/<text_id>')
    def text_download(text_id):
        row = available(text_id)
        limit('text-egress', app.config['DAILY_EGRESS'], TTL, len(row['ciphertext']))
        return make_response(row['ciphertext'], 200, {'Content-Type':'application/octet-stream'})

    @app.post('/text/api/texts/<text_id>/opened')
    def text_opened(text_id):
        # The receipt is encrypted alongside the message, independent of its key.
        # An atomic update allows only one cooperating reader to display a burn.
        if request.content_length is None or request.content_length > 128:
            abort(413)
        body = request.get_json(silent=True)
        receipt = body.get('receipt') if isinstance(body, dict) else None
        if not isinstance(receipt, str) or not TOKEN.fullmatch(receipt):
            abort(400)
        c = db()
        c.execute('BEGIN IMMEDIATE')
        row = available(text_id)
        if not hmac.compare_digest(row['receipt_hash'], digest(receipt)):
            c.rollback()
            abort(403)
        if row['mode'] == 'burn':
            c.execute('UPDATE texts SET opened=1,ciphertext=NULL,receipt_hash=\'\' WHERE id=?', (text_id,))
        c.commit()
        return jsonify(ok=True)
