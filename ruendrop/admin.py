import argparse
import fcntl
import os
import secrets
import sys
from pathlib import Path
from .app import initialize, connect, digest, cleanup, TOKEN

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=['rotate-url','show-url','cleanup','revoke-drop','text-list','text-revoke','text-show-url'])
    parser.add_argument('drop_id',nargs='?',help='Opaque drop ID only; never pass a share URL or key.')
    args=parser.parse_args()
    if args.command in ('revoke-drop','text-revoke'):
        if not args.drop_id or not TOKEN.fullmatch(args.drop_id):
            parser.error('Provide a valid drop ID only (43 URL-safe characters).')
    elif args.drop_id is not None:
        parser.error('This command does not accept a drop ID.')
    if args.command!='cleanup' and os.geteuid()!=0:
        sys.exit('Run this command with sudo.')
    os.umask(0o077)
    root=Path(os.environ.get('RUENDROP_DATA','/var/lib/ruendrop'))
    initialize(root)
    if args.command=='cleanup':
        cleanup(root)
        return
    if args.command=='revoke-drop':
        with connect(root/'ruendrop.db') as db:
            db.execute('BEGIN IMMEDIATE')
            (root/'data'/args.drop_id).unlink(missing_ok=True)
            db.execute('DELETE FROM photos WHERE id=?',(args.drop_id,))
        print('Drop revoked; stored ciphertext deleted (or already absent).')
        return
    if args.command=='text-list':
        with connect(root/'ruendrop.db') as db:
            print('ID CREATED_UTC EXPIRES_UTC MODE STATUS')
            from datetime import datetime, timezone
            import time
            for row in db.execute('SELECT id,created,expires,mode,opened FROM texts ORDER BY created'):
                stamp=lambda t: datetime.fromtimestamp(t,timezone.utc).isoformat()
                state='opened' if row['opened'] else 'expired' if row['expires']<=time.time() else 'available'
                print(row['id'],stamp(row['created']),stamp(row['expires']),row['mode'],state)
        return
    if args.command=='text-revoke':
        with connect(root/'ruendrop.db') as db:
            db.execute('DELETE FROM texts WHERE id=?',(args.drop_id,))
        print('Text revoked; stored ciphertext deleted (or already absent).')
        return
    secret=Path(os.environ.get('RUENDROP_INVITE_FILE','/etc/ruendrop/invite'))
    secret.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    lock=secret.with_suffix('.lock').open('a')
    os.chmod(secret.with_suffix('.lock'),0o600)
    fcntl.flock(lock,fcntl.LOCK_EX)
    if args.command=='rotate-url':
        token=secrets.token_urlsafe(32)
        secret.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        tmp=secret.with_suffix('.new')
        with tmp.open('w') as f:
            os.chmod(tmp,0o600)
            f.write(token)
            f.flush()
            os.fsync(f.fileno())
        with connect(root/'ruendrop.db') as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT OR REPLACE INTO invite VALUES (1,?)',(digest(token),))
            db.execute('DELETE FROM sessions')
            os.replace(tmp,secret)
    else:
        token=secret.read_text().strip()
        with connect(root/'ruendrop.db') as db:
            row=db.execute('SELECT hash FROM invite WHERE id=1').fetchone()
            if not row or row[0]!=digest(token):
                sys.exit('Invite recovery file mismatch; run rotate-url.')
    print(os.environ.get('RUENDROP_ORIGIN','https://novachat.ruenitservices.com')+('/text/#' if args.command=='text-show-url' else '/drop/#')+token)

if __name__=='__main__':
    main()
