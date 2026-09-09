import argparse
import fcntl
import os
import secrets
import sys
from pathlib import Path
from .app import initialize, connect, digest, cleanup

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=['rotate-url','show-url','cleanup'])
    args=parser.parse_args()
    os.umask(0o077)
    root=Path(os.environ.get('RUENDROP_DATA','/var/lib/ruendrop'))
    initialize(root)
    if args.command=='cleanup':
        cleanup(root)
        return
    if os.geteuid()!=0 and not os.environ.get('RUENDROP_ADMIN_TEST'):
        sys.exit('Run this command with sudo.')
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
    print(os.environ.get('RUENDROP_ORIGIN','https://novachat.ruenitservices.com')+'/drop/#'+token)

if __name__=='__main__':
    main()
