# RuenDrop

Private, temporary photo sharing at `/drop/`. No accounts, external scripts or analytics.

A secret invite fragment is exchanged for a Secure, HttpOnly, SameSite=Strict session cookie and immediately removed from the visible URL. Upload controls are served only to authorized sessions. Each share link carries an independent AES-256-GCM key in its fragment; recipients need no upload authorization.

The browser checks JPEG/PNG/WebP signatures and dimensions, actually decodes the image, applies orientation, draws onto a fresh canvas, resizes to at most 2000 pixels, and re-encodes JPEG. Only the encrypted result leaves the browser. Input is limited to 10 MiB and 40 million pixels; ciphertext to 6 MiB. No original filename or metadata is uploaded.

## Runtime

Python 3.10+, Flask, Gunicorn, SQLite and Nginx. See `requirements.txt` and `deploy/` for safe templates. Runtime files live outside the source tree under `/var/lib/ruendrop`; the service binds exclusively to `127.0.0.1:8787`.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

See [deployment notes](docs/deployment.md) for installation and verification. For day-to-day commands and maintenance, see the [usage and administrator guide](docs/USAGE.md). No production configuration or secrets belong in this repository.

## Administrator commands

```sh
sudo ruendrop show-url
sudo ruendrop rotate-url
```

Rotation is manual only. It changes the invite and revokes every upload session in one database transaction, without changing photo records or keys. The application stores only the invite hash. To support `show-url`, a separate root-readable `0600` recovery file stores the current invite; the application user cannot read it. Run display commands in a private terminal, never a recorded/shared terminal.

Every photo becomes inaccessible exactly 86,400 seconds after creation. A persistent systemd timer deletes expired ciphertext and rows every minute. Storage defaults: 1 GiB photo quota, 10,000 photos, 2 GiB minimum free disk reserve, 2 GiB ciphertext delivery budget per 24-hour window. At capacity, new uploads are refused. Requests, sessions, and limiter records are bounded.

## Verification

```sh
.venv/bin/pip install pytest playwright Pillow
.venv/bin/python -m pytest -q
.venv/bin/playwright install chromium
# Private file contains an invite URL; no URLs or keys are printed by the test.
RUENDROP_TEST_URL=https://photos.example.com RUENDROP_TEST_INVITE=/private/invite-url .venv/bin/python tests/browser_check.py
```

Browser checks cover authorization, invalid invites, non-images, byte/pixel limits, EXIF/GPS removal, orientation, resizing, encryption, separate-browser decryption, missing/wrong keys and request secrecy.
