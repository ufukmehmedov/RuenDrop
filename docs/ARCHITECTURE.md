# RuenDrop v1 architecture

Browser: inspect image dimensions → decode with orientation → new canvas → resize → JPEG → AES-256-GCM → upload ciphertext.

Nginx HTTPS `/drop/` → loopback Gunicorn `127.0.0.1:8787` → SQLite metadata and private ciphertext files.

Envelope: ASCII `RD01` (four bytes), random IV (12 bytes), AES-GCM ciphertext and 16-byte tag. `RD01` is authenticated additional data. The 32-byte key is base64url encoded without padding into the share URL fragment. Photo IDs and invite secrets are independently generated 32-byte random values.

The invite exchange runs over HTTPS with exact Origin validation. Authorized writes require both the session cookie and a session-specific CSRF header. SQLite write transactions serialize invite rotation, session creation, upload authorization and quota checks. Every read checks the 24-hour deadline; the cleanup timer removes expired records/files and crash orphans. Rotation never modifies photo records.

Dedicated Unix user, private storage, read-only application code, systemd memory/CPU limits, non-executable data paths and no public application port isolate the service from other applications.
