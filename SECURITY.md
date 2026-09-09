# Security model

Photo processing and encryption happen **in the browser**. The server cannot validate whether arbitrary authenticated ciphertext represents a photo without defeating end-to-end encryption. Photo-only enforcement applies to the supplied client; an authorized user with a modified client could submit other bounded ciphertext. The server validates the versioned envelope, session, CSRF token and byte/storage limits, never decrypts payloads, and never executes stored data.

AES-256-GCM uses a new OS/browser CSPRNG key and 96-bit IV per drop, with the four-byte protocol version authenticated as additional data. The 128-bit authentication tag is produced by Web Crypto. Keys appear only in share fragments and browser memory. SQLite contains opaque IDs, byte counts, timestamps, hashes and CSRF tokens, not photo keys or plaintext.

All API and HTML responses are no-store and carry restrictive CSP, no-referrer, nosniff and frame protection. Nginx and Gunicorn request logging is disabled for RuenDrop. Do not add request-body tracing, analytics, error-reporting SDKs, or proxy logs that could capture credentials. The root-only invite recovery file is the explicit exception to hash-only credential storage, required for `show-url`.

A compromised application server can deliver malicious JavaScript on future visits. E2EE does not protect against that active attack, a compromised browser, extensions, or recipients saving images. Anyone with a complete share link can view it until expiry. Share links remain in the recipient address bar so they can be copied/reloaded; invite fragments are removed immediately.

Expiration denies every new read at the deadline; it cannot retract an already downloaded/in-flight photo. Cleanup unlinks expired files and securely deletes SQLite rows. Filesystem/SSD snapshots and physical block remanence cannot be guaranteed erased by application code; exclude the data directory from backups. A crashed upload may leave an orphan, which cleanup removes under the same write lock used for uploads.

Disk and egress budgets limit local resource usage; they are not an Oracle billing guarantee. Keep Oracle account monitoring enabled independently. No paid cloud resources are required.

Never commit `.env`, invite recovery files, production DBs, ciphertext, server IPs, credentials, or private deployment state. Report security issues privately to the repository owner.
