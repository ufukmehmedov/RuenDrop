# Security Policy

RuenDrop is intended to expose the smallest possible public attack surface.

## Production rules

- Do not commit production secrets, invite URLs, API keys or TLS private keys.
- Bind the application service to `127.0.0.1` and expose it through an HTTPS reverse proxy.
- Keep uploaded images outside the source tree and outside any directly served web root.
- Accept only explicitly supported image formats and verify by decoding.
- Re-encode every accepted image before permanent temporary storage.
- Strip metadata by creating a new output image rather than copying the original file.
- Enforce upload byte-size and decoded pixel-count limits.
- Generate invite and photo access tokens with a cryptographically secure random generator.
- Apply rate limits to invite, upload and photo-serving endpoints.
- Delete expired images and their database records after 24 hours.
- Run RuenDrop under its own unprivileged operating-system account.
- Never execute or import uploaded content.

## Public repository note

The source code may be public. Security must not depend on hiding the implementation. Production access depends on server-side secrets that are generated during deployment and are never stored in this repository.
