# RuenDrop v1 Architecture

## User flow

1. An authorized person opens a secret invite URL.
2. RuenDrop validates the invite token and creates a secure browser session.
3. The browser is redirected to the clean RuenDrop upload page.
4. The user selects a photo.
5. The server validates, decodes, strips metadata by re-encoding, and resizes when necessary.
6. The original upload is discarded.
7. RuenDrop stores only the processed image in private storage.
8. A cryptographically random photo URL is created.
9. The photo URL works for 24 hours.
10. Expired image data and the associated database record are deleted automatically.

## Network layout

```text
Internet
   |
 TCP 443 / HTTPS
   |
 Nginx
   |  reverse proxy
   v
127.0.0.1:8787
   |
 RuenDrop service
   |-- SQLite metadata
   `-- /var/lib/ruendrop/photos (private)
```

The RuenDrop application port must not be exposed directly to the Internet.

## Access model

The secret invite URL acts as the bootstrap credential. After a successful visit, the service should set a secure session cookie and redirect away from the token-bearing URL so the secret is not left in the browser address bar during normal use.

Photo share URLs use independent high-entropy random tokens. Knowing a photo URL does not grant upload access.

## Image handling

Initial supported formats:

- JPEG
- PNG
- WebP

Processing rules:

- Reject data that cannot be decoded as an allowed image.
- Enforce a maximum upload byte size before decoding.
- Enforce a decoded pixel-count limit to defend against decompression bombs.
- Apply EXIF orientation during processing when needed.
- Create a fresh output image without EXIF/GPS metadata.
- Limit the longest image edge to a configurable value (initial target: 2000 px).
- Do not keep the original upload after processing.

## Retention

Every stored image has `created_at` and `expires_at` metadata. `expires_at` is exactly 24 hours after successful processing. A scheduled cleanup job removes expired images and records. Photo-serving endpoints must also reject expired records even if cleanup has not yet run.

## Isolation

RuenDrop should run under a dedicated unprivileged Linux user and use separate runtime directories from NovaRelay. Sharing the same Oracle VM must not mean sharing process permissions or writable directories.

## NovaChat

NovaChat integration is optional. The standalone service is the source of truth. A future NovaChat `/photo` feature can call the same RuenDrop backend without changing the standalone architecture.
