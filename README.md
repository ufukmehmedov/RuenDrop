# RuenDrop

RuenDrop is a small, private-access temporary photo sharing service.

## v1 goals

- Photo-only uploads
- No user accounts
- Access to the upload page through a secret invite URL
- A separate unguessable share URL for each uploaded photo
- Automatic EXIF/GPS metadata removal
- Decode and re-encode every accepted image
- Resize large images to a reasonable display size
- Keep photos for 24 hours, then delete the image and access record
- Store photos outside the public web root
- Serve publicly only through HTTPS
- Designed to run as an isolated service on the same Oracle server as NovaChat
- NovaChat integration is optional; RuenDrop must work independently

## Planned deployment

```text
Internet
   |
 HTTPS :443
   |
 Nginx
   |
 127.0.0.1:8787
   |
 RuenDrop
   |-- Web UI
   |-- Upload API
   |-- Image validation / re-encoding
   |-- SQLite metadata
   `-- Private photo storage
```

## Security principles

- Never trust filename extensions or browser-provided MIME types alone.
- Only accept image formats explicitly supported by the service.
- Decode images with an image library before accepting them.
- Re-encode accepted images before storage.
- Never execute uploaded content.
- Never store uploads inside the application source tree or Nginx public web root.
- Use cryptographically random access tokens.
- Apply upload size, image dimension and request-rate limits.
- Secrets and production invite URLs must never be committed to Git.

## Status

Early development / v1 design.
