# RuenDrop Usage & Administrator Guide

This file is the operational cheat sheet for a deployed RuenDrop instance.

## Normal use

Open the private invite URL provided by the administrator. After authorization, use the upload page to select a photo and create a temporary encrypted share link.

Do not publish the private invite URL. Photo share links are separate from the invite URL and expire automatically after 24 hours.

## Invite URL commands

Show the current private invite URL:

```sh
sudo ruendrop show-url
```

Rotate the private invite URL manually:

```sh
sudo ruendrop rotate-url
```

Rotation is never automatic. It invalidates the previous invite URL and existing upload-site sessions, but it does not invalidate already-created photo share links before their normal 24-hour expiry.

Run `show-url` only in a private terminal because the command prints the secret invite URL.

## Service status

Check the RuenDrop application service:

```sh
sudo systemctl status ruendrop
```

Check the cleanup timer:

```sh
sudo systemctl status ruendrop-cleanup.timer
```

List the next cleanup run:

```sh
sudo systemctl list-timers | grep ruendrop
```

## Restarting RuenDrop

Restart only the RuenDrop service:

```sh
sudo systemctl restart ruendrop
```

Do not restart NovaRelay or unrelated services for normal RuenDrop maintenance.

## Run cleanup immediately

```sh
sudo systemctl start ruendrop-cleanup.service
```

Then check its result:

```sh
sudo systemctl status ruendrop-cleanup.service
```

## Logs

Recent RuenDrop service logs:

```sh
sudo journalctl -u ruendrop -n 100 --no-pager
```

Follow live service logs:

```sh
sudo journalctl -u ruendrop -f
```

Recent cleanup logs:

```sh
sudo journalctl -u ruendrop-cleanup.service -n 100 --no-pager
```

RuenDrop is designed not to log invite secrets, photo keys, or URL fragments. Do not manually add secret-bearing debug logging.

## Network checks

RuenDrop must listen only on loopback port 8787:

```sh
sudo ss -ltnp | grep 8787
```

Expected address:

```text
127.0.0.1:8787
```

Port 8787 must never be exposed directly to the Internet.

Validate Nginx before any reload:

```sh
sudo nginx -t
```

If validation passes and a configuration change was intentionally made:

```sh
sudo systemctl reload nginx
```

## HTTPS certificate checks

Inspect installed certificates:

```sh
sudo certbot certificates
```

Test automatic renewal without changing the live certificate:

```sh
sudo certbot renew --dry-run
```

## Quick health check

```sh
sudo systemctl is-active ruendrop
sudo systemctl is-active ruendrop-cleanup.timer
sudo ss -ltnp | grep 8787
sudo nginx -t
```

The first two commands should report `active`, port 8787 should be loopback-only, and Nginx validation should succeed.

## Important safety rules

- Never commit or paste the production invite URL into GitHub.
- Never share the invite URL publicly.
- Never expose port 8787.
- Never store photo decryption keys on the server.
- Always run `nginx -t` before reloading Nginx.
- Use `sudo ruendrop rotate-url` only when you intentionally want a new invite URL.
- Photo content expires automatically after 24 hours.
