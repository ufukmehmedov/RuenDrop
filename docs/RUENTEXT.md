# RuenText

Private encrypted UTF-8 text sharing at `https://novachat.ruenitservices.com/text/`.
No accounts, registration, analytics, external scripts, or external services.

## Create and read

1. Run `sudo ruendrop text-show-url` in a private terminal to get the invite.
2. Open that invite. Its fragment is immediately removed from the visible URL and exchanged for a Secure, HttpOnly, SameSite=Strict cookie scoped to `/text/`.
3. Enter or paste multiline text, choose **24 hours** or **Burn after reading**, and press **Create secure link**.
4. Copy the complete link, including `#KEY`, and send it privately. Recipients need no invite. They press **Open text** to decrypt.

The textarea supports Turkish, Bulgarian Cyrillic, English, line breaks, mobile screens, spellcheck and internal scrolling. The encrypted envelope is limited to 1 MiB; UTF-8 characters and JSON escaping count toward that limit.

**24 hours:** repeat reads until exactly 86,400 seconds after creation.
**Burn after reading:** successful decryption produces a receipt; the server atomically marks the text opened and clears its ciphertext before the browser displays it. Later opens fail. Missing/wrong keys do not burn the text. Unread burn links also expire after 24 hours. Expired ciphertext and opened metadata are removed by the existing minute cleanup timer; expiry is enforced on requests without waiting for cleanup.

## Administrator commands

```sh
sudo ruendrop text-show-url       # Display existing invite with the /text/ path
sudo ruendrop text-list           # IDs, UTC dates, mode and status; no content/keys
sudo ruendrop text-revoke TEXT_ID # Delete one text, safe to repeat
sudo ruendrop cleanup             # Existing cleanup, now includes texts
sudo ruendrop show-url            # Existing RuenDrop invite
sudo ruendrop rotate-url          # Rotate shared invite; revoke BOTH services' sessions
sudo ruendrop revoke-drop DROP_ID # Existing photo revocation
```

Never pass a full share link or encryption key to an admin command. Rotation preserves existing shared photos and texts. The text invite uses the same secret as RuenDrop; creating either service's session does not widen the other's cookie path. `text-show-url` uses the existing root-only invite recovery file.

## Security model

Web Crypto generates an independent random 256-bit AES-GCM key and 96-bit nonce per text. The authenticated envelope is `RT01 || nonce || ciphertext-with-tag`, with `RT01` as additional authenticated data. JSON inside it holds the UTF-8 text, mode and independent random 256-bit receipt. Only the receipt's SHA-256 digest accompanies the ciphertext on upload. Receipt acknowledgment reveals neither the text nor its encryption key.

The key appears only in the share link fragment and browser memory, never in HTTP requests, cookies or browser persistent storage. Text is rendered as a textarea value, never HTML. HTML, scripts and JSON use UTF-8; SQLite uses UTF-8 metadata and binary ciphertext BLOBs. The server cannot validate whether an arbitrary uploader actually encrypted its bytes; the supplied browser always encrypts before upload.

SQLite stores ciphertext, random 256-bit ID, creation/expiry times, opened status, mode and receipt hash. It uses secure_delete; burn clears the ciphertext and receipt hash transactionally. No plaintext or key logging, social preview metadata, analytics or external dependencies are added. Existing CSP, no-store, noindex/nofollow/noarchive, no-referrer, CSRF, origin checks and bounded rate limiting apply. Text uploads have a separate 64 MiB quota and 1,000-record cap; delivery is bounded independently, and free-disk safeguards remain in place.

Burn semantics require the supplied client: only one concurrent receipt acknowledgment succeeds, and only that reader displays the text. Anyone holding a full link can save decrypted text or fetched ciphertext; no service can erase recipient copies. A browser crash or lost acknowledgment response after the atomic burn can consume the link without displaying it. The server cannot independently attest browser decryption. Explicit opening prevents ordinary link previews from consuming a link. The service operator and HTTPS-delivered JavaScript must be trusted; compromised browsers, servers or shared links defeat confidentiality. Keep the runtime directory out of backups; secure deletion does not guarantee erasure from SSD snapshots or external backups.

## Deployment and tests

Use the existing `/opt/ruendrop` source, `/var/lib/ruendrop/ruendrop.db`, loopback `127.0.0.1:8787`, `ruendrop.service` and cleanup timer. No new port or service is needed. Back up source/configuration, install the updated source, and include `deploy/nginx-text.conf` as `/etc/nginx/snippets/ruentext.conf` inside the existing HTTPS server block. Validate with `sudo nginx -t`, restart only RuenDrop and reload Nginx. The database table is created additively on startup. Preserve all unrelated virtual hosts, routes and services. Rollback restores old source and removes only the text include; the additive table does not affect old RuenDrop code.

```sh
.venv/bin/python -m pytest -q
RUENDROP_TEST_INVITE=/private/invite-url .venv/bin/python tests/text_browser_check.py
# For deployment use RUENDROP_TEST_URL=https://novachat.ruenitservices.com
```

Tests exercise Turkish/Bulgarian round trips, long multiline text, browser request secrecy, wrong keys, repeated 24-hour reads, burn and second-open rejection. Backend tests cover expiry at the boundary, cleanup, storage contents, concurrent burn, access controls and admin commands, alongside the existing RuenDrop regression suite.
