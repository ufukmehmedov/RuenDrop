# RuenText verification — 2026-09-11

Deployed to `https://novachat.ruenitservices.com/text/` through the existing RuenDrop service and Nginx HTTPS host.

- 14 pytest tests passed: existing RuenDrop tests plus text access, storage, exact 86,400-second expiry boundary, cleanup, concurrent burn winner, wrong receipt rejection, rate limits, quotas, CSRF/origin checks, admin commands and shared invite rotation.
- Local and public Chromium checks passed: invite removal, mobile layout, Turkish `ç ğ ı İ ö ş ü Ç Ğ Ö Ş Ü`, Bulgarian Cyrillic alphabet, English, long multiline text, HTML treated as text, AES-256-GCM round trips, wrong/missing keys, fragment/request secrecy, repeat reads and burn second-open rejection.
- Production SQLite inspection confirmed encrypted BLOBs, no sample plaintext, UTF-8 database encoding, 24-hour creation/expiry interval, and NULL ciphertext after burn.
- A test text's expiry was moved into the past to verify immediate public rejection; the actual cleanup systemd service removed its row. No wait of 24 wall-clock hours was performed.
- Production `text-list` and `text-revoke` passed. Test text fixtures were removed.
- Existing public RuenDrop browser regression passed: photo processing, EXIF/GPS removal, orientation, resizing, multi-photo galleries, legacy links, decryption and privacy checks.
- `nginx -t` passed; RuenDrop, Nginx, cleanup timer and all three NovaRelay services remained active. NovaRelay PIDs were unchanged. Backend listener remained exclusively `127.0.0.1:8787`.

The documented burn limitations (recipient copies and a lost acknowledgment consuming a link) apply. No known blocking deployment issues remain.
