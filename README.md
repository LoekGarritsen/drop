# drop

Self-hosted, end-to-end encrypted drop box for moving files, notes and passwords between your own devices. AirDrop-style convenience, but over your tailnet and with the server storing nothing it can read.

Zero runtime dependencies: Node 24+ (`node:sqlite`), plain HTML/JS, WebCrypto in the browser.

## How it works

- **One vault passphrase.** You type it once per device. The browser derives an AES-256 key with PBKDF2 (600k iterations, server-provided public salt) and keeps the derived key in `localStorage` so the device stays unlocked. The passphrase itself never leaves the browser.
- **Everything is ciphertext on the server.** Item metadata (name, type) and content are AES-GCM encrypted client-side. Files are encrypted in 8 MiB chunks so multi-GB uploads do not need to fit in memory. The server sees sizes, timestamps and an opaque kind hint.
- **Burn after read.** Secrets default to deletion the moment the server has served the bytes once. Reveal and Copy both count as the one read.
- **Expiry.** Every item has a TTL (1 hour to 30 days, 7 days default). A sweeper deletes expired and abandoned items every minute.
- **Live sync.** Server-sent events refresh every open tab when something is added or deleted.
- **PWA.** Installable on iOS and Android (share-sheet target on Android). Paste or drag files anywhere on the page.

Threat model: protects the data at rest on the server and against anyone who can read the disk or database. Does **not** protect against a malicious server operator modifying the JavaScript, and there is no per-user auth: run it only on a network you trust (tailnet, LAN). Losing the passphrase loses everything.

## Run

```bash
docker compose up -d --build     # listens on :8300, data in ./data
```

or without Docker:

```bash
npm run dev                      # PORT=8300 DATA_DIR=./data, restarts on change
```

Environment: `PORT` (8300), `DATA_DIR` (`./data`), `MAX_ITEM_BYTES` (4 GiB), `DEFAULT_TTL_S` (7 days), `MAX_TTL_S` (30 days).

Put a TLS-terminating reverse proxy in front (WebCrypto requires a secure context, so `https://` or `localhost`). If the proxy buffers request bodies, raise its upload limit or disable buffering for `/api/items/*/chunks/*`.

## Test

```bash
PORT=8399 DATA_DIR=./data-test node server.js &
npm test                         # end-to-end against :8399 with the real crypto.js
```

## API

All bodies are opaque to the server.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/meta` | salt, encrypted vault check, limits |
| PUT | `/api/meta` | set vault check once (first device) |
| GET | `/api/items` | list complete, unexpired items |
| POST | `/api/items` | create item `{kind, meta, chunkSize, burn, ttl}` |
| PUT | `/api/items/:id/chunks/:n` | append one encrypted chunk |
| POST | `/api/items/:id/finish` | mark complete, broadcast |
| GET | `/api/items/:id/blob` | full ciphertext, `X-Chunk-Size` header; deletes if burn |
| DELETE | `/api/items/:id` | delete |
| GET | `/api/events` | SSE stream of `change` events |
