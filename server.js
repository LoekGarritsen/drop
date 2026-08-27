// drop: zero-dependency Node server. Stores opaque ciphertext blobs and
// encrypted metadata; the browser does all crypto. See README for the model.
import http from "node:http";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { pipeline } from "node:stream/promises";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8300);
const DATA_DIR = path.resolve(process.env.DATA_DIR || "./data");
const BLOB_DIR = path.join(DATA_DIR, "blobs");
const PUBLIC_DIR = path.join(__dirname, "public");
const MAX_ITEM_BYTES = Number(process.env.MAX_ITEM_BYTES || 4 * 1024 ** 3);
const MAX_META_BYTES = 64 * 1024;
const DEFAULT_TTL_S = Number(process.env.DEFAULT_TTL_S || 7 * 86400);
const MAX_TTL_S = Number(process.env.MAX_TTL_S || 30 * 86400);

fs.mkdirSync(BLOB_DIR, { recursive: true });

// --- storage -----------------------------------------------------------
const db = new DatabaseSync(path.join(DATA_DIR, "drop.db"));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,            -- file | note | secret (hint only, real kind is in meta)
    meta TEXT NOT NULL,            -- base64 AES-GCM ciphertext of JSON metadata
    size INTEGER NOT NULL DEFAULT 0,
    chunk_size INTEGER NOT NULL DEFAULT 0,
    complete INTEGER NOT NULL DEFAULT 0,
    burn INTEGER NOT NULL DEFAULT 0,
    views INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS items_expires ON items(expires_at);
`);

// Vault salt is public and stable: every device derives the same key from
// the same passphrase. It is not a secret, only a namespace.
function setting(key, make) {
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(key);
  if (row) return row.value;
  const value = make();
  db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").run(key, value);
  return value;
}
const VAULT_SALT = setting("vault_salt", () => crypto.randomBytes(32).toString("base64"));
const VAULT_CHECK = setting("vault_check", () => ""); // set once by the first client

const q = {
  insert: db.prepare(`INSERT INTO items (id, kind, meta, chunk_size, burn, created_at, expires_at)
                      VALUES (?, ?, ?, ?, ?, ?, ?)`),
  get: db.prepare("SELECT * FROM items WHERE id = ?"),
  list: db.prepare(`SELECT id, kind, meta, size, complete, burn, views, created_at, expires_at
                    FROM items WHERE expires_at > ? ORDER BY created_at DESC`),
  finish: db.prepare("UPDATE items SET complete = 1, size = ? WHERE id = ?"),
  view: db.prepare("UPDATE items SET views = views + 1 WHERE id = ?"),
  del: db.prepare("DELETE FROM items WHERE id = ?"),
  expired: db.prepare("SELECT id FROM items WHERE expires_at <= ?"),
  stale: db.prepare("SELECT id FROM items WHERE complete = 0 AND created_at < ?"),
};

const blobPath = (id) => path.join(BLOB_DIR, id);
const now = () => Math.floor(Date.now() / 1000);

function removeItem(id) {
  q.del.run(id);
  fs.rm(blobPath(id), { force: true }, () => {});
}

function sweep() {
  const t = now();
  for (const { id } of q.expired.all(t)) removeItem(id);
  for (const { id } of q.stale.all(t - 6 * 3600)) removeItem(id); // abandoned uploads
}
sweep();
setInterval(sweep, 60_000).unref();

// --- server-sent events: tell every open tab the list changed ------------
const sseClients = new Set();
function broadcast(event, data) {
  const frame = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) res.write(frame);
}

// --- helpers -------------------------------------------------------------
const ID_RE = /^[A-Za-z0-9_-]{16,32}$/;
const MIME = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml",
  ".png": "image/png", ".webmanifest": "application/manifest+json",
};

function send(res, status, body, headers = {}) {
  const isJson = body !== undefined && typeof body !== "string" && !Buffer.isBuffer(body);
  res.writeHead(status, {
    "Cache-Control": "no-store",
    ...(isJson ? { "Content-Type": "application/json" } : {}),
    ...headers,
  });
  res.end(isJson ? JSON.stringify(body) : body);
}

async function readJson(req, limit = MAX_META_BYTES) {
  const chunks = [];
  let n = 0;
  for await (const c of req) {
    n += c.length;
    if (n > limit) throw Object.assign(new Error("payload too large"), { status: 413 });
    chunks.push(c);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks)) : {};
}

function publicItem(row) {
  const { meta, ...rest } = row;
  return { ...rest, meta, complete: !!row.complete, burn: !!row.burn };
}

// --- routes --------------------------------------------------------------
async function api(req, res, url) {
  const parts = url.pathname.split("/").filter(Boolean); // ["api", ...]
  const [, resource, id, sub, subId] = parts;

  if (resource === "meta" && req.method === "GET") {
    const check = db.prepare("SELECT value FROM settings WHERE key = 'vault_check'").get()?.value || "";
    return send(res, 200, { salt: VAULT_SALT, check, maxItemBytes: MAX_ITEM_BYTES,
      defaultTtl: DEFAULT_TTL_S, maxTtl: MAX_TTL_S });
  }

  // First device to set up the vault stores an encrypted check value so
  // other devices can tell a wrong passphrase from an empty vault.
  if (resource === "meta" && req.method === "PUT") {
    const cur = db.prepare("SELECT value FROM settings WHERE key = 'vault_check'").get()?.value || "";
    if (cur) return send(res, 409, { error: "vault already initialized" });
    const { check } = await readJson(req);
    if (typeof check !== "string" || check.length > 512) return send(res, 400, { error: "bad check" });
    db.prepare("UPDATE settings SET value = ? WHERE key = 'vault_check'").run(check);
    return send(res, 204);
  }

  if (resource === "events" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-store",
      Connection: "keep-alive", "X-Accel-Buffering": "no" });
    res.write("retry: 3000\n\n");
    sseClients.add(res);
    const ping = setInterval(() => res.write(": ping\n\n"), 25_000);
    req.on("close", () => { clearInterval(ping); sseClients.delete(res); });
    return;
  }

  if (resource !== "items") return send(res, 404, { error: "not found" });

  if (!id && req.method === "GET") {
    return send(res, 200, q.list.all(now()).filter((r) => r.complete).map(publicItem));
  }

  if (!id && req.method === "POST") {
    const body = await readJson(req);
    const { kind, meta, chunkSize, burn, ttl } = body;
    if (!["file", "note", "secret"].includes(kind)) return send(res, 400, { error: "bad kind" });
    if (typeof meta !== "string" || meta.length > MAX_META_BYTES) return send(res, 400, { error: "bad meta" });
    const cs = Number(chunkSize);
    if (!Number.isInteger(cs) || cs < 1024 || cs > 64 * 1024 ** 2) return send(res, 400, { error: "bad chunkSize" });
    const ttlS = Math.min(Math.max(Number(ttl) || DEFAULT_TTL_S, 60), MAX_TTL_S);
    const newId = crypto.randomBytes(16).toString("base64url");
    const t = now();
    q.insert.run(newId, kind, meta, cs, burn ? 1 : 0, t, t + ttlS);
    await fsp.writeFile(blobPath(newId), "");
    return send(res, 201, { id: newId, expires_at: t + ttlS });
  }

  if (!ID_RE.test(id || "")) return send(res, 400, { error: "bad id" });
  const row = q.get.get(id);
  if (!row || row.expires_at <= now()) return send(res, 404, { error: "not found" });

  // Append one encrypted chunk. Client sends them in order; server only
  // enforces the total size cap.
  if (sub === "chunks" && req.method === "PUT") {
    if (row.complete) return send(res, 409, { error: "already complete" });
    const len = Number(req.headers["content-length"]);
    if (!Number.isFinite(len)) return send(res, 411, { error: "length required" });
    const cur = (await fsp.stat(blobPath(id))).size;
    if (cur + len > MAX_ITEM_BYTES + 1024 ** 2) return send(res, 413, { error: "item too large" });
    await pipeline(req, fs.createWriteStream(blobPath(id), { flags: "a" }));
    return send(res, 204);
  }

  if (sub === "finish" && req.method === "POST") {
    const size = (await fsp.stat(blobPath(id))).size;
    q.finish.run(size, id);
    broadcast("change", { id, op: "add" });
    return send(res, 200, publicItem(q.get.get(id)));
  }

  if (sub === "blob" && req.method === "GET") {
    if (!row.complete) return send(res, 409, { error: "upload not finished" });
    q.view.run(id);
    res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": row.size,
      "Cache-Control": "no-store", "X-Chunk-Size": row.chunk_size });
    try {
      await pipeline(fs.createReadStream(blobPath(id)), res);
    } finally {
      // Burn-after-read: gone once the bytes have been sent, whether or not
      // the client manages to decrypt them.
      if (row.burn) { removeItem(id); broadcast("change", { id, op: "delete" }); }
    }
    return;
  }

  if (!sub && req.method === "GET") return send(res, 200, publicItem(row));

  if (!sub && req.method === "DELETE") {
    removeItem(id);
    broadcast("change", { id, op: "delete" });
    return send(res, 204);
  }

  return send(res, 405, { error: "method not allowed" });
}

async function serveStatic(req, res, url) {
  let rel = decodeURIComponent(url.pathname);
  if (rel === "/" || rel.startsWith("/i/")) rel = "/index.html"; // /i/<id> deep links
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR)) return send(res, 403, "forbidden");
  try {
    const stat = await fsp.stat(file);
    if (!stat.isFile()) throw new Error();
  } catch {
    return send(res, 404, "not found");
  }
  const type = MIME[path.extname(file)] || "application/octet-stream";
  res.writeHead(200, { "Content-Type": type,
    "Cache-Control": file.endsWith("index.html") ? "no-cache" : "public, max-age=3600" });
  await pipeline(fs.createReadStream(file), res);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  try {
    if (url.pathname.startsWith("/api/")) await api(req, res, url);
    else if (req.method === "GET" || req.method === "HEAD") await serveStatic(req, res, url);
    else send(res, 405, "method not allowed");
  } catch (err) {
    if (res.headersSent) return res.destroy();
    send(res, err.status || 500, { error: err.status ? err.message : "internal error" });
    if (!err.status) console.error(err);
  }
});
server.requestTimeout = 0; // long uploads over slow links
server.headersTimeout = 60_000;
server.listen(PORT, () => console.log(`drop listening on :${PORT}, data in ${DATA_DIR}`));

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => { server.close(); db.close(); process.exit(0); });
}
