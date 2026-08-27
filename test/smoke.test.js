// End-to-end: real crypto.js in Node against a running server on TEST_URL.
import { test } from "node:test";
import assert from "node:assert/strict";
import { deriveKey, encryptBytes, decryptBytes, encryptJson, decryptJson, OVERHEAD } from "../public/crypto.js";

const BASE = process.env.TEST_URL || "http://127.0.0.1:8399";
const JSON_H = { "content-type": "application/json" };
const j = async (path, opts) => { const r = await fetch(BASE + path, opts); return { r, body: r.headers.get("content-type")?.includes("json") ? await r.json() : null }; };

test("vault init, upload, list, download, burn, delete", async () => {
  const { body: meta } = await j("/api/meta");
  assert.ok(meta.salt);
  const key = await deriveKey("correct horse", meta.salt, 1000);
  if (!meta.check) {
    const check = await encryptJson(key, { ok: true });
    assert.equal((await j("/api/meta", { method: "PUT", headers: JSON_H, body: JSON.stringify({ check }) })).r.status, 204);
  }

  // 3 chunks of 4 KB + a tail: exercises chunk framing on both sides
  const CHUNK = 4096, plain = new Uint8Array(CHUNK * 3 + 777).map((_, i) => i % 251);
  const { body: created } = await j("/api/items", { method: "POST", headers: JSON_H,
    body: JSON.stringify({ kind: "file", meta: await encryptJson(key, { kind: "file", name: "x.bin" }), chunkSize: CHUNK, burn: false, ttl: 3600 }) });
  for (let off = 0; off < plain.length; off += CHUNK) {
    const wire = await encryptBytes(key, plain.subarray(off, Math.min(off + CHUNK, plain.length)));
    assert.equal((await fetch(`${BASE}/api/items/${created.id}/chunks/0`, { method: "PUT", body: wire })).status, 204);
  }
  const { body: fin } = await j(`/api/items/${created.id}/finish`, { method: "POST" });
  assert.equal(fin.size, plain.length + 4 * OVERHEAD);

  const { body: list } = await j("/api/items");
  const row = list.find((x) => x.id === created.id);
  assert.equal((await decryptJson(key, row.meta)).name, "x.bin");

  const blob = new Uint8Array(await (await fetch(`${BASE}/api/items/${created.id}/blob`)).arrayBuffer());
  const out = [];
  for (let off = 0; off < blob.length; off += CHUNK + OVERHEAD) out.push(...await decryptBytes(key, blob.subarray(off, Math.min(off + CHUNK + OVERHEAD, blob.length))));
  assert.deepEqual(Uint8Array.from(out), plain);

  const other = await deriveKey("wrong", meta.salt, 1000);
  await assert.rejects(decryptJson(other, row.meta));

  assert.equal((await fetch(`${BASE}/api/items/${created.id}`, { method: "DELETE" })).status, 204);
  assert.equal((await fetch(`${BASE}/api/items/${created.id}`)).status, 404);

  // burn after read
  const { body: s } = await j("/api/items", { method: "POST", headers: JSON_H,
    body: JSON.stringify({ kind: "secret", meta: await encryptJson(key, { kind: "secret", name: "pw" }), chunkSize: CHUNK, burn: true, ttl: 3600 }) });
  await fetch(`${BASE}/api/items/${s.id}/chunks/0`, { method: "PUT", body: await encryptBytes(key, new TextEncoder().encode("hunter2")) });
  await j(`/api/items/${s.id}/finish`, { method: "POST" });
  const first = await fetch(`${BASE}/api/items/${s.id}/blob`);
  assert.equal(first.status, 200);
  assert.equal(new TextDecoder().decode(await decryptBytes(key, new Uint8Array(await first.arrayBuffer()))), "hunter2");
  assert.equal((await fetch(`${BASE}/api/items/${s.id}/blob`)).status, 404);
});

test("input validation", async () => {
  assert.equal((await fetch(`${BASE}/api/items/zz`)).status, 400);
  assert.equal((await j("/api/items", { method: "POST", headers: JSON_H, body: JSON.stringify({ kind: "evil", meta: "x", chunkSize: 4096 }) })).r.status, 400);
  assert.equal((await fetch(`${BASE}/%2e%2e/server.js`)).status, 404);
  assert.equal((await fetch(`${BASE}/i/abc`)).headers.get("content-type"), "text/html; charset=utf-8");
});
