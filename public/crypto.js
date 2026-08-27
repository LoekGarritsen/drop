// All crypto happens here, in the browser. Server only ever sees output of
// these functions. AES-256-GCM, fresh 96-bit IV per message/chunk.
const enc = new TextEncoder();
const dec = new TextDecoder();
export const IV_BYTES = 12;
export const TAG_BYTES = 16;
export const OVERHEAD = IV_BYTES + TAG_BYTES;

export const b64 = {
  to: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  from: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};

export async function deriveKey(passphrase, saltB64, iterations = 600_000) {
  const material = await crypto.subtle.importKey("raw", enc.encode(passphrase.normalize("NFKC")), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: b64.from(saltB64), iterations },
    material, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

export const exportKey = async (key) => b64.to(await crypto.subtle.exportKey("raw", key));
export const importKey = (raw) =>
  crypto.subtle.importKey("raw", b64.from(raw), { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);

export async function encryptBytes(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes));
  const out = new Uint8Array(IV_BYTES + ct.length);
  out.set(iv, 0); out.set(ct, IV_BYTES);
  return out;
}

export async function decryptBytes(key, wire) {
  const iv = wire.subarray(0, IV_BYTES);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, wire.subarray(IV_BYTES)));
}

export const encryptJson = async (key, obj) => b64.to(await encryptBytes(key, enc.encode(JSON.stringify(obj))));
export const decryptJson = async (key, s) => JSON.parse(dec.decode(await decryptBytes(key, b64.from(s))));
