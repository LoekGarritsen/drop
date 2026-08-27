import { deriveKey, exportKey, importKey, encryptBytes, decryptBytes, encryptJson, decryptJson, OVERHEAD } from "/crypto.js";

const CHUNK = 8 * 1024 * 1024;
const $ = (s) => document.querySelector(s);
const state = { key: null, meta: null, items: [], tab: "files", decrypted: new Map() };

// --- tiny helpers -------------------------------------------------------
const api = async (path, opts = {}) => {
  const res = await fetch(`/api${path}`, opts);
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `${res.status}`);
  return res.status === 204 ? null : res.headers.get("content-type")?.includes("json") ? res.json() : res;
};
let toastTimer;
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), 2200);
}
const fmtSize = (n) => n < 1024 ? `${n} B` : n < 1024 ** 2 ? `${(n / 1024).toFixed(0)} KB`
  : n < 1024 ** 3 ? `${(n / 1024 ** 2).toFixed(1)} MB` : `${(n / 1024 ** 3).toFixed(2)} GB`;
const fmtWhen = (ts) => {
  const d = (Date.now() / 1000 - ts) / 60;
  if (d < 1) return "just now"; if (d < 60) return `${d | 0} min ago`;
  if (d < 1440) return `${(d / 60) | 0} h ago`; return new Date(ts * 1000).toLocaleDateString();
};
const fmtLeft = (ts) => { const h = (ts - Date.now() / 1000) / 3600; return h < 1 ? `${Math.max(1, h * 60 | 0)} min left` : h < 48 ? `${h | 0} h left` : `${Math.round(h / 24)} d left`; };
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied"); }
  catch { prompt("Copy:", text); }
}

// --- vault --------------------------------------------------------------
async function loadMeta() { state.meta = await api("/meta"); }

async function tryStoredKey() {
  const raw = localStorage.getItem("drop.key");
  if (!raw) return false;
  try { state.key = await importKey(raw); await decryptJson(state.key, state.meta.check); return true; }
  catch { localStorage.removeItem("drop.key"); return false; }
}

async function unlock(passphrase, remember) {
  const key = await deriveKey(passphrase, state.meta.salt);
  if (state.meta.check) {
    try { await decryptJson(key, state.meta.check); }
    catch { throw new Error("Wrong passphrase"); }
  } else {
    const check = await encryptJson(key, { ok: true, t: Date.now() });
    await api("/meta", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ check }) });
    state.meta.check = check;
  }
  state.key = key;
  if (remember) localStorage.setItem("drop.key", await exportKey(key));
}

function lock() {
  localStorage.removeItem("drop.key");
  state.key = null; state.decrypted.clear();
  location.reload();
}

// --- upload -------------------------------------------------------------
function progress(done, total, label) {
  const p = $("#progress"); p.hidden = total === null;
  if (total === null) return;
  $("#progress-bar").style.width = `${(done / total) * 100}%`;
  $("#progress-text").textContent = `${label} ${Math.round((done / total) * 100)}%`;
}

async function createItem(kind, metaObj, burn = false) {
  const meta = await encryptJson(state.key, metaObj);
  return api("/items", { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ kind, meta, chunkSize: CHUNK, burn, ttl: Number($("#ttl").value) }) });
}

async function uploadBytes(id, source, total, label) {
  // source: Blob (file) or Uint8Array (note/secret). Encrypt chunk by chunk
  // so multi-GB files never sit in memory as one buffer.
  let off = 0;
  while (off < total || (total === 0 && off === 0)) {
    const end = Math.min(off + CHUNK, total);
    const plain = source instanceof Blob ? new Uint8Array(await source.slice(off, end).arrayBuffer()) : source.subarray(off, end);
    const wire = await encryptBytes(state.key, plain);
    await api(`/items/${id}/chunks/0`, { method: "PUT", body: wire, headers: { "content-type": "application/octet-stream" } });
    off = end; progress(off, total, label);
    if (total === 0) break;
  }
  await api(`/items/${id}/finish`, { method: "POST" });
  progress(0, null);
}

async function uploadFile(file) {
  const { id } = await createItem("file", { kind: "file", name: file.name, mime: file.type || "application/octet-stream", size: file.size });
  try { await uploadBytes(id, file, file.size, file.name); toast(`Uploaded ${file.name}`); }
  catch (e) { await api(`/items/${id}`, { method: "DELETE" }).catch(() => {}); throw e; }
}

async function uploadText(kind, metaObj, text, burn) {
  const bytes = new TextEncoder().encode(text);
  const { id } = await createItem(kind, { ...metaObj, kind, size: bytes.length }, burn);
  await uploadBytes(id, bytes, bytes.length, metaObj.name);
  toast(kind === "secret" ? "Secret saved" : "Note saved");
}

async function handleFiles(files) {
  for (const f of files) {
    if (f.size > state.meta.maxItemBytes) { toast(`${f.name} too large`); continue; }
    try { await uploadFile(f); } catch (e) { toast(`Upload failed: ${e.message}`); progress(0, null); }
  }
}

// --- download / open ----------------------------------------------------
async function fetchPlain(item) {
  const res = await api(`/items/${item.id}/blob`);
  const wire = new Uint8Array(await res.arrayBuffer());
  const step = item.chunk_size + OVERHEAD;
  const parts = [];
  for (let off = 0; off < wire.length; off += step) parts.push(await decryptBytes(state.key, wire.subarray(off, Math.min(off + step, wire.length))));
  return new Blob(parts);
}

async function openItem(item, el) {
  const m = state.decrypted.get(item.id);
  if (m.kind === "file") {
    toast("Downloading…");
    const blob = await fetchPlain(item);
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([blob], { type: m.mime })), download: m.name });
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 30_000);
    return;
  }
  if (item.burn && !confirm(`Reveal "${m.name}"? It is deleted from the server the moment it is shown.`)) return;
  const text = await (await fetchPlain(item)).text();
  const pre = el.querySelector(".item-preview");
  pre.textContent = text; pre.hidden = false;
  el.dataset.text = text;
  if (item.burn) { el.classList.add("revealed"); el.querySelector(".act-open").disabled = true; }
}

async function copyItem(item, el) {
  const m = state.decrypted.get(item.id);
  if (m.kind === "file") return copyText(`${location.origin}/i/${item.id}`);
  if (item.burn && el.dataset.text === undefined) {
    if (!confirm(`Copy "${m.name}"? It is deleted from the server once copied.`)) return;
  }
  const text = el.dataset.text ?? (await (await fetchPlain(item)).text());
  el.dataset.text = text;
  await copyText(text);
  if (item.burn) el.querySelector(".act-open").disabled = true;
}

// --- list ---------------------------------------------------------------
const ICON = { file: "📄", note: "📝", secret: "🔑" };
const TAB_KIND = { files: "file", notes: "note", secrets: "secret" };

async function refresh() {
  state.items = await api("/items");
  await Promise.all(state.items.map(async (it) => {
    if (state.decrypted.has(it.id)) return;
    try { state.decrypted.set(it.id, await decryptJson(state.key, it.meta)); }
    catch { state.decrypted.set(it.id, { kind: it.kind, name: "(undecryptable: different passphrase)", broken: true }); }
  }));
  render();
}

function render() {
  const list = $("#list"); list.replaceChildren();
  const tpl = $("#item-tpl");
  const shown = state.items.filter((it) => state.decrypted.get(it.id)?.kind === TAB_KIND[state.tab]);
  $("#empty").hidden = shown.length > 0;
  for (const it of shown) {
    const m = state.decrypted.get(it.id);
    const el = tpl.content.firstElementChild.cloneNode(true);
    el.dataset.id = it.id;
    if (it.burn) el.classList.add("burn");
    el.querySelector(".item-icon").textContent = ICON[m.kind] || "📦";
    el.querySelector(".item-name").textContent = m.name || "(untitled)";
    el.querySelector(".item-sub").textContent = [m.kind === "file" ? fmtSize(m.size ?? it.size) : null,
      fmtWhen(it.created_at), fmtLeft(it.expires_at), it.views ? `${it.views} view${it.views > 1 ? "s" : ""}` : null].filter(Boolean).join(" · ");
    el.querySelector(".act-open").textContent = m.kind === "file" ? "Download" : it.burn ? "Reveal" : "Show";
    el.querySelector(".act-copy").textContent = m.kind === "file" ? "Copy link" : "Copy";
    if (m.broken) { el.querySelector(".act-open").disabled = true; el.querySelector(".act-copy").disabled = true; }
    el.querySelector(".act-open").onclick = () => openItem(it, el).catch((e) => toast(e.message));
    el.querySelector(".act-copy").onclick = () => copyItem(it, el).catch((e) => toast(e.message));
    el.querySelector(".act-delete").onclick = async () => {
      if (!confirm(`Delete "${m.name}"?`)) return;
      await api(`/items/${it.id}`, { method: "DELETE" }); refresh();
    };
    list.append(el);
  }
}

function setTab(tab) {
  state.tab = tab;
  document.querySelectorAll("nav button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  for (const t of ["files", "notes", "secrets"]) document.querySelectorAll(`.tab-${t}`).forEach((el) => (el.hidden = t !== tab));
  localStorage.setItem("drop.tab", tab); render();
}

// --- live updates -------------------------------------------------------
function connectEvents() {
  const es = new EventSource("/api/events");
  es.addEventListener("change", (e) => {
    const { id, op } = JSON.parse(e.data);
    if (op === "delete") state.decrypted.delete(id);
    refresh();
  });
  es.onerror = () => { es.close(); setTimeout(connectEvents, 3000); };
}

// --- share target / deep links ------------------------------------------
async function consumeShare() {
  if (!new URLSearchParams(location.search).has("shared")) return;
  history.replaceState(null, "", "/");
  const cache = await caches.open("drop-share");
  const payload = await (await cache.match("/share-payload"))?.json();
  if (!payload) return;
  const files = [];
  for (let i = 0; i < payload.files.length; i++) {
    const r = await cache.match(`/share-file-${i}`);
    if (r) files.push(new File([await r.blob()], payload.files[i].name || `shared-${i}`, { type: payload.files[i].type }));
  }
  await Promise.all([...Array(files.length).keys()].map((i) => cache.delete(`/share-file-${i}`)), cache.delete("/share-payload"));
  if (files.length) { setTab("files"); await handleFiles(files); }
  const text = [payload.title, payload.text, payload.url].filter(Boolean).join("\n");
  if (text && !files.length) { setTab("notes"); $("#note-title").value = payload.title || ""; $("#note-text").value = text.replace(payload.title || "", "").trim(); }
}

function highlightDeepLink() {
  const m = location.pathname.match(/^\/i\/([A-Za-z0-9_-]+)/);
  if (!m) return;
  history.replaceState(null, "", "/");
  const it = state.items.find((x) => x.id === m[1]);
  if (!it) return toast("Item not found or expired");
  const kind = state.decrypted.get(it.id)?.kind;
  setTab(Object.keys(TAB_KIND).find((t) => TAB_KIND[t] === kind) || "files");
  const el = $(`[data-id="${it.id}"]`); el?.scrollIntoView({ block: "center" }); el?.querySelector(".act-open").focus();
}

// --- wiring -------------------------------------------------------------
async function main() {
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});
  await loadMeta();

  const dlg = $("#unlock");
  if (!(await tryStoredKey())) {
    if (!state.meta.check) $("#unlock-hint").textContent = "New vault. Choose a passphrase; you will type it once on each device. There is no recovery if you lose it.";
    dlg.showModal();
    await new Promise((resolve) => {
      $("#unlock-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const btn = $("#unlock-btn"); btn.disabled = true; btn.textContent = "Deriving key…";
        try { await unlock($("#passphrase").value, $("#remember").checked); dlg.close(); resolve(); }
        catch (err) { $("#unlock-error").textContent = err.message; $("#unlock-error").hidden = false; }
        finally { btn.disabled = false; btn.textContent = "Unlock"; }
      });
      dlg.addEventListener("cancel", (e) => e.preventDefault());
    });
  }

  setTab(localStorage.getItem("drop.tab") || "files");
  await refresh();
  connectEvents();
  highlightDeepLink();
  consumeShare().catch((e) => toast(e.message));

  $("#lock").onclick = lock;
  document.querySelectorAll("nav button").forEach((b) => (b.onclick = () => setTab(b.dataset.tab)));
  $("#pick").onclick = () => $("#file-input").click();
  $("#file-input").onchange = (e) => { handleFiles([...e.target.files]); e.target.value = ""; };

  const dz = $("#dropzone");
  for (const ev of ["dragenter", "dragover"]) document.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("over"); });
  for (const ev of ["dragleave", "drop"]) document.addEventListener(ev, (e) => { e.preventDefault(); if (ev === "drop" || e.relatedTarget === null) dz.classList.remove("over"); });
  document.addEventListener("drop", (e) => { if (e.dataTransfer.files.length) { setTab("files"); handleFiles([...e.dataTransfer.files]); } });

  document.addEventListener("paste", (e) => {
    if (["TEXTAREA", "INPUT"].includes(e.target.tagName)) return;
    const files = [...e.clipboardData.files];
    if (files.length) { setTab("files"); return handleFiles(files); }
    const text = e.clipboardData.getData("text/plain");
    if (text) { setTab("notes"); $("#note-text").value = text; $("#note-text").focus(); }
  });

  $("#note-form").onsubmit = async (e) => {
    e.preventDefault();
    const text = $("#note-text").value; const name = $("#note-title").value.trim() || text.split("\n")[0].slice(0, 60);
    await uploadText("note", { name }, text, false).catch((err) => toast(err.message));
    e.target.reset();
  };
  $("#secret-form").onsubmit = async (e) => {
    e.preventDefault();
    const name = $("#secret-label").value.trim() || "secret";
    await uploadText("secret", { name }, $("#secret-text").value, $("#secret-burn").checked).catch((err) => toast(err.message));
    e.target.reset(); $("#secret-burn").checked = true;
  };
}
main().catch((e) => { console.error(e); toast(e.message); });
