# drop

E2EE file/note/secret drop between Loek's own devices. Zero-dependency Node 24+ server (`server.js`, `node:sqlite`) plus static PWA in `public/`. All crypto in `public/crypto.js`, UI in `public/app.js`.

- Never add a dependency. The zero-dep constraint (`node:` builtins only) is deliberate.
- Server must never receive plaintext or the passphrase. Any new field that carries user content goes inside the encrypted `meta` JSON, not a DB column.
- Wire format for blobs: repeated `[12-byte IV][ciphertext][16-byte tag]` chunks, plaintext chunk size in `items.chunk_size`. Changing it breaks existing data.
- Tests: `PORT=8399 DATA_DIR=./data-test node server.js &` then `npm test`. Delete `data-test/` after.
- American English, no em-dashes, comments 2-3 lines max.
