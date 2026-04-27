# did-pqvh

WebVH-style DID history experiments using ML-DSA (FIPS 204) and JSON Canonicalization Scheme (JCS).

Current target Data Integrity cryptosuite (W3C CCG [di-quantum-safe](https://w3c-ccg.github.io/di-quantum-safe/)):
- `mldsa44-jcs-2024` with proof `type` `DataIntegrityProof` (instead of `eddsa-jcs-2022`)
- ML-DSA parameter set **44** (`ML_DSA_44` via `dilithium-py`)

## Goal

Keep the did:webvh-style update flow (canonical JSON payload + detached signature over canonical bytes),
but swap the signing primitive from EdDSA to ML-DSA.

## Status

This repository currently provides:
- A minimal signer/verifier interface for `mldsa44-jcs-2024`
- JCS-based canonical payload serialization
- A small CLI demo for signing/verifying payload files

## Security note

`dilithium-py` explicitly states it is educational and not side-channel hardened.
Use this repository for interoperability prototyping, not production cryptographic assurance.

## Quick start (uv)

```bash
uv sync
```

Sign payload JSON:

```bash
uv run did-pqvh sign --in payload.json --secret-key secret.key --verification-method did:webvh:example#key-1 --out proof.json
```

Verify proof:

```bash
uv run did-pqvh verify --in payload.json --proof proof.json --public-key public.key
```

Run API server (short form):

```bash
uv run serve
```

Same as `uv run did-pqvh serve` (optional `--host`, `--port`, `--no-reload`). Under the hood this runs uvicorn with reload on by default. Equivalent manual invocation:

```bash
uv run uvicorn did_pqvh.api:app --reload
```

**Landing UI:** open **`GET /`** in a browser for the **myscid.com** page (creates a SCID with `POST /` from the client).

**Environment (HTTP API)**

| Variable | Effect |
| -------- | ------ |
| `KEY_MANAGEMENT` | Default **off**. Set to **`true`**, **`1`**, **`yes`**, or **`on`** (case-insensitive) to register the **`/keys`** REST API and show the **keys** group in OpenAPI. When off, **`/keys`** responds with **404** (reserved so paths are not mistaken for `GET /{scid}`); key material is still used internally for server-generated signing keys on **`POST /`**. |
| `DID_PQVH_WALLET_DIR` | If set (e.g. **`/wallets`**), each **`did:pqvh`** SCID log is stored in **Aries Askar** SQLite at **`{DIR}/{SCID}.sqlite`** (one encrypted DB per SCID). Requires **`DID_PQVH_ASKAR_PASS_KEY`**. When unset, SCID logs stay in-memory only (JWTs still use **`DID_PQVH_ACCESS_TOKEN_SECRET`** or an ephemeral process secret). |
| `DID_PQVH_ASKAR_PASS_KEY` | Raw Askar store key (generate once, e.g. `uv run python -c 'from aries_askar import Store; print(Store.generate_raw_key())'`). Required whenever **`DID_PQVH_WALLET_DIR`** is set; keep stable across restarts or wallets cannot be reopened. |
| `DID_PQVH_ACCESS_TOKEN_SECRET` | UTF-8 secret used to sign **`access_token`** (HS256 JWT from **`POST /`**). Prefer **≥ 32 bytes** of random material (PyJWT warns on short keys). If unset, a random **per-process** secret is used (**restart invalidates** outstanding tokens; multi-worker setups must set this to the same value). **Set in production.** |
| `DID_PQVH_ACCESS_TOKEN_TTL_SECONDS` | JWT lifetime in seconds (`exp` − `iat`; default **90 days**, clamped between **60** and **365 days**). |
| `DID_PQVH_WEBVH_HOSTNAME` | If non-empty, `GET /resolve` augments `didDocument.alsoKnownAs` with `did:webvh:{SCID}:{hostname}:alias:{alias}` for each alias registered for that DID in the server map (`{SCID}` is the `did:pqvh:` method-specific id; `{hostname}` is this value). This build does not expose HTTP APIs to add aliases. Omitted or empty disables that merge. |

**Key management HTTP API** (`KEY_MANAGEMENT=true`): keys are a REST resource (prototype **in-memory** store; restart clears it). The path parameter is **`publicKeyMultibase`** (multibase `z` + base58btc of the raw ML-DSA public key from the create response). Use that string as `/keys/{publicKeyMultibase}` (encode for HTTP if your client requires it).

- **`POST /keys`** — *(only if `KEY_MANAGEMENT` is enabled)* create (201); **409** if that `publicKeyMultibase` is already stored (same seed ⇒ same key).
- **`GET /keys/{publicKeyMultibase}`** / **`PUT`** / **`DELETE`** — *(same gate)* read, replace seed material (**PUT** may change the public key; if it does, the entry moves to the new multibase; **409** if that target is already taken), delete (204).

Use `seed` (UTF-8). Example uses 32×`0` demo material.

UTF-8 `seed` only:

```bash
curl -s -X POST "http://127.0.0.1:8000/keys" \
  -H "content-type: application/json" \
  -d '{"seed": "00000000000000000000000000000000"}'
```

Read back (substitute `publicKeyMultibase` from the POST response body):

```bash
PUB="$(curl -s -X POST "http://127.0.0.1:8000/keys" -H "content-type: application/json" \
  -d '{"seed": "00000000000000000000000000000000"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['publicKeyMultibase'])")"
curl -s "http://127.0.0.1:8000/keys/${PUB}"
```

Issue a minimal Verifiable Credential (`POST /credentials/issue`):

```bash
curl -s -X POST "http://127.0.0.1:8000/credentials/issue" \
  -H "content-type: application/json" \
  -d '{
    "issuer": "did:pqvh:issuer",
    "credentialSubject": {"id": "did:pqvh:subject"},
    "verification_method": "did:pqvh:issuer#key-1"
  }'
```

Response keys (key resources):
- `created` (UTC, RFC 3339 with `Z`)
- `publicKeyMultibase` / `secretKeyMultibase` — multibase **`z` + base58btc** of the raw ML-DSA keys (`publicKeyMultibase` is the resource path)

**SCID** resources hold an append-only signed log per DID (prototype **in-memory** store keyed by `state.id`; restart clears it):

- `parameters.preRotationKeys` is the single pre-rotation array in this API (we do not expose separate `updateKeys` or `nextKeyHashes`). Each item is a key hash using the did:webvh `nextKeyHashes` format: `base58btc(multihash(multikey))` (e.g. `Qm...`).
- `parameters.method` and `parameters.scid` are response-only fields generated by create and included in `logEntry`.

- **`POST /`** — create (201); fails with **409** if that `state.id` already exists. Response body is **`{ "logEntry": { … }, "access_token": "<jwt>", "token_type": "Bearer" }`**: **`access_token`** is an **HS256 JWT** (`sub` = full `did:pqvh:…`, `typ` = `pqvh_scid_write`, `iat` / `exp`; see env **`DID_PQVH_ACCESS_TOKEN_*`**). Send **`Authorization: Bearer <access_token>`** on **`PUT`** / **`DELETE`** for that DID. You may send **`{"options":{},"parameters":{},"state":{}}`**: the server registers a new ML-DSA signing key (same internal shape as key resources when **`KEY_MANAGEMENT`** is on), sets **`parameters.preRotationKeys`** to that key’s **`preRotationKey`**, and defaults **`state`** to a minimal DID document with **`id`: `did:pqvh:{SCID}`**. If **`KEY_MANAGEMENT`** is enabled and you use **`POST /keys`**, supply **`preRotationKeys`** as before. Use **HTTPS** in real deployments; configure proxies not to log **`Authorization`** on these routes.
- **`GET /{scid}`** — **NDJSON** stream (`Content-Type: application/x-ndjson`): one compact JSON **log entry** per line, **oldest first** (create, then each `PUT`). **`{scid}`** may be the **bare base58 SCID** or full **`did:pqvh:`** + that string (one path segment; percent-encode colons if needed). Registered after reserved paths (`/health`, optional `/keys`, `/resolve`, `/alias/…`, `/credentials`, etc.). Read does **not** require a bearer token.
- **Aliases** — **`GET /alias/{alias}`** only: streams the same **NDJSON** as **`GET /{scid}`** when that alias exists in the server’s in-memory map (**404** otherwise). There is **no** `POST` / `DELETE` for aliases in this build; the map is reserved for operator wiring. Deleting a SCID log (**`DELETE /{scid}`**) still clears any alias rows pointing at that DID.
- **`PUT /{scid}`** — update document/parameters and re-sign; body `state.id` must match the path after the same SCID normalization as **`GET /{scid}`**. Requires **`Authorization: Bearer <access_token>`** (the JWT from create; **403** if missing, wrong, or **expired**).
- **`DELETE /{scid}`** — remove (204); same path rules as **`GET /{scid}`** and the same **`Authorization: Bearer`** requirement (**403** if missing, wrong, or expired).
- **`GET /resolve?did={did}`** — JSON **`{ "didDocument": { … } }`**: the **`state`** map from the **latest** signed log entry for that DID. **`did`** is full **`did:pqvh:…`** or bare SCID (same normalization as **`GET /{scid}`**; local store only in this prototype). For the full append-only history, use **`GET /{scid}`** (NDJSON). If **`DID_PQVH_WEBVH_HOSTNAME`** is set (e.g. `wallets.example.com`), the resolved document merges **`alsoKnownAs`** with one synthetic WebVH-style DID per registered alias: **`did:webvh:{SCID}:{hostname}:alias:{alias}`** (not present in the signed NDJSON log; resolve-only; alias map is not populated via HTTP here).

Minimal create (server-generated signing key; key material lives in the internal store; with **`KEY_MANAGEMENT=true`** you can read it via **`GET /keys/{publicKeyMultibase}`** using the multibase from **`logEntry.proof.verificationMethod`**):

```bash
curl -s -X POST "http://127.0.0.1:8000/" \
  -H "content-type: application/json" \
  -d '{"options":{},"parameters":{},"state":{}}'
```

Create with an existing key from **`POST /keys`** (requires **`KEY_MANAGEMENT=true`**):

```bash
PUB="$(curl -s -X POST "http://127.0.0.1:8000/keys" -H "content-type: application/json" \
  -d '{"seed": "00000000000000000000000000000000"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['publicKeyMultibase'])")"
curl -s -X POST "http://127.0.0.1:8000/" \
  -H "content-type: application/json" \
  -d "$(PUB="$PUB" python3 -c 'import hashlib,json,os,base58; pub=os.environ["PUB"]; digest=hashlib.sha256(pub.encode("utf-8")).digest(); pre_rot=base58.b58encode(b"\x12\x20"+digest).decode("ascii"); print(json.dumps({"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:pqvh:{SCID}"},"parameters":{"preRotationKeys":[pre_rot],"witness":{"threshold":0,"witnesses":[]},"watchers":[]},"options":{}}))')"
```

```bash
SCID="$(curl -s -X POST "http://127.0.0.1:8000/" -H "content-type: application/json" \
  -d "$(PUB="$PUB" python3 -c 'import hashlib,json,os,base58; pub=os.environ["PUB"]; digest=hashlib.sha256(pub.encode("utf-8")).digest(); pre_rot=base58.b58encode(b"\x12\x20"+digest).decode("ascii"); print(json.dumps({"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:pqvh:{SCID}"},"parameters":{"preRotationKeys":[pre_rot],"witness":{"threshold":0,"witnesses":[]},"watchers":[]},"options":{}}))')" | python3 -c "import sys,json,urllib.parse; print(urllib.parse.quote(json.load(sys.stdin)['logEntry']['state']['id'], safe=''))")"
curl -s "http://127.0.0.1:8000/${SCID}"
```

```bash
curl -s "http://127.0.0.1:8000/resolve?did=did%3Apqvh%3AQm..."
# → {"didDocument":{"@context":[...],"id":"did:pqvh:…", ...}}
```

Each NDJSON line is a did:webvh-style signed log entry object with **`versionId`**, **`versionTime`**, **`state`**, **`parameters`**, and **`proof`**.

Verify a credential (`POST /credentials/verify`): body has the secured `credential` JSON (with top-level `proof`) and the issuer’s public key in one of the same two forms. Response includes `verified` and the unsecured `credential` when valid.

## Dependency management

- Add dependency: `uv add <package>`
- Add dev dependency: `uv add --dev <package>`
- Refresh lockfile: `uv lock`
