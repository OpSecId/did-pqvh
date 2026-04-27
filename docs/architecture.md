# did-pqvh architecture notes

## Intent

Replicate the DID WebVH-style update/signature pattern but use:
- cryptosuite: `mldsa44-jcs-2024` ([[di-quantum-safe]]); proof `type` is `DataIntegrityProof`
- crypto primitive: ML-DSA (FIPS 204 family)

instead of:
- `eddsa-jcs-2022`

## Flow mapping (WebVH-like)

1. Build history entry JSON (without signature object).
   - Include top-level `parameters` block mirroring WebVH method parameters.
   - Include `state` as a DID Document (minimal: `@context` first entry `https://www.w3.org/ns/did/v1` + `id`). On create, `state.id` may use `{SCID}` placeholder and the server finalizes it.
2. Build a Data Integrity proof per [[di-quantum-safe]] **Create Proof (ML-DSA)** (§3.3.1): proof configuration (JCS), transformation (JCS of the unsecured entry), then **SHA-256** hashing to **hashData** (config hash ‖ document hash).
3. Sign **hashData** with ML-DSA-44 using the library’s **`sign_external_mu`** path (64-byte μ).
4. Set `proof.proofValue` to **multibase `u` + base64url** (no pad) of the signature octets.
5. Verifier follows **§3.3.2 Verify Proof (ML-DSA)**: derive ``unsecuredDocument`` (secured map without ``proof``), ``proofOptions`` (``proof`` without ``proofValue``), recompute **hashData**, multibase-decode ``proofValue`` to **proofBytes**, run proof verification; ``VerificationResult`` exposes ``verified`` and ``verifiedDocument`` (unsecured map or null).

## Current prototype choices

- OpenAPI: operations are grouped under tags **`server`** (e.g. health), **`keys`**, **`scids`** (root SCID log CRUD), **`dids`** (`GET /resolve`), **`credentials`**.
- Library: `dilithium-py` (`ML_DSA_44` — ML-DSA-44 parameter set)
- Signature in `proofValue`: multibase **base64url** (`u` prefix) without padding
- API endpoints:
  - `POST /keys` -> create key resource (seed material; store keyed by ``publicKeyMultibase``)
  - `GET /keys/{publicKeyMultibase}` / `PUT` / `DELETE` -> read, update (may move to new multibase), delete
  - `POST /` -> create SCID resource; signing key is the first matching hash in `parameters.preRotationKeys` (or server-generated key when that list is empty, stored like `POST /keys`); response body is `{ "logEntry": ... }` and response header **`X-Scid-Auth-Secret`** holds a per-DID shared secret for subsequent writes
  - `GET /{scid}` -> **NDJSON** stream (`application/x-ndjson`): one JSON signed log entry per line, oldest first (append-only history: create then each `PUT`); no write secret required
  - `PUT /{scid}` / `DELETE /{scid}` -> append updated signed entry, or delete entire log; both require request header **`X-Scid-Auth-Secret`** equal to the value from create (**403** if missing or invalid). Path accepts bare base58 SCID or full `did:pqvh:<SCID>`; registered last so `/health`, `/keys`, `/resolve`, `/credentials` win. Treat the secret like a bearer: use TLS, and avoid logging that header at proxies.
  - `GET /resolve?did={did}` -> same NDJSON stream as `GET /{scid}` (full `did:pqvh:…` or bare SCID)
  - `POST /credentials/issue` -> minimal W3C VC (`@context`, `type`, `issuer`, `issuanceDate`, `credentialSubject`) + `mldsa44-jcs-2024` proof
  - `POST /credentials/verify` -> verify secured VC + public key; returns unsecured credential when valid
- Proof shape:

```json
{
  "type": "DataIntegrityProof",
  "cryptosuite": "mldsa44-jcs-2024",
  "verificationMethod": "did:key:z<ML-DSA_publicKeyMultibase>#vm",
  "created": "2026-04-27T00:00:00Z",
  "proofValue": "u<base64url-nopad-of-2420-signature-bytes>"
}
```

- Entry envelope shape (prototype):
- `preRotationKeys` is the only pre-rotation field in this API, replacing separate `updateKeys` and `nextKeyHashes` fields. Each value uses the did:webvh next-key-hash format: `base58btc(multihash(multikey))`.
- `method`/`scid` are response-only fields injected into the create response `logEntry.parameters` (`method = pqvh:1.0`, `scid = finalized SCID`).

```json
{
  "versionId": "1-Qm...",
  "versionTime": "2026-04-27T00:00:00Z",
  "state": {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:pqvh:Qm..."
  },
  "parameters": {
    "method": "pqvh:1.0",
    "scid": "Qm...",
    "preRotationKeys": ["QmcGZKdgovo6gTCfU5Ddf53j9PwuSQrJEscXEjFCPQy7NJ"],
    "witness": {"threshold": 0, "witnesses": []},
    "watchers": []
  }
}
```

## Caveat

`dilithium-py` is educational and not production-hardened. This repo is for interoperability
and format validation work, not production signing.
