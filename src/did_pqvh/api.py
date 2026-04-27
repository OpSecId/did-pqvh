"""HTTP API for did-pqvh."""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
import threading
from datetime import datetime, timezone
from typing import Annotated, Any, Self

import base58
from fastapi import Body, FastAPI, HTTPException, Path, Query
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .canonical import canonicalize_json
from .suite import KeyPair, make_proof, verify_payload, verify_proof_mldsa44_jcs
from .suite import generate_keypair as generate_ml_dsa_keypair
from .suite import generate_keypair_from_seed

app = FastAPI(
    title="did-pqvh API",
    version="0.1.0",
    openapi_tags=[
        {"name": "server", "description": "Server metadata and health endpoints."},
        {"name": "keys", "description": "ML-DSA keypair resources; path key is `publicKeyMultibase` (multibase `z` + base58btc)."},
        {
            "name": "dids",
            "description": (
                "DID WebVH-like signed history entries (SCID resources). "
                "Create/update requests use `options.apiKey` for operation protection. "
                "Create selects signing keys by sequential lookup of `parameters.preRotationKeys`."
            ),
        },
        {"name": "credentials", "description": "Verifiable Credentials (issue and verify)."},
    ],
)

# Prototype in-memory registry: ``state.id`` -> last ``CreateResponse`` (not persistent; not for production).
_scid_store_lock = threading.Lock()
_scid_store: dict[str, dict[str, Any]] = {}
_scid_api_key_store: dict[str, str] = {}
_pre_rotation_key_index: dict[str, str] = {}

_key_store_lock = threading.Lock()
_key_store: dict[str, dict[str, Any]] = {}

# Minimal DID document (https://www.w3.org/TR/did-1.1/) for default `state`.
MINIMAL_DID_DOCUMENT: dict[str, Any] = {
    "@context": ["https://www.w3.org/ns/did/v1.1"],
    "id": "did:pqvh:{SCID}",
}

# ``GET /{scid}`` only: full ``did:pqvh`` DID whose method-specific id is base58btc (SHA-256 multihash
# from ``_entry_hash`` is always 46 chars; allow a small range for future hash widths).
SCID_ROOT_DID_PATH_PATTERN = r"^did:pqvh:[1-9A-HJ-NP-Za-km-z]{43,48}$"


class WitnessConfig(BaseModel):
    """WebVH-style witness block (prototype defaults)."""

    model_config = ConfigDict(extra="allow")

    threshold: int = Field(0, description="Witness threshold.")
    witnesses: list[Any] = Field(
        default_factory=list,
        description="Witness entries (method-specific).",
    )


class WebVHParameters(BaseModel):
    """WebVH-like DID method parameters (stored next to `state` in the signed entry)."""

    model_config = ConfigDict(extra="allow")

    preRotationKeys: list[str] = Field(
        default_factory=list,
        description=(
            "Pre-rotation key hashes (single array replacing `updateKeys`/`nextKeyHashes` semantics). "
            "Each value is a hash string in the same format as did:webvh `nextKeyHashes`: "
            "`base58btc(multihash(multikey))`."
        ),
    )
    witness: WitnessConfig = Field(default_factory=WitnessConfig)
    watchers: list[Any] = Field(
        default_factory=list,
        description="Watcher entries (method-specific; e.g. endpoint URLs or descriptor objects).",
    )

    @model_validator(mode="after")
    def _forbid_reserved_response_only_fields(self) -> Self:
        extra = self.model_extra or {}
        forbidden = [k for k in ("method", "scid") if k in extra]
        if forbidden:
            names = ", ".join(forbidden)
            raise ValueError(
                f"`parameters.{names}` is response-only and must not be supplied in request bodies."
            )
        return self


class AliasDidState(BaseModel):
    """DID document material for a SCID resource (`state` in the signed entry)."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    context: list[str] | str | None = Field(
        default_factory=lambda: ["https://www.w3.org/ns/did/v1.1"],
        alias="@context",
        description="JSON-LD `@context` (string or array of strings).",
    )
    id: str = Field(
        default="did:pqvh:{SCID}",
        min_length=1,
        description=(
            "DID string; storage key for `GET /dids/{scid}` (URL-encode the path segment). "
            "Defaults to `did:pqvh:{SCID}` so `state: {}` is valid on create."
        ),
    )

DEFAULT_VC_CONTEXT: list[Any] = ["https://www.w3.org/2018/credentials/v1"]

# Demo seed: UTF-8 "00000000000000000000000000000000".
_KEY_CREATE_EXAMPLE_PUBLIC_KEY_MULTIBASE = (
    "z13xsJx6JnnwtBKuXcz9xkTbWNjSHF2pCwtVANVymgVgYzksv9UoXNHspZXVU4tkYDNDpbPCvR3mwAkYc9qcfZXtV9CchmzrpjyKyBH9veqZnHcLxrng8G9C6rm9EycB9dmQCsidoJeytqNAVafn3FW8ZX99PDqrb9P1CMXDfpXRUC5tjCdhoDhVFP6353weMYxCghTpMRZf9oWJDERV6jWaKXxiSk1RXMJCjzP2nyquRr6qhjvSfB5iF4cCF5LsHJBdEhcTG63JMCHtUj24RgyKvKZ6g3se3Yd7cKz2y8pKCsGNhJJzhRqkhRRmhNhEGwQqqnepodyjtBB5cQbGX1HKFstn1aBqh78XWy4TQRC7ah7Gp81TGNNYbAUezsDQoWNBDfLfxjAxG5XviCXk7Abt2jxjZxCGbYVoxigzbngHyzHW1YS7xWVmsBM64xxaP7Bx9osEtRSH9KxosRw8fL8M9372TwNZSwbboENAWguN6FgM2LRxqHdWfm8Y6WZ6xLbMaDmVcwsDEZRf1wbwazfceaRN5yGRq7fVgYYdqEgyDUKw7RJJeVhgzEvT9L3uDvJJuxZgGg7WnBBCNVWPiM9Yy24ko5twXFtDdVBi9dX7E5vrbskena9SZCNNT4g7r75ia3pTmRJudYdakLS3is2XFEjcTYkCspRNNYSFKiACi6qzRmX4ttLPcKQ76CTENBAki8GDStAJ4cdxkrgY74guADgHQVLN6hKWVcT9M6dPKUWv2xvsuXCqThcC2qoAzqtR23S1tFSdzRgVJFhA2saZCerRsgZun9ShgBWeoA6WEZ1Ze3gX55RUcFUH2rC4cSDV2vWocA4ZXobdc8Hk23nH4HyUXK4Uzba3corGzkBrSNxCytMahv1E2YFvM9Uqo5pcoBo6mUXT6c7a53akpxa1W8Cvby8Y32uAXRufJTqbe9UBSmZXNN4JxUqpo4Z3ohQ8VYy615uh4NBckvLAeQLqLeARrN3YhGWCnVM382ziJnwUTciX1pqqorm4zC6mdoneKhpxVhxj9cu55Qg7SiPAMX1w3eK8Hi81DhUQLX3dyaaApKvFzU1atJPKVZFiTr8dgxBuWty9ePYkH2G9a1cUQNkRa5yxwM4uxhpJGpwgkurKU67gcAeNUHAXGnEqzoUq6D55M1sPY8zwm1KrdSKgL7qySud9YeXBnPsH1pQtWhjKGsxcXY7LvoburbN9cQkJVaNUmGz33GgdVS6Nq7GFyY2VVjD6rJVYM2EVfWuY6SSdEpYSmSnfofSVbExUKaf4rUKSjJdLuPLAzh2hYPJQvPHfwJ6H9oXn1sDS68QrDWbSatCzf6ZGgkyLmdoDcx7MPd36d39Ku3DYjgpeSLiZgYTvCfnX9UeM13wsaNr2PewQ54GDiTCA52nD8UHBaXhfHyuYGditLsUY15Cpt2RVdKzWh2WcrBDa4fedSTdU4BQGWMkF9gLufhspT6hjxgKVRQkmPC9D2fkhQAHEe9JDD5vb2PUqkaqzK666fRLfJWAsJ6VkhGKzSBhMBpGcidvu1Azm5cwfjuoeQuUm2FR6nUwJ4hypr7vtfhWXd4CXsGirG1D8epNYpSQ4Dv1qyvZw5wTbZ77hw1yD9uod1iRTc6adLxpKXyF9cYspdbxc6cH9jj1pymQU9HdZrGTWEWAjrSPYDaHfhp9Mb2imw9RnxASKVwQxDuEJ1o4kuxa8vtGCf7DtmvD8uqHSh5at3AWoLKafdGmcwjurnGc18HTfbRhc86ZjWjdkH8fyqnGwNhuMvuQgHAWnQQEtzWqAf"
)
_KEY_CREATE_EXAMPLE_PRE_ROTATION_KEY_HASH = "QmcGZKdgovo6gTCfU5Ddf53j9PwuSQrJEscXEjFCPQy7NJ"


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))


def _multibase_encode(data: bytes) -> str:
    # multibase base58btc — same convention as typical did:key / IPFS multibase strings (`z` prefix).
    return "z" + base58.b58encode(data).decode("ascii")


def _multibase_decode_bytes(data: str) -> bytes:
    if not data:
        raise ValueError("Empty multibase string")
    prefix, rest = data[0], data[1:]
    if prefix == "u":
        return _b64u_decode(rest)
    if prefix == "z":
        try:
            return base58.b58decode(rest)
        except ValueError as e:
            raise ValueError(f"Invalid multibase base58btc payload: {e}") from e
    raise ValueError(
        "Unsupported multibase prefix; use 'z' (base58btc) or 'u' (base64url, no pad)"
    )


def _multibase_decode(data: str) -> bytes:
    try:
        return _multibase_decode_bytes(data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


def _utc_created() -> str:
    """RFC 3339 / ISO 8601 UTC with Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _did_id_from_state(state: AliasDidState) -> str:
    return state.id


def _multihash_sha256_base58(data: bytes) -> str:
    """Encode SHA-256 multihash as base58btc string (did:webvh-style hash encoding)."""
    digest = hashlib.sha256(data).digest()
    multihash = b"\x12\x20" + digest  # 0x12 = sha2-256, 0x20 = 32-byte digest length
    return base58.b58encode(multihash).decode("ascii")


def _entry_hash(unsecured_log_entry: dict[str, Any]) -> str:
    return _multihash_sha256_base58(canonicalize_json(unsecured_log_entry))


def _resolve_state_id_with_scid(state_obj: dict[str, Any], scid: str) -> dict[str, Any]:
    out = dict(state_obj)
    did = out.get("id")
    if isinstance(did, str) and "{SCID}" in did:
        out["id"] = did.replace("{SCID}", scid)
    return out


def _compact_parameters(parameters: dict[str, Any]) -> dict[str, Any]:
    """Drop default-empty parameter blocks from serialized entries/responses."""
    out = dict(parameters)

    watchers = out.get("watchers")
    if isinstance(watchers, list) and len(watchers) == 0:
        out.pop("watchers", None)

    witness = out.get("witness")
    if isinstance(witness, dict):
        threshold = witness.get("threshold")
        witnesses = witness.get("witnesses")
        extra_keys = [k for k in witness.keys() if k not in {"threshold", "witnesses"}]
        if threshold == 0 and isinstance(witnesses, list) and len(witnesses) == 0 and len(extra_keys) == 0:
            out.pop("witness", None)

    return out


def _public_key_multibase_from_did_key_verification_method(verification_method: str) -> str:
    """Parse a did:key verification method as ``did:key:{mb}#{mb}``; return ``mb`` for ``/keys`` lookup."""
    prefix = "did:key:"
    if not verification_method.startswith(prefix):
        raise HTTPException(
            status_code=400,
            detail=(
                "verificationMethod must be did:key:{publicKeyMultibase}#{same_publicKeyMultibase} "
                "(multibase from POST /keys, repeated after did:key: and as the fragment)."
            ),
        )
    rest = verification_method[len(prefix) :]
    if "#" not in rest:
        raise HTTPException(
            status_code=400,
            detail="verificationMethod must include a # fragment matching the did:key method id.",
        )
    method_id, fragment = rest.split("#", 1)
    if not method_id or method_id != fragment:
        raise HTTPException(
            status_code=400,
            detail=(
                "verificationMethod must be did:key:{publicKeyMultibase}#{publicKeyMultibase} "
                "with the same multibase in both places."
            ),
        )
    return method_id


def _keypair_from_key_store(public_key_multibase: str) -> KeyPair:
    with _key_store_lock:
        raw = _key_store.get(public_key_multibase)
    if raw is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No key resource for publicKeyMultibase={public_key_multibase!r}. "
                "Create it with POST /keys first (path must match exactly)."
            ),
        )
    rec = KeyCreateResponse.model_validate(raw)
    return KeyPair(
        public_key=_multibase_decode(rec.publicKeyMultibase),
        secret_key=_multibase_decode(rec.secretKeyMultibase),
    )


def _keypair_from_pre_rotation_keys(pre_rotation_keys: list[str]) -> tuple[KeyPair, str]:
    """Select first existing key by ordered `preRotationKeys` lookup."""
    if not pre_rotation_keys:
        raise HTTPException(status_code=400, detail="parameters.preRotationKeys must include at least one key hash.")
    for key_hash in pre_rotation_keys:
        with _key_store_lock:
            public_key_multibase = _pre_rotation_key_index.get(key_hash)
        if public_key_multibase is None:
            continue
        return _keypair_from_key_store(public_key_multibase), public_key_multibase
    raise HTTPException(
        status_code=404,
        detail="No signing key found for supplied parameters.preRotationKeys (checked in order).",
    )


def _create_did_record(
    req: CreateRequest,
    *,
    keypair: KeyPair,
    verification_method: str,
    version_number: int,
    allow_scid_placeholder: bool = False,
) -> CreateResponse:
    version_time = _utc_created()
    state_obj = req.state.model_dump(by_alias=True, exclude_none=True)
    params_obj = _compact_parameters(req.parameters.model_dump(exclude_none=True))
    preliminary = {
        "versionId": "{SCID}",
        "versionTime": version_time,
        "state": state_obj,
        "parameters": params_obj,
    }
    if allow_scid_placeholder:
        scid = _entry_hash(preliminary)
        state_obj = _resolve_state_id_with_scid(state_obj, scid)
        params_obj["method"] = "pqvh:1.0"
        params_obj["scid"] = scid
    elif "{SCID}" in str(state_obj.get("id", "")):
        raise HTTPException(status_code=400, detail="state.id cannot contain {SCID} on update.")
    unsigned = {
        "versionId": f"{version_number}-{_entry_hash({'versionTime': version_time, 'state': state_obj, 'parameters': params_obj})}",
        "versionTime": version_time,
        "state": state_obj,
        "parameters": params_obj,
    }
    proof = make_proof(
        unsigned,
        keypair.secret_key,
        verification_method=verification_method,
        proof_created=version_time,
    )
    verified = verify_payload(unsigned, proof, keypair.public_key)
    if not verified:
        raise HTTPException(status_code=500, detail="Generated proof failed immediate verification.")
    return CreateResponse(
        versionId=unsigned["versionId"],
        versionTime=version_time,
        state=state_obj,
        parameters=params_obj,
        proof=proof,
    )


def _keypair_for_put(previous: CreateResponse) -> KeyPair:
    prev_vm = previous.proof.get("verificationMethod")
    if not isinstance(prev_vm, str) or not prev_vm:
        raise HTTPException(status_code=500, detail="Stored proof.verificationMethod is missing; provide options.")
    mb = _public_key_multibase_from_did_key_verification_method(prev_vm)
    return _keypair_from_key_store(mb)


def _verification_method_for_scid_put(previous: CreateResponse) -> str:
    prev_vm = previous.proof.get("verificationMethod")
    if isinstance(prev_vm, str) and prev_vm:
        return prev_vm
    raise HTTPException(
        status_code=500,
        detail="Stored SCID record has no proof.verificationMethod; provide options to re-sign.",
    )


def _next_version_number(previous: CreateResponse) -> int:
    raw = previous.versionId
    if "-" not in raw:
        raise HTTPException(status_code=500, detail=f"Stored versionId has invalid format: {raw!r}")
    prefix, _ = raw.split("-", 1)
    try:
        current = int(prefix)
    except ValueError as e:
        raise HTTPException(status_code=500, detail=f"Stored versionId has non-numeric prefix: {raw!r}") from e
    return current + 1


class AliasRequestOptions(BaseModel):
    """Signing options for SCID create/update. Key material is always resolved from `POST /keys` resources."""

    model_config = ConfigDict(
        extra="allow",
        json_schema_extra={
            "example": {
                "apiKey": "replace-with-secret-string",
            }
        },
    )

    apiKey: str | None = Field(
        default=None,
        min_length=1,
        description="Secret string used to authorize protected `PUT /dids/{scid}` and `DELETE /dids/{scid}` operations.",
    )


class CreateRequest(BaseModel):
    """Body for `POST /dids` and `PUT /dids/{scid}` (create or update a signed SCID entry)."""

    model_config = ConfigDict(
        json_schema_extra={
            "title": "Alias create / update",
            "example": {
                "state": {
                    "@context": ["https://www.w3.org/ns/did/v1.1"],
                    "id": "did:pqvh:{SCID}",
                },
                "parameters": {
                    "preRotationKeys": [_KEY_CREATE_EXAMPLE_PRE_ROTATION_KEY_HASH],
                    "witness": {"threshold": 0, "witnesses": []},
                    "watchers": [],
                },
                "options": {
                    "apiKey": "replace-with-secret-string",
                },
            },
        }
    )

    state: AliasDidState = Field(
        default_factory=lambda: AliasDidState.model_validate(MINIMAL_DID_DOCUMENT),
        description="DID document (`state` in the signed entry). Default mirrors a minimal DID 1.1 document.",
    )
    parameters: WebVHParameters = Field(
        default_factory=lambda: WebVHParameters(),
        description="WebVH-like parameters merged into the signed entry.",
    )
    options: AliasRequestOptions | None = Field(
        default=None,
        description=(
            "For `PUT /dids/{scid}`, `apiKey` is required. "
            "For `POST /dids`, omit or leave empty to let the server generate a URL-safe `apiKey`. "
            "Only `apiKey` is accepted. "
            "On create, signing key is selected by sequential lookup of `parameters.preRotationKeys`; "
            "if that list is empty, the server generates an ML-DSA key (stored like `POST /keys`)."
        ),
    )


class CreateResponse(BaseModel):
    versionId: str
    versionTime: str
    state: dict[str, Any]
    parameters: dict[str, Any]
    proof: dict[str, Any]


class DidBootstrapInfo(BaseModel):
    """Returned on `POST /dids` when the server generated an API key and/or signing key (prototype custody)."""

    apiKey: str | None = Field(
        default=None,
        description="Generated `options.apiKey` when the request omitted one (store for PUT/DELETE).",
    )
    publicKeyMultibase: str | None = Field(
        default=None,
        description="When the server created a signing key, its `publicKeyMultibase` (`GET /keys/{...}`).",
    )
    secretKeyMultibase: str | None = Field(
        default=None,
        description="When the server created a signing key, multibase-encoded secret (handle like `POST /keys`).",
    )
    preRotationKey: str | None = Field(
        default=None,
        description="When the server created a signing key, the hash added to `parameters.preRotationKeys`.",
    )


class CreateDidResponse(BaseModel):
    logEntry: CreateResponse
    bootstrap: DidBootstrapInfo | None = Field(
        default=None,
        description="Present when the server generated an API key and/or ML-DSA signing key for this create.",
    )


class CredentialIssueRequest(BaseModel):
    issuer: str = Field(..., description="Credential issuer IRI (e.g. DID of the issuer).")
    credential_subject: dict[str, Any] = Field(
        ...,
        description="`credentialSubject` map (must include an `id` for most use cases).",
    )
    verification_method: str = Field(..., description="Verification method used for the data integrity proof.")
    credential_types: list[str] = Field(
        default_factory=lambda: ["VerifiableCredential"],
        description="`type` array; `VerifiableCredential` is always included if missing.",
    )
    contexts: list[Any] = Field(
        default_factory=lambda: list(DEFAULT_VC_CONTEXT),
        description="JSON-LD `@context` values (defaults to W3C VC v1).",
    )
    credential_id: str | None = Field(default=None, description="Optional credential `id` IRI.")
    secret_key_b64u: str | None = Field(
        default=None,
        description="Optional ML-DSA secret key (base64url). If omitted, a new keypair is generated.",
    )
    public_key_b64u: str | None = Field(
        default=None,
        description="Optional ML-DSA public key (base64url). Required when `secret_key_b64u` is set.",
    )


class CredentialIssueResponse(BaseModel):
    created: str
    credential: dict[str, Any]
    public_key_b64u: str
    secret_key_b64u: str
    verified: bool


class _ExactlyOnePublicKey(BaseModel):
    public_key_b64u: str | None = Field(default=None, description="ML-DSA public key (base64url).")
    public_key_multibase: str | None = Field(
        default=None,
        description="ML-DSA public key (multibase `z` or `u`, raw key bytes).",
    )

    @model_validator(mode="after")
    def _exactly_one_public_key(self) -> Self:
        has_b64 = self.public_key_b64u is not None and self.public_key_b64u != ""
        has_mb = self.public_key_multibase is not None and self.public_key_multibase != ""
        if has_b64 == has_mb:
            raise ValueError("Provide exactly one of public_key_b64u or public_key_multibase")
        return self


class CredentialVerifyRequest(_ExactlyOnePublicKey):
    credential: dict[str, Any] = Field(
        ...,
        description="Secured Verifiable Credential (includes top-level `proof`).",
    )


class CredentialVerifyResponse(BaseModel):
    verified: bool
    credential: dict[str, Any] | None = Field(
        default=None,
        description="Unsecured credential (no `proof`) when verified.",
    )


def _public_key_bytes_from_model(m: _ExactlyOnePublicKey) -> bytes:
    if m.public_key_b64u:
        try:
            return _b64u_decode(m.public_key_b64u)
        except (ValueError, binascii.Error) as e:
            raise HTTPException(status_code=400, detail=f"Invalid public_key_b64u: {e}") from e
    assert m.public_key_multibase is not None
    return _multibase_decode(m.public_key_multibase)


@app.get("/health", tags=["server"])
def health() -> dict[str, str]:
    return {"status": "ok"}


class KeyCreateResponse(BaseModel):
    created: str
    publicKeyMultibase: str
    secretKeyMultibase: str
    preRotationKey: str


class KeyCreateRequest(BaseModel):
    """Deterministic ML-DSA key derivation from a UTF-8 seed."""

    model_config = ConfigDict(
        json_schema_extra={
            "title": "Key create (seed)",
            "description": (
                "`seed` is UTF-8 seed material. "
                "Server applies SHA-256 then ML-DSA keygen."
            ),
            "example": {
                "seed": "00000000000000000000000000000000",
            },
        }
    )

    seed: str = Field(
        ...,
        min_length=1,
        description="UTF-8 seed; SHA-256 → ζ.",
    )


def _create_key_record(req: KeyCreateRequest) -> KeyCreateResponse:
    material = req.seed.encode("utf-8")
    keypair = generate_keypair_from_seed(material)
    public_key_multibase = _multibase_encode(keypair.public_key)
    return KeyCreateResponse(
        created=_utc_created(),
        publicKeyMultibase=public_key_multibase,
        secretKeyMultibase=_multibase_encode(keypair.secret_key),
        preRotationKey=_multihash_sha256_base58(public_key_multibase.encode("utf-8")),
    )


@app.post(
    "/keys",
    response_model=KeyCreateResponse,
    status_code=201,
    summary="Create key",
    response_description="New ML-DSA keypair and `created` timestamp; resource URL is `/keys/{publicKeyMultibase}`.",
    tags=["keys"],
)
def keys_post(
    req: Annotated[
        KeyCreateRequest,
        Body(
            openapi_examples={
                "seed_only": {
                    "summary": "UTF-8 seed",
                    "description": "Seed material as UTF-8 string.",
                    "value": {
                        "seed": "00000000000000000000000000000000",
                    },
                },
            },
        ),
    ],
) -> KeyCreateResponse:
    """Create a key resource keyed by ``publicKeyMultibase`` (prototype in-memory registry)."""
    record = _create_key_record(req)
    pk = record.publicKeyMultibase
    with _key_store_lock:
        if pk in _key_store:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"A key is already stored for publicKeyMultibase={pk!r}. "
                    "Use PUT to replace or DELETE first."
                ),
            )
        _key_store[pk] = record.model_dump()
        _pre_rotation_key_index[record.preRotationKey] = pk
    return record


@app.get("/keys/{publicKeyMultibase:path}", response_model=KeyCreateResponse, tags=["keys"])
def keys_get(publicKeyMultibase: str) -> KeyCreateResponse:
    """Read stored keypair for this ``publicKeyMultibase`` (use raw multibase string in path; encode for HTTP if needed)."""
    with _key_store_lock:
        raw = _key_store.get(publicKeyMultibase)
    if raw is None:
        raise HTTPException(status_code=404, detail=f"Key not found for publicKeyMultibase={publicKeyMultibase!r}")
    return KeyCreateResponse.model_validate(raw)


@app.put("/keys/{publicKeyMultibase:path}", response_model=KeyCreateResponse, tags=["keys"])
def keys_put(publicKeyMultibase: str, req: KeyCreateRequest) -> KeyCreateResponse:
    """Replace key material from new seed input. If the derived public key changes, the store moves the entry to the new multibase key."""
    record = _create_key_record(req)
    new_pk = record.publicKeyMultibase
    with _key_store_lock:
        if publicKeyMultibase not in _key_store:
            raise HTTPException(
                status_code=404,
                detail=f"Key not found for publicKeyMultibase={publicKeyMultibase!r}",
            )
        if new_pk != publicKeyMultibase and new_pk in _key_store:
            raise HTTPException(
                status_code=409,
                detail=f"Derived publicKeyMultibase={new_pk!r} already exists; choose a different seed or delete the other key first.",
            )
        old_record = KeyCreateResponse.model_validate(_key_store[publicKeyMultibase])
        del _key_store[publicKeyMultibase]
        _pre_rotation_key_index.pop(old_record.preRotationKey, None)
        _key_store[new_pk] = record.model_dump()
        _pre_rotation_key_index[record.preRotationKey] = new_pk
    return record


@app.delete("/keys/{publicKeyMultibase:path}", status_code=204, tags=["keys"])
def keys_delete(publicKeyMultibase: str) -> None:
    """Remove key from the prototype registry."""
    with _key_store_lock:
        if publicKeyMultibase not in _key_store:
            raise HTTPException(
                status_code=404,
                detail=f"Key not found for publicKeyMultibase={publicKeyMultibase!r}",
            )
        record = KeyCreateResponse.model_validate(_key_store[publicKeyMultibase])
        del _key_store[publicKeyMultibase]
        _pre_rotation_key_index.pop(record.preRotationKey, None)


def _register_random_ml_dsa_key() -> KeyCreateResponse:
    """Generate ML-DSA keypair and store it like ``POST /keys`` (with rare collision retry)."""
    for _ in range(8):
        keypair = generate_ml_dsa_keypair()
        public_key_multibase = _multibase_encode(keypair.public_key)
        record = KeyCreateResponse(
            created=_utc_created(),
            publicKeyMultibase=public_key_multibase,
            secretKeyMultibase=_multibase_encode(keypair.secret_key),
            preRotationKey=_multihash_sha256_base58(public_key_multibase.encode("utf-8")),
        )
        with _key_store_lock:
            if public_key_multibase in _key_store:
                continue
            _key_store[public_key_multibase] = record.model_dump()
            _pre_rotation_key_index[record.preRotationKey] = public_key_multibase
        return record
    raise HTTPException(
        status_code=500,
        detail="Failed to allocate a unique signing key after several attempts; retry.",
    )


@app.post(
    "/dids",
    response_model=CreateDidResponse,
    response_model_exclude_none=True,
    status_code=201,
    tags=["dids"],
    summary="Create DID",
)
def scids_post(
    req: Annotated[
        CreateRequest,
        Body(
            openapi_examples={
                "minimal_bootstrap": {
                    "summary": "Empty objects (server key + API key)",
                    "description": (
                        "Omit signing key material: server registers a new ML-DSA key, "
                        "fills `parameters.preRotationKeys`, and generates `options.apiKey`. "
                        "See `bootstrap` in the response."
                    ),
                    "value": {"options": {}, "parameters": {}, "state": {}},
                },
            },
        ),
    ],
) -> CreateDidResponse:
    """Create a SCID resource: sign DID entry, store under ``state.id`` (prototype in-memory registry).

    If ``parameters.preRotationKeys`` is empty, the server generates an ML-DSA key, stores it like
    ``POST /keys``, and uses its ``preRotationKey`` for signing. If ``options.apiKey`` is missing
    or empty, the server generates a URL-safe secret for ``PUT``/``DELETE``. Generated values are
    echoed under ``bootstrap`` when applicable.
    """
    api_key_supplied = bool(req.options and req.options.apiKey)
    final_api_key = req.options.apiKey if api_key_supplied else secrets.token_urlsafe(32)

    key_record: KeyCreateResponse | None = None
    if not req.parameters.preRotationKeys:
        key_record = _register_random_ml_dsa_key()
        eff_params = req.parameters.model_copy(update={"preRotationKeys": [key_record.preRotationKey]})
    else:
        eff_params = req.parameters

    effective_req = req.model_copy(
        update={
            "parameters": eff_params,
            "options": AliasRequestOptions(apiKey=final_api_key),
        }
    )

    keypair, public_key_multibase = _keypair_from_pre_rotation_keys(
        effective_req.parameters.preRotationKeys
    )
    vm = f"did:key:{public_key_multibase}#{public_key_multibase}"
    record = _create_did_record(
        effective_req,
        keypair=keypair,
        verification_method=vm,
        version_number=1,
        allow_scid_placeholder=True,
    )
    did = record.state.get("id")
    if not isinstance(did, str) or not did:
        raise HTTPException(status_code=500, detail="Resolved state.id is missing after create.")
    with _scid_store_lock:
        if did in _scid_store:
            raise HTTPException(
                status_code=409,
                detail=f"SCID entry already exists for {did!r}. Use PUT to update or DELETE first.",
            )
        _scid_store[did] = record.model_dump()
        _scid_api_key_store[did] = final_api_key

    bootstrap: DidBootstrapInfo | None = None
    if (not api_key_supplied) or (key_record is not None):
        b_kw: dict[str, str] = {}
        if not api_key_supplied:
            b_kw["apiKey"] = final_api_key
        if key_record is not None:
            b_kw["publicKeyMultibase"] = key_record.publicKeyMultibase
            b_kw["secretKeyMultibase"] = key_record.secretKeyMultibase
            b_kw["preRotationKey"] = key_record.preRotationKey
        bootstrap = DidBootstrapInfo(**b_kw)

    return CreateDidResponse(logEntry=record, bootstrap=bootstrap)


def _get_scid_entry_or_404(scid: str) -> CreateResponse:
    """Load stored signed entry for ``scid`` (full DID string used as map key)."""
    with _scid_store_lock:
        raw = _scid_store.get(scid)
    if raw is None:
        raise HTTPException(status_code=404, detail=f"SCID entry not found: {scid!r}")
    return CreateResponse.model_validate(raw)


@app.get("/dids/{scid:path}", response_model=CreateResponse, tags=["dids"], summary="Read DID")
def scids_get(scid: str) -> CreateResponse:
    """Read the stored signed entry for path ``scid`` (the DID string; URL-encode, e.g. ``did%3Apqvh%3A…``)."""
    return _get_scid_entry_or_404(scid)


@app.put("/dids/{scid:path}", response_model=CreateResponse, tags=["dids"], summary="Update DID")
def scids_put(
    scid: str,
    req: Annotated[
        CreateRequest,
        Body(
            openapi_examples={
                "minimal_update": {
                    "summary": "Minimal update body",
                    "description": "Use empty `state` and `parameters` objects with required `options.apiKey`.",
                    "value": {
                        "state": {},
                        "parameters": {},
                        "options": {
                            "apiKey": "replace-with-secret-string",
                        },
                    },
                },
            },
        ),
    ],
) -> CreateResponse:
    """Update DID document/parameters: re-signs entry.

    Requires ``options.apiKey``.
    """
    body_id = _did_id_from_state(req.state)
    if body_id != scid:
        raise HTTPException(
            status_code=400,
            detail=f"Path scid {scid!r} must match body state.id {body_id!r}",
        )
    if req.options is None or not req.options.apiKey:
        raise HTTPException(status_code=401, detail="`options.apiKey` is required for update.")
    with _scid_store_lock:
        stored_api_key = _scid_api_key_store.get(scid)
        if stored_api_key is None:
            raise HTTPException(status_code=404, detail=f"SCID entry not found: {scid!r}")
        if req.options.apiKey != stored_api_key:
            raise HTTPException(status_code=403, detail="Invalid apiKey for this DID.")
        prev_raw = _scid_store.get(scid)
    if prev_raw is None:
        raise HTTPException(status_code=404, detail=f"SCID entry not found: {scid!r}")
    previous = CreateResponse.model_validate(prev_raw)
    keypair = _keypair_for_put(previous)
    vm = _verification_method_for_scid_put(previous)
    record = _create_did_record(
        req,
        keypair=keypair,
        verification_method=vm,
        version_number=_next_version_number(previous),
    )
    with _scid_store_lock:
        if scid not in _scid_store:
            raise HTTPException(status_code=404, detail=f"SCID entry not found: {scid!r}")
        _scid_store[scid] = record.model_dump()
    return record


@app.delete("/dids/{scid:path}", status_code=204, tags=["dids"], summary="Delete DID")
def scids_delete(
    scid: str,
    apiKey: str = Query(..., min_length=1, description="Secret API key created at `POST /dids` (`options.apiKey`)."),
) -> None:
    """Remove SCID entry from the prototype registry."""
    with _scid_store_lock:
        if scid not in _scid_store:
            raise HTTPException(status_code=404, detail=f"SCID entry not found: {scid!r}")
        stored_api_key = _scid_api_key_store.get(scid)
        if stored_api_key is None:
            raise HTTPException(status_code=404, detail=f"SCID entry not found: {scid!r}")
        if apiKey != stored_api_key:
            raise HTTPException(status_code=403, detail="Invalid apiKey for this DID.")
        del _scid_store[scid]
        del _scid_api_key_store[scid]


@app.get("/resolve", response_model=CreateResponse, tags=["dids"])
def dids_resolve(
    did: str = Query(..., description="Resolve by full DID (public-style query)."),
) -> CreateResponse:
    """Resolve DID record by `did`."""
    with _scid_store_lock:
        raw = _scid_store.get(did)
    if raw is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"DID not found in local store: {did!r}. "
                "Public network resolution is not implemented in this prototype."
            ),
        )
    return CreateResponse.model_validate(raw)


@app.post("/credentials/issue", response_model=CredentialIssueResponse, tags=["credentials"])
def credentials_issue(req: CredentialIssueRequest) -> CredentialIssueResponse:
    """Issue a minimal W3C Verifiable Credential with an `mldsa44-jcs-2024` data integrity proof."""
    keypair: KeyPair
    if req.secret_key_b64u:
        secret_key = _b64u_decode(req.secret_key_b64u)
        if not req.public_key_b64u:
            raise HTTPException(status_code=400, detail="public_key_b64u is required with secret_key_b64u")
        public_key = _b64u_decode(req.public_key_b64u)
        keypair = KeyPair(public_key=public_key, secret_key=secret_key)
    else:
        keypair = generate_ml_dsa_keypair()

    created = _utc_created()
    types = list(req.credential_types)
    if "VerifiableCredential" not in types:
        types = ["VerifiableCredential", *types]

    vc: dict[str, Any] = {
        "@context": list(req.contexts),
        "type": types,
        "issuer": req.issuer,
        "issuanceDate": created,
        "credentialSubject": dict(req.credential_subject),
    }
    if req.credential_id:
        vc["id"] = req.credential_id

    proof = make_proof(
        vc,
        keypair.secret_key,
        verification_method=req.verification_method,
        proof_created=created,
    )
    secured = {**vc, "proof": proof}
    vresult = verify_proof_mldsa44_jcs(secured, keypair.public_key)

    return CredentialIssueResponse(
        created=created,
        credential=secured,
        public_key_b64u=_b64u_encode(keypair.public_key),
        secret_key_b64u=_b64u_encode(keypair.secret_key),
        verified=vresult.verified,
    )


@app.post("/credentials/verify", response_model=CredentialVerifyResponse, tags=["credentials"])
def credentials_verify(req: CredentialVerifyRequest) -> CredentialVerifyResponse:
    """Verify an `mldsa44-jcs-2024` data integrity proof on a secured Verifiable Credential."""
    if "proof" not in req.credential:
        raise HTTPException(status_code=400, detail="`credential` must include a top-level `proof`")

    pk = _public_key_bytes_from_model(req)
    result = verify_proof_mldsa44_jcs(req.credential, pk)

    return CredentialVerifyResponse(
        verified=result.verified,
        credential=result.verified_document if result.verified else None,
    )


@app.get(
    "/{scid}",
    response_model=CreateResponse,
    tags=["dids"],
    summary="Read DID (root path)",
    description=(
        "Same as `GET /dids/{scid}`: returns the stored signed entry when `scid` is the full DID. "
        "The path must match `did:pqvh:` plus a base58btc method-specific id (see OpenAPI `pattern`); "
        "otherwise the request fails validation (422). "
        "Registered after all other routes so paths like `/health`, `/keys`, `/dids`, `/resolve`, "
        "and `/credentials` are not captured."
    ),
)
def scid_root_get(
    scid: Annotated[
        str,
        Path(
            pattern=SCID_ROOT_DID_PATH_PATTERN,
            description=(
                "Full DID string, single path segment. Must be `did:pqvh:` followed by a base58btc "
                "method-specific id (43–48 characters)."
            ),
        ),
    ],
) -> CreateResponse:
    """Root-path alias for reading a SCID entry (must be registered last)."""
    return _get_scid_entry_or_404(scid)
