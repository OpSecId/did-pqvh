"""HTTP API for did-pqvh."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import threading
from datetime import datetime, timezone
from typing import Annotated, Any, Self

import base58
from fastapi import Body, FastAPI, Header, HTTPException, Path, Query, Response
from starlette.responses import StreamingResponse
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
            "name": "scids",
            "description": (
                "SCID log resources at the API root: `POST /` appends the first signed entry and returns "
                "`X-Scid-Auth-Secret` (store it for writes); "
                "`GET /{scid}` streams **NDJSON** (one JSON log entry per line, oldest first); "
                "`PUT /{scid}` / `DELETE /{scid}` require that header. "
                "Paths accept bare multihash SCID or full `did:pqvh:…`. Create selects signing keys by sequential "
                "lookup of `parameters.preRotationKeys` (empty list triggers a server-generated key, same as `POST /keys`)."
            ),
        },
        {
            "name": "dids",
            "description": "DID resolution (`GET /resolve?did=` returns JSON with top-level `didDocument` from the local store).",
        },
        {"name": "credentials", "description": "Verifiable Credentials (issue and verify)."},
    ],
)

# Prototype in-memory registry: ``state.id`` -> ordered list of signed log entries (not persistent; not for production).
_scid_log_lock = threading.Lock()
_scid_log: dict[str, list[dict[str, Any]]] = {}
# Per-DID shared secret (returned on ``POST /`` in ``X-Scid-Auth-Secret``); required on ``PUT`` / ``DELETE``.
_scid_secret: dict[str, str] = {}
_pre_rotation_key_index: dict[str, str] = {}

_key_store_lock = threading.Lock()
_key_store: dict[str, dict[str, Any]] = {}

# Response / request header for SCID write authentication (caller must persist after create).
SCID_AUTH_SECRET_HEADER = "X-Scid-Auth-Secret"

# Minimal DID document (https://www.w3.org/TR/did-1.1/) for default `state`.
MINIMAL_DID_DOCUMENT: dict[str, Any] = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:pqvh:{SCID}",
}

# SCID log entry proofs: ``_did_key_verification_method`` → ``did:key:{publicKeyMultibase}#vm`` (fixed fragment).
SCID_DID_KEY_VM_FRAGMENT = "vm"

# ``GET /{scid}`` only: bare base58 **SCID** (multihash string, e.g. ``QmWty8to1v573wR3ZS…``) **or**
# full ``did:pqvh:<SCID>``. Lower bound avoids short paths like ``/health`` matching this route.
SCID_ROOT_PATH_PATTERN = r"^(?:did:pqvh:)?[1-9A-HJ-NP-Za-km-z]{32,80}$"


def _normalize_root_scid_lookup_key(path_segment: str) -> str:
    """Map root path segment to in-memory store key (full ``did:pqvh:…`` DID string)."""
    if path_segment.startswith("did:pqvh:"):
        return path_segment
    return f"did:pqvh:{path_segment}"


ScidPathSegment = Annotated[
    str,
    Path(
        pattern=SCID_ROOT_PATH_PATTERN,
        description=(
            "Bare base58 SCID (32–80 chars) or full `did:pqvh:` + same, one URL path segment "
            "(encode `:` for HTTP if needed)."
        ),
    ),
]

ScidAuthSecretHeader = Annotated[
    str | None,
    Header(
        alias=SCID_AUTH_SECRET_HEADER,
        description=(
            f"Per-DID secret from the `POST /` response header `{SCID_AUTH_SECRET_HEADER}`; "
            "required for PUT and DELETE (missing or wrong value yields 403)."
        ),
    ),
]


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
        default_factory=lambda: ["https://www.w3.org/ns/did/v1"],
        alias="@context",
        description="JSON-LD `@context` (string or array of strings).",
    )
    id: str = Field(
        default="did:pqvh:{SCID}",
        min_length=1,
        description=(
            "DID string; storage key for `GET /{scid}` (URL-encode the path segment). "
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


def _did_key_verification_method(public_key_multibase: str) -> str:
    """Build ``did:key`` proof ``verificationMethod``: ``did:key:{multibase}#vm``."""
    return f"did:key:{public_key_multibase}#{SCID_DID_KEY_VM_FRAGMENT}"


def _public_key_multibase_from_did_key_verification_method(verification_method: str) -> str:
    """Parse ``did:key:{publicKeyMultibase}#vm``; return ``publicKeyMultibase`` for ``/keys`` lookup."""
    prefix = "did:key:"
    if not verification_method.startswith(prefix):
        raise HTTPException(
            status_code=400,
            detail=(
                "verificationMethod must be did:key:{publicKeyMultibase}#vm "
                "(multibase from POST /keys as the did:key method-specific id)."
            ),
        )
    rest = verification_method[len(prefix) :]
    if "#" not in rest:
        raise HTTPException(
            status_code=400,
            detail="verificationMethod must include a # fragment (expected `#vm`).",
        )
    method_id, fragment = rest.split("#", 1)
    if not method_id or fragment != SCID_DID_KEY_VM_FRAGMENT:
        raise HTTPException(
            status_code=400,
            detail=(
                "verificationMethod must be did:key:{publicKeyMultibase}#vm "
                f"with fragment {SCID_DID_KEY_VM_FRAGMENT!r}, not {fragment!r}."
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
    """Optional request bag for SCID create/update (reserved for future options)."""

    model_config = ConfigDict(
        extra="allow",
        json_schema_extra={"example": {}},
    )


class CreateRequest(BaseModel):
    """Body for `POST /` (create) and `PUT /{scid}` (update a signed SCID entry)."""

    model_config = ConfigDict(
        json_schema_extra={
            "title": "Alias create / update",
            "example": {
                "state": {
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "did:pqvh:{SCID}",
                },
                "parameters": {
                    "preRotationKeys": [_KEY_CREATE_EXAMPLE_PRE_ROTATION_KEY_HASH],
                    "witness": {"threshold": 0, "witnesses": []},
                    "watchers": [],
                },
                "options": {},
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
            "Optional; reserved for future use. "
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


class CreateDidResponse(BaseModel):
    """Wrapped create response (signed log entry only)."""

    logEntry: CreateResponse


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


def _scid_log_snapshot(key: str) -> list[dict[str, Any]] | None:
    """Copy current log lines for ``key`` (full ``did:pqvh:…``), or ``None`` if unknown."""
    with _scid_log_lock:
        rows = _scid_log.get(key)
        if not rows:
            return None
        return [dict(r) for r in rows]


def _ndjson_bytes_iter(snapshot: list[dict[str, Any]]):
    for row in snapshot:
        yield (json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _scid_log_streaming_response(key: str, *, not_found_detail: str | None = None) -> StreamingResponse:
    snapshot = _scid_log_snapshot(key)
    if snapshot is None:
        raise HTTPException(
            status_code=404,
            detail=not_found_detail or f"SCID entry not found: {key!r}",
        )
    return StreamingResponse(
        _ndjson_bytes_iter(snapshot),
        media_type="application/x-ndjson; charset=utf-8",
    )


def _require_scid_auth_secret(normalized: str, secret: str | None) -> None:
    """Raise 403 if the per-DID secret is missing or wrong (call under ``_scid_log_lock``)."""
    if not secret:
        raise HTTPException(
            status_code=403,
            detail="Missing SCID write secret; send the `X-Scid-Auth-Secret` header from the `POST /` response.",
        )
    expected = _scid_secret.get(normalized)
    if expected is None or not secrets.compare_digest(secret, expected):
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing SCID write secret; send the value from the `POST /` response header.",
        )


@app.get("/resolve", tags=["dids"])
def dids_resolve(
    did: str = Query(
        ...,
        description="Full `did:pqvh:…` or bare base58 SCID (same normalization as `GET /{scid}`).",
    ),
) -> dict[str, Any]:
    """Resolve DID document from the latest SCID log entry (local store only in this prototype)."""
    key = _normalize_root_scid_lookup_key(did)
    snapshot = _scid_log_snapshot(key)
    if snapshot is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"DID not found in local store: {key!r}. "
                "Public network resolution is not implemented in this prototype."
            ),
        )
    last = snapshot[-1]
    state = last.get("state")
    if not isinstance(state, dict):
        raise HTTPException(
            status_code=500,
            detail="Latest log entry has no usable `state` map for didDocument.",
        )
    return {"didDocument": dict(state)}


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


@app.post(
    "/",
    response_model=CreateDidResponse,
    status_code=201,
    tags=["scids"],
    summary="Create DID",
    responses={
        201: {
            "description": (
                "Created; persist the `X-Scid-Auth-Secret` response header value for `PUT /{scid}` and `DELETE /{scid}`."
            ),
            "headers": {
                "X-Scid-Auth-Secret": {
                    "description": (
                        "Per-DID shared secret; send the same header name and value on write operations for this DID."
                    ),
                    "schema": {"type": "string"},
                },
            },
        },
    },
)
def root_post_did(
    response: Response,
    req: Annotated[
        CreateRequest,
        Body(
            openapi_examples={
                "minimal_create": {
                    "summary": "Empty objects (server-generated signing key)",
                    "description": (
                        "Omit signing key material: server registers a new ML-DSA key and "
                        "fills `parameters.preRotationKeys` (stored like `POST /keys`)."
                    ),
                    "value": {"options": {}, "parameters": {}, "state": {}},
                },
            },
        ),
    ],
) -> CreateDidResponse:
    """Create a SCID resource: sign DID entry, store under ``state.id`` (prototype in-memory registry).

    If ``parameters.preRotationKeys`` is empty, the server generates an ML-DSA key, stores it like
    ``POST /keys``, and uses its ``preRotationKey`` for signing.
    """
    key_record: KeyCreateResponse | None = None
    if not req.parameters.preRotationKeys:
        key_record = _register_random_ml_dsa_key()
        eff_params = req.parameters.model_copy(update={"preRotationKeys": [key_record.preRotationKey]})
    else:
        eff_params = req.parameters

    effective_req = req.model_copy(update={"parameters": eff_params})

    keypair, public_key_multibase = _keypair_from_pre_rotation_keys(
        effective_req.parameters.preRotationKeys
    )
    vm = _did_key_verification_method(public_key_multibase)
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
    auth_secret = secrets.token_urlsafe(32)
    with _scid_log_lock:
        if did in _scid_log:
            raise HTTPException(
                status_code=409,
                detail=f"SCID entry already exists for {did!r}. Use PUT to update or DELETE first.",
            )
        _scid_log[did] = [record.model_dump()]
        _scid_secret[did] = auth_secret

    response.headers[SCID_AUTH_SECRET_HEADER] = auth_secret
    return CreateDidResponse(logEntry=record)


@app.get(
    "/{scid}",
    tags=["scids"],
    summary="Read DID log",
    description=(
        "NDJSON stream (``Content-Type: application/x-ndjson``): one compact JSON object per line, "
        "signed log entries **oldest first** (initial create, then each ``PUT``). "
        "Path accepts a bare base58 **SCID** (e.g. ``QmWty8to1v573wR3ZSj88FScJFY6JaVijGuJAA8UugrhoX``) or a full "
        "``did:pqvh:<SCID>`` single segment (see OpenAPI `pattern`). "
        "Registered after all other routes so paths like `/health`, `/keys`, `/resolve`, "
        "and `/credentials` are not captured."
    ),
    responses={
        200: {
            "description": "NDJSON stream of signed log entries (one JSON object per line).",
            "content": {
                "application/x-ndjson": {
                    "schema": {"type": "string", "format": "binary"},
                },
            },
        }
    },
)
def root_get_did(scid: ScidPathSegment) -> StreamingResponse:
    """Stream the SCID log (registered after static paths)."""
    return _scid_log_streaming_response(_normalize_root_scid_lookup_key(scid))


@app.put(
    "/{scid}",
    response_model=CreateResponse,
    tags=["scids"],
    summary="Update DID",
)
def root_put_did(
    scid: ScidPathSegment,
    req: Annotated[
        CreateRequest,
        Body(
            openapi_examples={
                "minimal_update": {
                    "summary": "Minimal update body",
                    "description": (
                        "Path accepts bare SCID or full `did:pqvh:…`; `state.id` must match the resolved DID."
                    ),
                    "value": {
                        "state": {},
                        "parameters": {},
                    },
                },
            },
        ),
    ],
    scid_auth_secret: ScidAuthSecretHeader = None,
) -> CreateResponse:
    """Update DID document/parameters: re-signs entry; requires ``X-Scid-Auth-Secret`` from create."""
    normalized = _normalize_root_scid_lookup_key(scid)
    body_id = _did_id_from_state(req.state)
    if body_id != normalized:
        raise HTTPException(
            status_code=400,
            detail=f"Path scid resolved to {normalized!r}; must match body state.id {body_id!r}",
        )
    with _scid_log_lock:
        rows = _scid_log.get(normalized)
        if not rows:
            raise HTTPException(status_code=404, detail=f"SCID entry not found: {normalized!r}")
        _require_scid_auth_secret(normalized, scid_auth_secret)
    previous = CreateResponse.model_validate(rows[-1])
    keypair = _keypair_for_put(previous)
    vm = _verification_method_for_scid_put(previous)
    record = _create_did_record(
        req,
        keypair=keypair,
        verification_method=vm,
        version_number=_next_version_number(previous),
    )
    with _scid_log_lock:
        if normalized not in _scid_log:
            raise HTTPException(status_code=404, detail=f"SCID entry not found: {normalized!r}")
        _scid_log[normalized].append(record.model_dump())
    return record


@app.delete("/{scid}", status_code=204, tags=["scids"], summary="Delete DID")
def root_delete_did(
    scid: ScidPathSegment,
    scid_auth_secret: ScidAuthSecretHeader = None,
) -> None:
    """Remove SCID entry from the prototype registry; requires ``X-Scid-Auth-Secret`` from create."""
    normalized = _normalize_root_scid_lookup_key(scid)
    with _scid_log_lock:
        if normalized not in _scid_log:
            raise HTTPException(status_code=404, detail=f"SCID entry not found: {normalized!r}")
        _require_scid_auth_secret(normalized, scid_auth_secret)
        del _scid_log[normalized]
        _scid_secret.pop(normalized, None)
