"""ML-DSA + JCS signing primitives for DID history entries (Data Integrity quantum-safe profile)."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
from dataclasses import dataclass
from typing import Any

from dilithium_py.ml_dsa import ML_DSA_44

# ML-DSA parameter set: 44 (NIST “ML-DSA-44”) vs 65 / 87 for higher strength.
ML_DSA = ML_DSA_44

from .canonical import canonicalize_json

# W3C CCG Data Integrity quantum-safe cryptosuite identifier (Table / MLSuitesTable).
CRYPTOSUITE = "mldsa44-jcs-2024"
# Backward-compatible export name (same string as cryptosuite).
SUITE_NAME = CRYPTOSUITE

PROOF_TYPE = "DataIntegrityProof"


@dataclass(frozen=True)
class VerificationResult:
    """Result of [[di-quantum-safe]] §3.3.2 *Verify Proof (ML-DSA)*."""

    verified: bool
    verified_document: dict[str, Any] | None


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))


def _proof_value_encode(proof_bytes: bytes) -> str:
    """Multibase base64url-no-pad per [[CID]] / di-quantum-safe proofValue rules (`u` header)."""
    return "u" + _b64u_encode(proof_bytes)


def _proof_value_decode(s: str) -> bytes:
    if s.startswith("u"):
        return _b64u_decode(s[1:])
    return _b64u_decode(s)


def _jcs_canonical_bytes(document: Any) -> bytes:
    """JCS-style canonical UTF-8 bytes (RFC 8785–oriented; deterministic JSON)."""
    return canonicalize_json(document)


def _proof_configuration_map(unsecured_document: dict[str, Any], proof_options: dict[str, Any]) -> dict[str, Any]:
    """Section 3.1.2 Proof Configuration (``jcs`` branch): clone options, validate, set ``@context``."""
    proof_config = copy.deepcopy(proof_options)
    if proof_config.get("type") != PROOF_TYPE:
        raise ValueError("INVALID_PROOF_CONFIGURATION: proof options type must be DataIntegrityProof")
    if proof_config.get("cryptosuite") != CRYPTOSUITE:
        raise ValueError(f"INVALID_PROOF_CONFIGURATION: cryptosuite must be {CRYPTOSUITE!r}")
    created = proof_config.get("created")
    if created is not None and not isinstance(created, str):
        raise ValueError("INVALID_PROOF_DATETIME: created must be a string when set")
    proof_config["@context"] = unsecured_document.get("@context", [])
    return proof_config


def hash_data_mldsa44_jcs(unsecured_document: dict[str, Any], proof_options: dict[str, Any]) -> bytes:
    """Section 3.1.1 Hashing for ``mldsa44-jcs-2024`` (SHA-256): proofConfigHash || transformedDocumentHash."""
    proof_config = _proof_configuration_map(unsecured_document, proof_options)
    canonical_proof_config = _jcs_canonical_bytes(proof_config)
    transformed = _jcs_canonical_bytes(unsecured_document)
    h_cfg = hashlib.sha256(canonical_proof_config).digest()
    h_doc = hashlib.sha256(transformed).digest()
    return h_cfg + h_doc


def _verify_external_mu(pk: bytes, mu: bytes, sig: bytes) -> bool:
    """Verify ML-DSA-44 signature where ``mu`` is 64-byte hashData (``sign_external_mu`` path).

    Mirrors ``dilithium_py.ml_dsa.ML_DSA._verify_internal`` but uses the supplied ``mu`` instead of
    ``H(tr || M')``.
    """
    ml = ML_DSA
    rho, t1 = ml._unpack_pk(pk)
    try:
        c_tilde, z, h = ml._unpack_sig(sig)
    except ValueError:
        return False

    if h.sum_hint() > ml.omega:
        return False

    if z.check_norm_bound(ml.gamma_1 - ml.beta):
        return False

    A_hat = ml._expand_matrix_from_seed(rho)

    c = ml.R.sample_in_ball(c_tilde, ml.tau)

    c = c.to_ntt()
    z = z.to_ntt()

    t1 = t1.scale(1 << ml.d)
    t1 = t1.to_ntt()

    Az_minus_ct1 = (A_hat @ z) - t1.scale(c)
    Az_minus_ct1 = Az_minus_ct1.from_ntt()

    w_prime = h.use_hint(Az_minus_ct1, 2 * ml.gamma_2)
    w_prime_bytes = w_prime.bit_pack_w(ml.gamma_2)

    return c_tilde == ml._h(mu + w_prime_bytes, ml.c_tilde_bytes)


@dataclass(frozen=True)
class KeyPair:
    public_key: bytes
    secret_key: bytes


def generate_keypair() -> KeyPair:
    public_key, secret_key = ML_DSA.keygen()
    return KeyPair(public_key=public_key, secret_key=secret_key)


def generate_keypair_from_seed(seed_material: bytes) -> KeyPair:
    """Derive ML-DSA keypair deterministically from arbitrary seed bytes.

    ζ is SHA-256(seed_material) (32 bytes), then dilithium-py ML-DSA keygen internal
    path is used. Relies on ``ML_DSA._keygen_internal`` (library private API).
    """
    zeta = hashlib.sha256(seed_material).digest()
    public_key, secret_key = ML_DSA._keygen_internal(zeta)
    return KeyPair(public_key=public_key, secret_key=secret_key)


def sign_payload(payload: Any, secret_key: bytes) -> str:
    """Legacy: sign JCS(payload) with ML-DSA (library default message formatting)."""
    message = canonicalize_json(payload)
    signature = ML_DSA.sign(secret_key, message)
    return _proof_value_encode(signature)


def verify_payload_legacy(payload: Any, proof_value: str, public_key: bytes) -> bool:
    """Verify pre–Data-Integrity-layout proofs (``type`` was the cryptosuite id; optional ``u`` on proofValue)."""
    message = canonicalize_json(payload)
    signature = _proof_value_decode(proof_value)
    return bool(ML_DSA.verify(public_key, message, signature))


def verify_proof_mldsa44_jcs(
    secured_document: dict[str, Any],
    public_key: bytes,
) -> VerificationResult:
    """Verify per [[di-quantum-safe]] §3.3.2 *Verify Proof (ML-DSA)* (``mldsa44-jcs-2024`` only).

    ``securedDocument`` MUST contain a top-level ``proof`` map. The unsecured document is the same map
    with ``proof`` removed.
    """
    proof = secured_document.get("proof")
    if not isinstance(proof, dict):
        return VerificationResult(False, None)

    unsecured_document: dict[str, Any] = {
        k: v for k, v in secured_document.items() if k != "proof"
    }

    if proof.get("cryptosuite") != CRYPTOSUITE:
        return VerificationResult(False, None)

    proof_value = proof.get("proofValue")
    if not isinstance(proof_value, str):
        return VerificationResult(False, None)
    try:
        proof_bytes = _proof_value_decode(proof_value)
    except (ValueError, binascii.Error):
        return VerificationResult(False, None)

    proof_options = {k: v for k, v in proof.items() if k != "proofValue"}
    try:
        hash_data = hash_data_mldsa44_jcs(unsecured_document, proof_options)
    except ValueError:
        return VerificationResult(False, None)

    verified = _verify_external_mu(public_key, hash_data, proof_bytes)
    if not verified:
        return VerificationResult(False, None)
    return VerificationResult(True, copy.deepcopy(unsecured_document))


def verify_data_integrity_proof(
    unsecured_document: dict[str, Any],
    proof: dict[str, Any],
    public_key: bytes,
) -> bool:
    """Verify detached ``proof`` over ``unsecured_document`` (same semantics as a secured doc with ``proof`` nested)."""
    secured: dict[str, Any] = {**unsecured_document, "proof": proof}
    return verify_proof_mldsa44_jcs(secured, public_key).verified


def verify_payload(payload: Any, proof: dict[str, Any] | str, public_key: bytes) -> bool:
    """Verify using a proof map, or legacy ``proofValue`` string only."""
    if isinstance(proof, str):
        return verify_payload_legacy(payload, proof, public_key)
    if proof.get("type") == PROOF_TYPE and proof.get("cryptosuite") == CRYPTOSUITE:
        if not isinstance(payload, dict):
            return False
        return verify_proof_mldsa44_jcs({**payload, "proof": proof}, public_key).verified
    # Older layout: cryptosuite string was carried in ``type``.
    if "cryptosuite" not in proof and proof.get("type") in (CRYPTOSUITE, "mldsa-jcs-2024"):
        pv = proof.get("proofValue", "")
        if not isinstance(pv, str):
            return False
        return verify_payload_legacy(payload, pv, public_key)
    return False


def make_proof(
    unsecured_document: dict[str, Any],
    secret_key: bytes,
    *,
    verification_method: str,
    proof_created: str | None = None,
) -> dict[str, Any]:
    """Create a Data Integrity proof per Section 3.3.1 Create Proof (ML-DSA) / [[di-quantum-safe]]."""
    options: dict[str, Any] = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "verificationMethod": verification_method,
    }
    if proof_created is not None:
        options["created"] = proof_created

    hash_data = hash_data_mldsa44_jcs(unsecured_document, options)
    proof_bytes = ML_DSA.sign_external_mu(secret_key, hash_data, deterministic=False)
    proof_value = _proof_value_encode(proof_bytes)

    out = {**options, "proofValue": proof_value}
    return out
