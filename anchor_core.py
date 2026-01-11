#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union


# --- Proof schema / meta ---
ANCHOR_VERSION = "v1"               # legacy/human
PROOF_SCHEMA = "anchor-proof-1"     # machine schema
COMMITMENT_ALG = "sha256(file_bytes)"
KDF_ALG = "sha256(' '.join(seed_words))"
SIG_ALG = "hmac-sha256(key=sha256(seed_words), data=commitment)"


def normalize_seed(seed_text: str) -> List[str]:
    # lower + split by ANY whitespace (spaces/newlines/tabs), collapse automatically
    return [w for w in seed_text.lower().split() if w]


def assert_24_words(seed_words: List[str]) -> None:
    if len(seed_words) != 24:
        raise ValueError(f"Seed must contain exactly 24 words (you have {len(seed_words)}).")


def _seed_to_key(seed_words: List[str]) -> bytes:
    joined = " ".join(seed_words).encode("utf-8")
    return hashlib.sha256(joined).digest()


def seed_fingerprint(seed_text: str, n_hex: int = 12) -> str:
    words = normalize_seed(seed_text)
    joined = " ".join(words).encode("utf-8")
    return hashlib.sha256(joined).hexdigest()[:n_hex]


def hash_file(file_path: Union[str, Path]) -> str:
    p = Path(file_path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sign(commitment_hex: str, key: bytes) -> str:
    # commitment_hex is a hex string; we HMAC the UTF-8 bytes of that hex
    return hmac.new(key, commitment_hex.encode("utf-8"), hashlib.sha256).hexdigest()


def _resolve_seed_and_file(seed_text: str, file_path: Union[str, Path]) -> Tuple[List[str], Path]:
    seed_words = normalize_seed(seed_text)
    assert_24_words(seed_words)

    p = Path(file_path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"File not found: {p}")

    return seed_words, p


def create_proof(seed_text: str, file_path: Union[str, Path]) -> Dict[str, Any]:
    seed_words, p = _resolve_seed_and_file(seed_text, file_path)

    commitment = hash_file(p)
    key = _seed_to_key(seed_words)
    signature = sign(commitment, key)

    proof = {
        "anchor": ANCHOR_VERSION,
        "schema": PROOF_SCHEMA,
        "commitment_alg": COMMITMENT_ALG,
        "kdf": KDF_ALG,
        "sig_alg": SIG_ALG,
        "file_name": p.name,
        "commitment": commitment,
        "signature": signature,
        "seed_fp": seed_fingerprint(seed_text),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return proof


def save_proof(proof: Dict[str, Any], out_path: Union[str, Path]) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(proof, f, ensure_ascii=False, indent=2)


def load_proof(proof_path: Union[str, Path]) -> Dict[str, Any]:
    p = Path(proof_path)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def verify(seed_text: str, file_path: Union[str, Path], proof: Dict[str, Any]) -> Tuple[bool, str]:
    seed_words, p = _resolve_seed_and_file(seed_text, file_path)

    # 1) Check file commitment matches proof commitment
    current_commitment = hash_file(p)
    proof_commitment = str(proof.get("commitment", ""))

    if current_commitment != proof_commitment:
        return False, "❌ HASH MISMATCH: file has changed since proof creation."

    # 2) Check seed controls signature
    key = _seed_to_key(seed_words)
    expected_sig = sign(proof_commitment, key)
    proof_sig = str(proof.get("signature", ""))

    if not hmac.compare_digest(expected_sig, proof_sig):
        proof_fp = proof.get("seed_fp", "— (legacy proof)")
        your_fp = seed_fingerprint(seed_text)
        return (
            False,
            "❌ SIGNATURE INVALID: seed does NOT control this proof.\n"
            f"• Proof owner fingerprint: {proof_fp}\n"
            f"• Your seed fingerprint:  {your_fp}"
        )

    return True, "✅ Verified: file is unchanged and your seed controls the proof."


def diagnose(seed_text: str, file_path: Union[str, Path], proof_path: Union[str, Path, None]) -> Dict[str, Any]:
    """
    Returns a dict useful for debugging UI:
    - file exists?
    - seed words count?
    - current commitment
    - proof commitment
    - expected sig (if seed is valid)
    - status
    """
    result: Dict[str, Any] = {
        "file": str(file_path),
        "proof": str(proof_path) if proof_path else None,
        "seed_words": len(normalize_seed(seed_text)),
        "seed_fp": seed_fingerprint(seed_text) if normalize_seed(seed_text) else None,
        "current_commitment": None,
        "proof_commitment": None,
        "expected_sig": None,
        "proof_sig": None,
        "status": "—",
    }

    p_file = Path(file_path) if file_path else None
    p_proof = Path(proof_path) if proof_path else None

    proof: Dict[str, Any] = {}
    if p_proof and p_proof.exists() and p_proof.is_file():
        try:
            proof = load_proof(p_proof)
            result["proof_commitment"] = proof.get("commitment")
            result["proof_sig"] = proof.get("signature")
        except Exception as e:
            result["status"] = f"proof load error: {e}"
            return result

    if p_file and p_file.exists() and p_file.is_file():
        try:
            result["current_commitment"] = hash_file(p_file)
        except Exception as e:
            result["status"] = f"file hash error: {e}"
            return result
    else:
        result["status"] = "file missing"
        return result

    words = normalize_seed(seed_text)
    if len(words) != 24:
        result["status"] = f"seed invalid ({len(words)} words)"
        return result

    if p_file and p_file.exists() and p_file.is_file():
        key = _seed_to_key(words)
        result["expected_sig"] = sign(result["current_commitment"], key)

    if proof and p_file and p_file.exists() and p_file.is_file():
        ok, msg = verify(seed_text, str(p_file), proof)
        result["status"] = "OK" if ok else msg

    return result


# ----------------------------
# System manifest proofs
# ----------------------------

def create_manifest_proof(seed_text: str, manifest_sha256_hex: str, label: str = "system") -> Dict[str, Any]:
    """Create a proof for a manifest commitment (sha256 of a deterministic manifest).

    This reuses the same Anchor model as file proofs:
      signature = HMAC_SHA256(key=SHA256(seed_words_joined), data=manifest_sha256_hex)

    Args:
        seed_text: 24-word seed phrase.
        manifest_sha256_hex: hex digest of sha256(manifest_jsonl).
        label: optional label to indicate the scope (e.g., system, home, dataset).
    """
    seed_words = normalize_seed(seed_text)
    assert_24_words(seed_words)

    key = _seed_to_key(seed_words)
    signature = sign(manifest_sha256_hex, key)

    return {
        "anchor": ANCHOR_VERSION,
        "schema": "anchor-manifest-proof-1",
        "commitment_alg": "sha256(manifest_jsonl)",
        "kdf": KDF_ALG,
        "sig_alg": SIG_ALG,
        "label": label,
        "commitment": manifest_sha256_hex,
        "signature": signature,
        "seed_fp": seed_fingerprint(seed_text),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def verify_manifest_proof(seed_text: str, manifest_sha256_hex: str, proof: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify a manifest proof against a manifest commitment and a seed."""
    proof_commitment = str(proof.get("commitment", ""))
    if manifest_sha256_hex != proof_commitment:
        return False, "❌ HASH MISMATCH: manifest does not match proof."

    seed_words = normalize_seed(seed_text)
    if len(seed_words) != 24:
        return False, f"❌ Seed must contain exactly 24 words (you have {len(seed_words)})."

    key = _seed_to_key(seed_words)
    expected_sig = sign(manifest_sha256_hex, key)
    proof_sig = str(proof.get("signature", ""))

    if not hmac.compare_digest(expected_sig, proof_sig):
        proof_fp = proof.get("seed_fp", "— (legacy proof)")
        your_fp = seed_fingerprint(seed_text)
        return (
            False,
            "❌ SIGNATURE INVALID: seed does NOT control this proof.\n"
            f"• Proof owner fingerprint: {proof_fp}\n"
            f"• Your seed fingerprint:  {your_fp}"
        )

    return True, "✅ Verified: manifest matches proof and your seed controls the proof."
