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
SIG_ALG = "hmac-sha256(commitment_hex)"
ANCHOR_PREFIX = "A_"


# ----------------------------
# Seed normalization / keying
# ----------------------------

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
    if not words:
        return f"{ANCHOR_PREFIX}{'0'*n_hex}"
    key = _seed_to_key(words)
    return ANCHOR_PREFIX + hashlib.sha256(key).hexdigest()[:n_hex]


# ----------------------------
# File hashing (streamed)
# ----------------------------

def hash_file(file_path: Union[str, Path]) -> str:
    p = Path(file_path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ----------------------------
# Signature
# ----------------------------

def sign(commitment_hex: str, key: bytes) -> str:
    return hmac.new(key, commitment_hex.encode("utf-8"), hashlib.sha256).hexdigest()


# ----------------------------
# Argument order compatibility
# ----------------------------

def _resolve_seed_and_file(a: str, b: str) -> Tuple[str, str]:
    """
    Accept either (seed_text, file_path) OR (file_path, seed_text).
    Whichever exists as a file becomes file_path.
    """
    pa, pb = Path(a), Path(b)
    a_is_file = pa.exists() and pa.is_file()
    b_is_file = pb.exists() and pb.is_file()

    if a_is_file and not b_is_file:
        return b, a
    if b_is_file and not a_is_file:
        return a, b

    # ambiguous: keep order and let validation raise a clear error
    return a, b


# ----------------------------
# Proof creation
# ----------------------------

def create_proof(seed_text: str, file_path: str) -> Dict[str, Any]:
    seed_text, file_path = _resolve_seed_and_file(seed_text, file_path)

    p = Path(file_path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"No such file: '{file_path}'")

    seed_words = normalize_seed(seed_text)
    assert_24_words(seed_words)

    commitment = hash_file(p)
    key = _seed_to_key(seed_words)
    signature = sign(commitment, key)

    return {
        "anchor": ANCHOR_VERSION,
        "schema": PROOF_SCHEMA,
        "commitment_alg": COMMITMENT_ALG,
        "kdf": KDF_ALG,
        "sig_alg": SIG_ALG,
        "file": p.name,
        "commitment": commitment,
        "signature": signature,
        "seed_fp": seed_fingerprint(seed_text),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


# Backwards compatibility: older UI might call make_proof
make_proof = create_proof


# ----------------------------
# Proof I/O
# ----------------------------

def save_proof(proof: Dict[str, Any], out_path: Union[str, Path]) -> None:
    out = Path(out_path)
    with out.open("w", encoding="utf-8") as f:
        json.dump(proof, f, indent=2, sort_keys=True)


def load_proof(path: Union[str, Path]) -> Dict[str, Any]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


# ----------------------------
# Verify
# ----------------------------

def verify(seed_text: str, file_path: str, proof: Dict[str, Any]) -> Tuple[bool, str]:
    seed_text, file_path = _resolve_seed_and_file(seed_text, file_path)

    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return False, f"❌ FILE NOT FOUND: '{file_path}'"

    current_commitment = hash_file(p)
    proof_commitment = str(proof.get("commitment", ""))

    if current_commitment != proof_commitment:
        return (
            False,
            "❌ HASH MISMATCH: selected file is NOT byte-identical to the anchored file."
        )

    seed_words = normalize_seed(seed_text)
    if len(seed_words) != 24:
        return False, f"❌ Seed must contain exactly 24 words (you have {len(seed_words)})."

    key = _seed_to_key(seed_words)
    expected_sig = sign(current_commitment, key)
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

    return True, "✅ Verified: file matches proof and your seed controls the proof."


# ----------------------------
# Diagnose (verbose details)
# ----------------------------

def diagnose(seed_text: str, file_path: str, proof_path: str) -> Dict[str, str]:
    result = {
        "seed_words": str(len(normalize_seed(seed_text))),
        "seed_fp": seed_fingerprint(seed_text),
        "file_exists": "no",
        "proof_exists": "no",
        "current_commitment": "",
        "proof_commitment": "",
        "expected_sig": "",
        "proof_sig": "",
        "proof_seed_fp": "",
        "status": "",
    }

    p_file = Path(file_path) if file_path else None
    p_proof = Path(proof_path) if proof_path else None

    if p_file and p_file.exists() and p_file.is_file():
        result["file_exists"] = "yes"
        result["current_commitment"] = hash_file(p_file)

    proof = None
    if p_proof and p_proof.exists() and p_proof.is_file():
        result["proof_exists"] = "yes"
        try:
            proof = load_proof(p_proof)
        except Exception:
            proof = None

    if proof:
        result["proof_commitment"] = str(proof.get("commitment", ""))
        result["proof_sig"] = str(proof.get("signature", ""))
        result["proof_seed_fp"] = str(proof.get("seed_fp", ""))

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
