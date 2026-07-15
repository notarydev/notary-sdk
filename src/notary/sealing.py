"""HMAC-SHA256 sealing and Merkle chaining — the trust root of the SDK."""

from __future__ import annotations

import hashlib
import hmac
from typing import Tuple

from notary.snapshot import CapturedElement


def seal_element(prev_hash: bytes, data: bytes, secret_key: bytes) -> bytes:
    """Return the HMAC-SHA256 seal chaining *data* onto *prev_hash*.

    Raises ``ValueError`` when *secret_key* is empty or inputs are not bytes.
    """
    if not isinstance(secret_key, bytes) or not secret_key:
        raise ValueError("secret_key must be non-empty bytes")
    if not isinstance(prev_hash, bytes):
        raise TypeError("prev_hash must be bytes")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hmac.new(secret_key, prev_hash + data, hashlib.sha256).digest()


def compute_root_hash(element_hashes: list[bytes]) -> str:
    """Deterministically fold *element_hashes* into a single Merkle root.

    Uses SHA-256 pairwise folding.  If the count is odd the last hash is
    duplicated for that round.  Returns the root as a hex string.

    Raises ``ValueError`` for an empty list.
    """
    if not element_hashes:
        raise ValueError("element_hashes must not be empty")

    current: list[bytes] = list(element_hashes)
    while len(current) > 1:
        next_round: list[bytes] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            next_round.append(hashlib.sha256(left + right).digest())
        current = next_round
    return current[0].hex()


def seal_captured_elements(
    elements: list[CapturedElement],
    secret_key: bytes,
) -> Tuple[list[str], list[str], str]:
    """Seal every element in order, populate hashes, and compute the root.

    Returns ``(element_hashes_hex, merkle_chain, root_hash_hex)``.

    Raises ``ValueError`` when *elements* is empty or *secret_key* is missing.
    """
    if not isinstance(secret_key, bytes) or not secret_key:
        raise ValueError("secret_key must be non-empty bytes")
    if not elements:
        raise ValueError("elements must not be empty")

    prev_hash = b"\x00" * 32
    element_hashes_hex: list[str] = []

    for elem in elements:
        h = seal_element(prev_hash, elem.canonical_bytes(), secret_key)
        hex_digest = h.hex()
        elem.element_hash = hex_digest
        element_hashes_hex.append(hex_digest)
        prev_hash = h

    root_hash = compute_root_hash([bytes.fromhex(h) for h in element_hashes_hex])
    return element_hashes_hex, element_hashes_hex, root_hash
