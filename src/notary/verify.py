"""Local root-hash verification for forensic snapshots.  Offline and deterministic."""

from __future__ import annotations

import hmac

from notary.sealing import compute_root_hash, seal_element
from notary.snapshot import ForensicSnapshot


def verify(snapshot: ForensicSnapshot, secret_key: bytes) -> bool:
    """Recompute the snapshot's root hash and report whether it is authentic.

    Returns ``True`` only when every element hash *and* the root hash match.
    Never logs or exposes the secret key.
    """
    if not isinstance(secret_key, bytes) or not secret_key:
        return False
    if not snapshot.elements:
        return False

    prev_hash = b"\x00" * 32
    recomputed_hashes: list[bytes] = []

    for elem in snapshot.elements:
        recomputed = seal_element(prev_hash, elem.canonical_bytes(), secret_key)
        recomputed_hashes.append(recomputed)
        stored = bytes.fromhex(elem.element_hash)
        if not hmac.compare_digest(recomputed, stored):
            return False
        prev_hash = recomputed

    recomputed_root = compute_root_hash(recomputed_hashes)
    return hmac.compare_digest(recomputed_root, snapshot.root_hash)
