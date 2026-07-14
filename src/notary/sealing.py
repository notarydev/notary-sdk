"""HMAC-SHA256 sealing and Merkle chaining — the trust root of the SDK.  Contract only. Implemented in WO-1. Uses the Python standard library only."""

from __future__ import annotations

def seal_element(prev_hash: bytes, data: bytes, secret_key: bytes) -> bytes:
    """Return the HMAC-SHA256 seal chaining ``data`` onto ``prev_hash``. (WO-1)"""
    raise NotImplementedError

def compute_root_hash(element_hashes: list[bytes]) -> str:
    """Fold per-element hashes into a single Merkle root hash. (WO-1)"""
    raise NotImplementedError
