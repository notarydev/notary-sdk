"""Local root-hash verification for forensic snapshots.  Offline and deterministic. Contract only — implemented in WO-1."""

from __future__ import annotations
from notary.snapshot import ForensicSnapshot

def verify(snapshot: ForensicSnapshot, secret_key: bytes) -> bool:
    """Recompute the snapshot's root hash and report whether it is authentic. (WO-1)"""
    raise NotImplementedError
