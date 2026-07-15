"""ForensicSnapshot model with schema versioning."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CapturedElement:
    """A single captured node in a run: an LLM call, an API call, or a decision."""

    kind: str  # "llm" | "http" | "decision" | "rng_seed" | "timestamp"
    payload: dict[str, Any] = field(default_factory=dict)
    element_hash: str = ""

    def canonical_bytes(self) -> bytes:
        """Return deterministic JSON bytes for hashing (excludes element_hash)."""
        return json.dumps(
            {"kind": self.kind, "payload": self.payload},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CapturedElement:
        """Reconstruct a ``CapturedElement`` from a plain dict."""
        return cls(
            kind=str(d.get("kind", "")),
            payload=dict(d.get("payload", {})),
            element_hash=str(d.get("element_hash", "")),
        )


@dataclass
class ForensicSnapshot:
    """A forensic snapshot of an agent run."""

    schema_version: int
    timestamp: str
    elements: list[CapturedElement] = field(default_factory=list)
    merkle_chain: list[str] = field(default_factory=list)
    root_hash: str = ""

    def element_hash_bytes(self) -> list[bytes]:
        """Return each element's stored hash as raw bytes."""
        return [bytes.fromhex(e.element_hash) for e in self.elements]

    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation suitable for JSON serialization."""
        return {
            "schema_version": self.schema_version,
            "timestamp": self.timestamp,
            "elements": [asdict(e) for e in self.elements],
            "merkle_chain": self.merkle_chain,
            "root_hash": self.root_hash,
        }

    def to_json(self) -> str:
        """Serialize the snapshot to a canonical JSON string."""
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ForensicSnapshot:
        """Reconstruct a ``ForensicSnapshot`` from a plain dict."""
        elements_raw = d.get("elements", [])
        return cls(
            schema_version=int(d.get("schema_version", 0)),
            timestamp=str(d.get("timestamp", "")),
            elements=[CapturedElement.from_dict(e) for e in elements_raw],
            merkle_chain=list(d.get("merkle_chain", [])),
            root_hash=str(d.get("root_hash", "")),
        )

    @classmethod
    def from_json(cls, raw: str) -> ForensicSnapshot:
        """Parse a canonical JSON string into a ``ForensicSnapshot``."""
        return cls.from_dict(json.loads(raw))
