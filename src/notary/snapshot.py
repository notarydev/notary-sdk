"""ForensicSnapshot model with schema versioning."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib import request as urllib_request


@dataclass
class CapturedElement:
    """A single explicitly captured node in a run."""

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

    def submit(
        self,
        api_url: str,
        api_token: str = "",
        metadata: dict[str, Any] | None = None,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        """Submit this snapshot to the Platform Verification Record endpoint.

        Network access is opt-in: normal capture and local verification remain
        fully offline. ``metadata`` carries source, agent, and expected-outcome
        fields used by the platform to assess replayability.
        """
        base_url = api_url.rstrip("/")
        if not base_url:
            raise ValueError("api_url must be non-empty")
        payload = self.to_dict()
        if metadata:
            payload.update(metadata)
        headers = {"Content-Type": "application/json"}
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"
        req = urllib_request.Request(
            f"{base_url}/v1/verification-records/from-snapshot",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("platform response must be a JSON object")
        return result

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
