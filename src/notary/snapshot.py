"""ForensicSnapshot model with schema versioning."""

from dataclasses import dataclass, field
from typing import Any

@dataclass
class CapturedElement:
    """A single captured node in a run: an LLM call, an API call, or a decision."""
    kind: str  # "llm" | "http" | "decision"
    payload: dict[str, Any] = field(default_factory=dict)
    element_hash: str = ""

@dataclass
class ForensicSnapshot:
    """A forensic snapshot of an agent run."""
    schema_version: int
    timestamp: str
    elements: list[CapturedElement] = field(default_factory=list)
    merkle_chain: list[str] = field(default_factory=list)
    root_hash: str = ""

    def to_json(self) -> str:
        """Serialize to the canonical JSON contract sent to ingestion. (WO-2)"""
        raise NotImplementedError
