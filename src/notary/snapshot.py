"""ForensicSnapshot model with schema versioning.

Defines the core data structure for capturing and sealing forensic evidence.
"""

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class ForensicSnapshot:
    """A forensic snapshot of agent execution state.
    
    Attributes:
        schema_version: Version of the snapshot schema (e.g., "1.0")
        timestamp: ISO 8601 timestamp when snapshot was captured
        data: Arbitrary captured data (LLM, HTTP, decisions, etc.)
    """

    schema_version: str
    timestamp: str
    data: Dict[str, Any]


# Placeholder: snapshot serialization and verification TBD
