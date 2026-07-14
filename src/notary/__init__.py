"""Notary Forensic Logger SDK — offline-first sealing and interception for AI agents."""

from notary.interception import instrument
from notary.snapshot import ForensicSnapshot
from notary.verify import verify

__version__ = "0.0.1"
__author__ = "Notary Contributors"
__license__ = "Apache-2.0"

SCHEMA_VERSION = 1
__all__ = ["instrument", "ForensicSnapshot", "verify", "SCHEMA_VERSION", "__version__"]
