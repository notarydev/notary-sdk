# notary-sdk — Python SDK for AI Decision Capture

**GitHub:** `notarydev/notary-sdk` | **Latest:** `56b0a78` | **Branch:** `main`

## What this is

Python client library for capturing AI decisions as forensic snapshots. Provides `RunCapture`, `@instrument` decorator, and `capture_run` context manager.

## Key files

| Area | Files |
|---|---|
| Explicit capture APIs | `src/notary/interception.py` |
| Cryptographic sealing | `src/notary/sealing.py` |
| Snapshot model | `src/notary/snapshot.py` |
| Verification | `src/notary/verify.py` |
| Tests | `tests/test_crypto_core.py`, `tests/test_interception.py` |
| CI | `.github/workflows/ci.yml` |

## Usage

```python
from notary import RunCapture

capture = RunCapture(secret_key=b"your-key")
capture.capture_llm(prompt="...", response="...")
capture.capture_http(request={...}, response={...})
capture.capture_decision(decision="APPROVE")
snapshot = capture.finalize()

# Send to Notary Platform
# Optional: submit snapshot to the platform from application code.
```

## Build/Run

```bash
pip install -e ".[dev]"
pytest -q    # 54 tests
```

## State

- Python-only SDK. No JS/Go/Java equivalents.
- Explicitly captures selected LLM calls, HTTP calls, decisions, timestamps, RNG seeds
- Seals evidence with HMAC-SHA256 + Merkle tree
- 54 tests passing

## Claim boundary

- Supported: manual/context/decorator capture, HMAC/Merkle sealing, local verification.
- Not yet supported as a tested claim: transparent capture of all OpenAI, Anthropic, framework, or outbound HTTP calls.
