# notary-sdk — Python SDK for AI Decision Capture

**GitHub:** `notarydev/notary-sdk` | **Latest:** `56b0a78` | **Branch:** `main`

## What this is

Python client library for explicitly capturing AI decision evidence as forensic snapshots. Provides `RunCapture`, the `@instrument` decorator, and the `capture_run` context manager.

## Key files

| Area | Files |
|---|---|
| Explicit capture helpers | `src/notary/interception.py` |
| Cryptographic sealing | `src/notary/sealing.py` |
| Snapshot model | `src/notary/snapshot.py` |
| Verification | `src/notary/verify.py` |
| Tests | `tests/test_crypto_core.py`, `tests/test_interception.py` |
| CI | `.github/workflows/ci.yml` |

## Usage

```python
from notary import RunCapture, verify

capture = RunCapture(secret_key=b"your-key")
capture.capture_llm(prompt="...", response="...")
capture.capture_http(request={...}, response={...})
capture.capture_decision(decision="APPROVE")
snapshot = capture.finalize()

assert verify(snapshot, secret_key=b"your-key")
```

## Claim boundaries

Allowed public claims for the current SDK:

- Manual capture with `RunCapture`.
- Function-level capture with `@instrument`.
- Scoped manual capture with `capture_run`.
- HMAC-SHA256 element sealing, Merkle root generation, and local verification.

Unsupported until implemented and tested:

- Transparent interception of OpenAI, Anthropic, requests, httpx, browser, or cloud SDK calls.
- Claims that every API call or LLM invocation is captured automatically.
- Claims that PyPI or npm packages are published unless release verification confirms it.
- Platform ingest, GRC integrations, or compliance certification flows from this SDK alone.

## Build/Run

```bash
pip install -e ".[dev]"
pytest -q    # 54 tests
```

## State

- Python-only SDK. No JS/Go/Java equivalents.
- Explicitly captures: LLM payloads, HTTP payloads, decisions, timestamps, RNG seeds
- Seals evidence with HMAC-SHA256 + Merkle tree
- 54 tests passing
