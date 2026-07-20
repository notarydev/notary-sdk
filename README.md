# Notary Forensic Logger SDK

Offline-first capture and sealing library for AI agent evidence. The current SDK supports explicit capture through `RunCapture`, the `@instrument` decorator, and the `capture_run` context manager.

It does not yet provide transparent interception of OpenAI, Anthropic, HTTP, or other provider clients.

## Features

- **Offline-first**: Zero cloud/network dependencies. All sealing happens locally using HMAC-SHA256 and Merkle chaining.
- **Cryptographic sealing**: Every snapshot is signed and tamper-evident.
- **Explicit capture surfaces**: Record LLM payloads, HTTP payloads, decisions, timestamps, and RNG seeds when your code calls the SDK capture APIs.
- **Local verification**: Verify chains and root hashes without contacting any service.
- **Schema versioning**: Create schema-v1 forensic snapshots that can be checked locally.

## Installation

```bash
python -m pip install -e .
```

PyPI package publication is not verified for the current pilot build. Install from a checked-out repository until a release is explicitly published and verified.

## Quick Start

```python
from notary import RunCapture, verify

capture = RunCapture(secret_key=b"local-demo-key")
capture.capture_llm(prompt="Summarize invoice INV-42", response="Approved")
capture.capture_http(
    request={"method": "POST", "url": "https://example.invalid/audit"},
    response={"status": "queued"},
    status=202,
)
capture.capture_decision({"decision": "APPROVE", "reason": "policy_match"})

snapshot = capture.finalize(timestamp="2026-07-20T00:00:00Z")
assert verify(snapshot, secret_key=b"local-demo-key")
```

See [SETUP.md](./SETUP.md) for development setup instructions.

## Supported Capture Boundaries

Supported today:

- Manual capture with `RunCapture`.
- Function result/error capture with `@instrument`.
- Scoped manual capture with `capture_run`.
- Local HMAC-SHA256 sealing, Merkle root generation, and verification.

Not supported today:

- Automatic transparent interception of OpenAI, Anthropic, requests, httpx, browser, or cloud SDK calls.
- A guarantee that every API call or LLM invocation is captured without explicit instrumentation.
- Cloud ingest or compliance workflow integrations from this SDK alone.

## Repository Structure

- `src/notary/` — Python SDK package
  - `sealing.py` — HMAC-SHA256 and Merkle chaining
  - `interception.py` — explicit LLM/HTTP/decision capture helpers
  - `snapshot.py` — ForensicSnapshot model with schema versioning
  - `verify.py` — Local root-hash verification
- `packages/notary-sdk-ts/` — TypeScript implementation
- `tests/` — Test suite
- `.github/workflows/` — CI/CD pipelines

## License

Apache License 2.0. See [LICENSE](./LICENSE) for details.

## Security

For security vulnerability reporting, see [SECURITY.md](./SECURITY.md).

## Contributing

Contributions welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md).
