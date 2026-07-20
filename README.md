# Notary Forensic Logger SDK

Offline-first capture and sealing library for AI agents. Use explicit manual, context-manager, or decorator capture to record selected LLM calls, HTTP/tool calls, and decisions, then verify the sealed snapshot locally.

This package does not currently provide tested transparent interception of all OpenAI, Anthropic, framework, or outbound HTTP calls. Treat broad automatic interception as planned work until it is implemented and covered by tests.

## Features

- **Offline-first**: Zero cloud/network dependencies. All sealing happens locally using HMAC-SHA256 and Merkle chaining.
- **Cryptographic sealing**: Captured snapshot elements are HMAC-sealed and Merkle-rooted for tamper evidence.
- **Explicit capture APIs**: Record selected LLM prompts/completions, HTTP requests/responses, decision points, timestamps, and RNG seeds through `RunCapture`, `capture_run`, or `@instrument`.
- **Local verification**: Verify chains and root hashes without contacting any service.
- **Scoped claim boundary**: The SDK proves the integrity of what your code explicitly captures; it does not certify that every runtime side effect was captured.
- **Schema versioning**: Create schema-v1 forensic snapshots that can be checked locally.

## Installation

This repository is currently used from source. PyPI publishing must be verified before documenting a package-index install as the primary path.

```bash
python -m pip install -e ".[dev]"
```

## Quick Start

```python
from notary import RunCapture, verify

secret = b"replace-with-your-test-secret"
capture = RunCapture(secret)
capture.capture_llm(prompt="loan application", response="review policy")
capture.capture_http(
    request={"method": "POST", "url": "https://example.local/score"},
    response={"score": 681},
    status=200,
)
capture.capture_decision("UNDERWRITING_REVIEW")
snapshot = capture.finalize(timestamp="2026-07-20T00:00:00Z")

assert verify(snapshot, secret) is True
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
- PyPI or npm package availability until a release is explicitly published and verified.

## Repository Structure

- `src/notary/` — Python SDK package
  - `sealing.py` — HMAC-SHA256 and Merkle chaining
  - `interception.py` — explicit manual/context/decorator capture APIs
  - `snapshot.py` — ForensicSnapshot model with schema versioning
  - `verify.py` — Local root-hash verification
- `packages/notary-sdk-ts/` — Placeholder TypeScript package
- `tests/` — Test suite
- `.github/workflows/` — CI/CD pipelines

## License

Apache License 2.0. See [LICENSE](./LICENSE) for details.

## Security

For security vulnerability reporting, see [SECURITY.md](./SECURITY.md).

## Contributing

Contributions welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md).
