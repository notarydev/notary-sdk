"""Explicit capture helpers for LLM payloads, HTTP payloads, and decisions.

Provides RunCapture (manual capture), instrument (decorator), and capture_run
(context manager) for building forensic snapshots offline.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from typing import Any, Generator, TypeVar

from notary.sealing import seal_captured_elements
from notary.snapshot import CapturedElement, ForensicSnapshot

F = TypeVar("F", bound=Callable[..., Any])


class RunCapture:
    """Collect elements during an agent run and seal them into a snapshot."""

    def __init__(self, secret_key: bytes) -> None:
        if not isinstance(secret_key, bytes) or not secret_key:
            raise ValueError("secret_key must be non-empty bytes")
        self._secret_key = secret_key
        self._elements: list[CapturedElement] = []
        self._snapshot: ForensicSnapshot | None = None

    @property
    def snapshot(self) -> ForensicSnapshot | None:
        """Return the sealed snapshot, or None if not yet finalized."""
        return self._snapshot

    def capture_llm(
        self,
        prompt: Any = None,
        response: Any = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record an LLM call element."""
        payload: dict[str, Any] = {}
        if prompt is not None:
            payload["prompt"] = prompt
        if response is not None:
            payload["response"] = response
        if metadata:
            payload["metadata"] = metadata
        self._elements.append(CapturedElement(kind="llm", payload=payload))

    def capture_http(
        self,
        request: Any = None,
        response: Any = None,
        status: int | None = None,
    ) -> None:
        """Record an outbound HTTP call element."""
        payload: dict[str, Any] = {}
        if request is not None:
            payload["request"] = request
        if response is not None:
            payload["response"] = response
        if status is not None:
            payload["status"] = status
        self._elements.append(CapturedElement(kind="http", payload=payload))

    def capture_decision(self, decision: Any = None) -> None:
        """Record a decision point element."""
        self._elements.append(
            CapturedElement(kind="decision", payload={"decision": decision})
        )

    def capture_rng_seed(self, seed: Any = None) -> None:
        """Record the RNG seed for determinism."""
        self._elements.append(
            CapturedElement(kind="rng_seed", payload={"seed": seed})
        )

    def capture_timestamp(self, timestamp: str = "") -> None:
        """Record a timestamp element."""
        self._elements.append(
            CapturedElement(kind="timestamp", payload={"timestamp": timestamp})
        )

    def finalize(self, timestamp: str = "") -> ForensicSnapshot:
        """Seal all captured elements and return the snapshot."""
        if not self._elements:
            raise ValueError("no elements captured — cannot finalize")

        _, chain, root = seal_captured_elements(self._elements, self._secret_key)
        self._snapshot = ForensicSnapshot(
            schema_version=1,
            timestamp=timestamp,
            elements=list(self._elements),
            merkle_chain=chain,
            root_hash=root,
        )
        return self._snapshot


def instrument(secret_key: bytes) -> Callable[[F], F]:
    """Decorator that wraps a callable, captures its run, and seals a snapshot."""

    def decorator(fn: F) -> F:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            cap = RunCapture(secret_key)
            try:
                result = fn(*args, **kwargs)
            except BaseException:
                cap.capture_decision({"error": True})
                wrapper.notary_last_snapshot = cap.finalize()  # type: ignore[attr-defined]
                raise

            cap.capture_decision({"result": result})
            wrapper.notary_last_snapshot = cap.finalize()  # type: ignore[attr-defined]
            return result

        wrapper.notary_last_snapshot = None  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorator


@contextmanager
def capture_run(secret_key: bytes) -> Generator[RunCapture, None, None]:
    """Yield a RunCapture and finalize it when the context exits."""
    cap = RunCapture(secret_key)
    try:
        yield cap
    finally:
        if cap.snapshot is None and cap._elements:
            cap.finalize()
