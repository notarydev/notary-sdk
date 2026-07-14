"""Transparent capture of LLM calls, outbound HTTP calls, and the agent's decision.  Contract only. Implemented in WO-2."""

from __future__ import annotations
from collections.abc import Callable
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

def instrument(secret_key: bytes) -> Callable[[F], F]:
    """Wrap an agent callable to capture and seal its run. No-op stub until WO-2."""
    def decorator(fn: F) -> F:
        return fn
    return decorator
