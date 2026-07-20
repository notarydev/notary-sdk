"""Regression tests for PRG-004 SDK public claim boundaries."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_readme_scopes_capture_claims_to_explicit_apis() -> None:
    readme = _read("README.md")
    assert "explicit manual, context-manager, or decorator capture" in readme
    assert "RunCapture" in readme
    assert "capture_run" in readme
    assert "@instrument" in readme
    assert "does not currently provide tested transparent interception" in readme
    assert "pip install notary-sdk" not in readme


def test_python_package_descriptions_do_not_claim_transparent_interception() -> None:
    for relative in ["pyproject.toml", "src/notary/__init__.py", "src/notary/interception.py"]:
        text = _read(relative).lower()
        assert "transparent capture" not in text
        assert "transparently intercept" not in text


def test_typescript_package_is_marked_placeholder() -> None:
    text = _read("packages/notary-sdk-ts/src/index.ts")
    assert "Placeholder package" in text
    assert "TypeScript parity is not yet" in text
    assert "implemented here" in text
