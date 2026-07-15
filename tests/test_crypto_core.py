"""Tests for the offline SDK cryptographic core (WO-1)."""

from __future__ import annotations

import pytest

from notary.sealing import compute_root_hash, seal_captured_elements, seal_element
from notary.snapshot import CapturedElement, ForensicSnapshot
from notary.verify import verify

SECRET = b"test-secret-key-32-bytes-long!!!"


# ---------------------------------------------------------------------------
# seal_element
# ---------------------------------------------------------------------------


class TestSealElement:
    def test_deterministic(self) -> None:
        a = seal_element(b"\x00" * 32, b"hello", SECRET)
        b = seal_element(b"\x00" * 32, b"hello", SECRET)
        assert a == b

    def test_changes_when_data_changes(self) -> None:
        a = seal_element(b"\x00" * 32, b"hello", SECRET)
        b = seal_element(b"\x00" * 32, b"world", SECRET)
        assert a != b

    def test_changes_when_key_changes(self) -> None:
        other = b"different-key-32-bytes-long!!!"
        a = seal_element(b"\x00" * 32, b"hello", SECRET)
        b = seal_element(b"\x00" * 32, b"hello", other)
        assert a != b

    def test_empty_key_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_key"):
            seal_element(b"\x00" * 32, b"hello", b"")

    def test_non_bytes_key_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_key"):
            seal_element(b"\x00" * 32, b"hello", "not-bytes")  # type: ignore[arg-type]

    def test_returns_32_bytes(self) -> None:
        h = seal_element(b"\x00" * 32, b"data", SECRET)
        assert isinstance(h, bytes)
        assert len(h) == 32


# ---------------------------------------------------------------------------
# seal_captured_elements
# ---------------------------------------------------------------------------


def _make_elements() -> list[CapturedElement]:
    return [
        CapturedElement(kind="llm", payload={"prompt": "hi"}),
        CapturedElement(kind="http", payload={"url": "https://x.com"}),
    ]


class TestSealCapturedElements:
    def test_populates_hashes_and_root(self) -> None:
        elems = _make_elements()
        hashes, chain, root = seal_captured_elements(elems, SECRET)
        assert len(hashes) == 2
        assert len(chain) == 2
        assert len(root) == 64  # hex-encoded SHA-256
        for elem, h in zip(elems, hashes):
            assert elem.element_hash == h

    def test_empty_elements_raises(self) -> None:
        with pytest.raises(ValueError, match="elements"):
            seal_captured_elements([], SECRET)

    def test_empty_key_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_key"):
            seal_captured_elements(_make_elements(), b"")

    def test_root_changes_when_content_changes(self) -> None:
        e1 = _make_elements()
        _, _, r1 = seal_captured_elements(e1, SECRET)
        e2 = [
            CapturedElement(kind="llm", payload={"prompt": "changed"}),
            CapturedElement(kind="http", payload={"url": "https://x.com"}),
        ]
        _, _, r2 = seal_captured_elements(e2, SECRET)
        assert r1 != r2

    def test_root_changes_when_order_changes(self) -> None:
        e1 = _make_elements()
        _, _, r1 = seal_captured_elements(e1, SECRET)
        e2 = list(reversed(e1))
        _, _, r2 = seal_captured_elements(e2, SECRET)
        assert r1 != r2


# ---------------------------------------------------------------------------
# compute_root_hash
# ---------------------------------------------------------------------------


class TestComputeRootHash:
    def test_single_hash(self) -> None:
        h = b"\x01" * 32
        assert compute_root_hash([h]) == h.hex()

    def test_two_hashes(self) -> None:
        a, b = b"\x01" * 32, b"\x02" * 32
        expected = __import__("hashlib").sha256(a + b).hexdigest()
        assert compute_root_hash([a, b]) == expected

    def test_odd_count_duplicates_last(self) -> None:
        a, b, c = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
        import hashlib

        ab = hashlib.sha256(a + b).digest()
        cc = hashlib.sha256(c + c).digest()
        root = hashlib.sha256(ab + cc).hexdigest()
        assert compute_root_hash([a, b, c]) == root

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            compute_root_hash([])


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def _sealed_snapshot() -> ForensicSnapshot:
    elems = _make_elements()
    hashes, chain, root = seal_captured_elements(elems, SECRET)
    return ForensicSnapshot(
        schema_version=1,
        timestamp="2025-01-01T00:00:00Z",
        elements=elems,
        merkle_chain=chain,
        root_hash=root,
    )


class TestVerify:
    def test_authentic_snapshot(self) -> None:
        snap = _sealed_snapshot()
        assert verify(snap, SECRET) is True

    def test_false_after_tamper(self) -> None:
        snap = _sealed_snapshot()
        snap.elements[0].payload = {"prompt": "tampered"}
        assert verify(snap, SECRET) is False

    def test_false_after_reorder(self) -> None:
        snap = _sealed_snapshot()
        snap.elements = list(reversed(snap.elements))
        assert verify(snap, SECRET) is False

    def test_false_wrong_key(self) -> None:
        snap = _sealed_snapshot()
        assert verify(snap, b"wrong-key-32-bytes-long!!!!!!!!!!") is False

    def test_false_empty_key(self) -> None:
        snap = _sealed_snapshot()
        assert verify(snap, b"") is False

    def test_false_no_key_type(self) -> None:
        snap = _sealed_snapshot()
        assert verify(snap, "not-bytes") is False  # type: ignore[arg-type]

    def test_false_empty_elements(self) -> None:
        snap = ForensicSnapshot(
            schema_version=1, timestamp="t", elements=[], root_hash=""
        )
        assert verify(snap, SECRET) is False

    def test_no_network_dependency(self) -> None:
        import sys

        assert "requests" not in sys.modules
        assert "httpx" not in sys.modules
