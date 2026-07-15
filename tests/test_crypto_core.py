"""Tests for the offline SDK cryptographic core (WO-1), hardened."""

from __future__ import annotations

import json

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
        b_val = seal_element(b"\x00" * 32, b"hello", SECRET)
        assert a == b_val

    def test_changes_when_data_changes(self) -> None:
        a = seal_element(b"\x00" * 32, b"hello", SECRET)
        b_val = seal_element(b"\x00" * 32, b"world", SECRET)
        assert a != b_val

    def test_changes_when_key_changes(self) -> None:
        other = b"different-key-32-bytes-long!!!"
        a = seal_element(b"\x00" * 32, b"hello", SECRET)
        b_val = seal_element(b"\x00" * 32, b"hello", other)
        assert a != b_val

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
        assert len(root) == 64
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
        import hashlib

        a, b_val = b"\x01" * 32, b"\x02" * 32
        expected = hashlib.sha256(a + b_val).hexdigest()
        assert compute_root_hash([a, b_val]) == expected

    def test_odd_count_duplicates_last(self) -> None:
        import hashlib

        a, b_val, c = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
        ab = hashlib.sha256(a + b_val).digest()
        cc = hashlib.sha256(c + c).digest()
        root = hashlib.sha256(ab + cc).hexdigest()
        assert compute_root_hash([a, b_val, c]) == root

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            compute_root_hash([])

    def test_non_bytes_raises(self) -> None:
        with pytest.raises(ValueError, match="32-byte"):
            compute_root_hash(["not-bytes"])  # type: ignore[list-item]

    def test_wrong_length_raises(self) -> None:
        with pytest.raises(ValueError, match="32-byte"):
            compute_root_hash([b"\x00" * 16])


# ---------------------------------------------------------------------------
# snapshot serialization
# ---------------------------------------------------------------------------


class TestSnapshotSerialization:
    def test_canonical_bytes_excludes_element_hash(self) -> None:
        e = CapturedElement(kind="llm", payload={"a": 1}, element_hash="deadbeef")
        cb = e.canonical_bytes()
        assert b"deadbeef" not in cb
        parsed = json.loads(cb)
        assert parsed["kind"] == "llm"
        assert parsed["payload"] == {"a": 1}

    def test_canonical_bytes_deterministic(self) -> None:
        e = CapturedElement(kind="http", payload={"z": 2, "a": 1})
        assert e.canonical_bytes() == e.canonical_bytes()

    def test_to_json_round_trip(self) -> None:
        snap = _sealed_snapshot()
        raw = snap.to_json()
        restored = ForensicSnapshot.from_json(raw)
        assert restored.schema_version == snap.schema_version
        assert restored.timestamp == snap.timestamp
        assert len(restored.elements) == len(snap.elements)
        assert restored.root_hash == snap.root_hash
        assert restored.merkle_chain == snap.merkle_chain

    def test_from_dict_preserves_fields(self) -> None:
        snap = _sealed_snapshot()
        d = snap.to_dict()
        restored = ForensicSnapshot.from_dict(d)
        assert restored.schema_version == snap.schema_version
        assert restored.elements[0].kind == snap.elements[0].kind

    def test_canonical_json_deterministic_for_dict_key_order(self) -> None:
        d1 = {"b": 2, "a": 1}
        d2 = {"a": 1, "b": 2}
        e1 = CapturedElement(kind="x", payload=d1)
        e2 = CapturedElement(kind="x", payload=d2)
        assert e1.canonical_bytes() == e2.canonical_bytes()


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

    def test_false_malformed_element_hash_hex(self) -> None:
        snap = _sealed_snapshot()
        snap.elements[0].element_hash = "not-hex!!!"
        assert verify(snap, SECRET) is False

    def test_false_empty_element_hash(self) -> None:
        snap = _sealed_snapshot()
        snap.elements[0].element_hash = ""
        assert verify(snap, SECRET) is False

    def test_false_wrong_length_element_hash(self) -> None:
        snap = _sealed_snapshot()
        snap.elements[0].element_hash = "ab" * 16  # 32 hex chars = 16 bytes, not 32
        assert verify(snap, SECRET) is False

    def test_false_empty_root_hash(self) -> None:
        snap = _sealed_snapshot()
        snap.root_hash = ""
        assert verify(snap, SECRET) is False

    def test_false_malformed_root_hash(self) -> None:
        snap = _sealed_snapshot()
        snap.root_hash = "not-a-hash"
        assert verify(snap, SECRET) is False

    def test_no_network_dependency(self) -> None:
        import sys

        assert "requests" not in sys.modules
        assert "httpx" not in sys.modules
