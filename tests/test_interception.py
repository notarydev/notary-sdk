"""Tests for the WO-2 capture/interception MVP."""

from __future__ import annotations

import json

import pytest

from notary import ForensicSnapshot, capture_run, instrument, verify
from notary.interception import RunCapture

SECRET = b"test-secret-key-32-bytes-long!!!"


class TestRunCapture:
    def test_missing_key_raises(self) -> None:
        with pytest.raises(ValueError, match="secret_key"):
            RunCapture(b"")

    def test_finalize_empty_raises(self) -> None:
        cap = RunCapture(SECRET)
        with pytest.raises(ValueError, match="no elements"):
            cap.finalize()

    def test_capture_llm(self) -> None:
        cap = RunCapture(SECRET)
        cap.capture_llm(prompt="hi", response="hello", metadata={"model": "gpt"})
        snap = cap.finalize()
        assert len(snap.elements) == 1
        assert snap.elements[0].kind == "llm"
        assert snap.elements[0].payload["prompt"] == "hi"

    def test_capture_http(self) -> None:
        cap = RunCapture(SECRET)
        cap.capture_http(request="req", response="resp", status=200)
        snap = cap.finalize()
        assert snap.elements[0].kind == "http"
        assert snap.elements[0].payload["status"] == 200

    def test_capture_decision(self) -> None:
        cap = RunCapture(SECRET)
        cap.capture_decision("approve")
        snap = cap.finalize()
        assert snap.elements[0].kind == "decision"
        assert snap.elements[0].payload["decision"] == "approve"

    def test_capture_rng_seed(self) -> None:
        cap = RunCapture(SECRET)
        cap.capture_rng_seed(42)
        snap = cap.finalize()
        assert snap.elements[0].kind == "rng_seed"

    def test_capture_timestamp(self) -> None:
        cap = RunCapture(SECRET)
        cap.capture_timestamp("2025-01-01T00:00:00Z")
        snap = cap.finalize()
        assert snap.elements[0].kind == "timestamp"

    def test_snapshot_is_sealed(self) -> None:
        cap = RunCapture(SECRET)
        cap.capture_decision("ok")
        snap = cap.finalize()
        assert snap.root_hash != ""
        assert len(snap.merkle_chain) == 1
        assert verify(snap, SECRET) is True

    def test_snapshot_json_round_trip(self) -> None:
        cap = RunCapture(SECRET)
        cap.capture_llm(prompt="test", response="answer")
        cap.capture_decision("done")
        snap = cap.finalize()
        raw = snap.to_json()
        restored = ForensicSnapshot.from_json(raw)
        assert verify(restored, SECRET) is True

    def test_snapshot_submit_posts_raw_snapshot_with_metadata(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with capture_run(SECRET) as cap:
            cap.capture_decision("ESCALATE")
        snap = cap.snapshot
        assert snap is not None

        class Response:
            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self) -> bytes:
                return b'{"id":"vr-submit-test"}'

        captured: dict[str, object] = {}

        def fake_urlopen(req: object, timeout: float) -> Response:
            captured["request"] = req
            captured["timeout"] = timeout
            return Response()

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        result = snap.submit(
            "https://api.example.test",
            api_token="token",
            metadata={"source_record_ref": "CASE-1", "expected_outcome": "ESCALATE"},
        )
        assert result["id"] == "vr-submit-test"
        req = captured["request"]
        assert req.full_url.endswith("/v1/verification-records/from-snapshot")
        assert req.get_header("Authorization") == "Bearer token"
        body = json.loads(req.data.decode("utf-8"))
        assert body["source_record_ref"] == "CASE-1"
        assert body["elements"][0]["payload"]["decision"] == "ESCALATE"


class TestInstrumentDecorator:
    def test_captures_return_value(self) -> None:
        @instrument(secret_key=SECRET)
        def agent() -> str:
            return "approved"

        result = agent()
        assert result == "approved"
        snap = agent.notary_last_snapshot  # type: ignore[attr-defined]
        assert snap is not None
        assert isinstance(snap, ForensicSnapshot)
        assert snap.elements[-1].payload["decision"]["result"] == "approved"
        assert verify(snap, SECRET) is True

    def test_captures_exception(self) -> None:
        @instrument(secret_key=SECRET)
        def bad_agent() -> None:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            bad_agent()
        snap = bad_agent.notary_last_snapshot  # type: ignore[attr-defined]
        assert snap is not None
        assert snap.elements[-1].payload["decision"]["error"] is True
        assert verify(snap, SECRET) is True

    def test_noop_passthrough(self) -> None:
        @instrument(secret_key=SECRET)
        def sample() -> str:
            return "ok"

        assert sample() == "ok"


class TestCaptureRunContextManager:
    def test_manual_capture(self) -> None:
        with capture_run(SECRET) as cap:
            cap.capture_llm(prompt="hi", response="hello")
            cap.capture_http(request="get", response="ok", status=200)
            cap.capture_decision("approve")
        snap = cap.snapshot
        assert snap is not None
        assert len(snap.elements) == 3
        assert verify(snap, SECRET) is True

    def test_json_includes_required_fields(self) -> None:
        with capture_run(SECRET) as cap:
            cap.capture_decision("yes")
        snap = cap.snapshot
        assert snap is not None
        raw = json.loads(snap.to_json())
        assert "schema_version" in raw
        assert "timestamp" in raw
        assert "elements" in raw
        assert "merkle_chain" in raw
        assert "root_hash" in raw


class TestNoNetworkDependency:
    def test_no_cloud_imports(self) -> None:
        import sys

        for mod in ("requests", "httpx", "boto3", "openai", "anthropic"):
            assert mod not in sys.modules
