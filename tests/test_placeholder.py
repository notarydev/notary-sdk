import notary

def test_package_imports() -> None:
    assert notary.__version__ == "0.0.1"

def test_schema_version_is_int() -> None:
    assert notary.SCHEMA_VERSION == 1
    assert isinstance(notary.SCHEMA_VERSION, int)

def test_public_api_exposed() -> None:
    assert hasattr(notary, "instrument")
    assert hasattr(notary, "ForensicSnapshot")
    assert hasattr(notary, "verify")

def test_instrument_is_noop_passthrough() -> None:
    @notary.instrument(secret_key=b"placeholder")
    def sample() -> str:
        return "ok"

    assert sample() == "ok"
