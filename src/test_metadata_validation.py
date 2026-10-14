
import pytest

from discovery_client import validate_metadata


def test_valid_metadata_is_accepted():
    metadata = {
        "service": "latency",
        "url": "http://127.0.0.1:5001/latency",
    }
    assert validate_metadata(metadata, "latency") == metadata


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        [],
        "not a JSON object",
        {},
        {"service": "latency"},
        {"service": "latency", "url": ""},
        {"service": "latency", "url": 123},
        {"service": "traceroute", "url": "http://localhost/test"},
        {"service": "latency", "url": "javascript:alert(1)"},
    ],
)
def test_invalid_metadata_is_rejected(metadata):
    with pytest.raises(ValueError):
        validate_metadata(metadata, "latency")


def test_unsupported_service_is_rejected():
    with pytest.raises(ValueError):
        validate_metadata(
            {"service": "unknown", "url": "http://localhost/test"},
            "unknown",
        )
