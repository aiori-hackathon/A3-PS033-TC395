
import json
from pathlib import Path


METADATA_FILE = Path(__file__).with_name("service_metadata.json")


def load_metadata():
    with METADATA_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_all_services_have_required_fields():
    metadata = load_metadata()

    assert set(metadata.keys()) == {"latency", "traceroute", "health"}

    for name, service in metadata.items():
        assert service["service"] == name
        assert service["url"].startswith("http://127.0.0.1:5001/")
        assert service["description"]


def test_service_urls_are_unique():
    metadata = load_metadata()
    urls = [service["url"] for service in metadata.values()]

    assert len(urls) == len(set(urls))
