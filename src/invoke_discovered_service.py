
import os
import requests
from urllib.parse import urlparse
from discovery_client import discover_service

SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "")

ALLOWED_URLS = {
    "latency": "http://127.0.0.1:5001/latency",
    "traceroute": "http://127.0.0.1:5001/traceroute",
    "health": "http://127.0.0.1:5001/health",
}


def invoke_service(service_name):
    metadata = discover_service(service_name)

    if not metadata:
        print("FAILED: Service discovery or DNSSEC validation failed.")
        return

    url = metadata.get("url")

    # Never invoke an arbitrary URL obtained from DNS metadata.
    if url != ALLOWED_URLS.get(service_name):
        print("REJECTED: Service URL is not allowlisted.")
        return

    if service_name != "health" and not SERVICE_TOKEN:
        print("REJECTED: SERVICE_TOKEN is not configured.")
        return

    headers = {}
    if SERVICE_TOKEN:
        headers["Authorization"] = f"Bearer {SERVICE_TOKEN}"

    try:
        response = requests.get(url, headers=headers, timeout=3)
        print(f"HTTP status: {response.status_code}")

        if response.ok:
            print("Service response:")
            print(response.json())
        elif response.status_code == 401:
            print("REJECTED: Service authorization failed.")
        else:
            print("Service invocation failed.")

    except requests.RequestException as exc:
        print(f"Service unavailable: {exc}")


if __name__ == "__main__":
    name = input(
        "Service to invoke (latency/traceroute/health): "
    ).strip().lower()

    if name not in ALLOWED_URLS:
        print("Unsupported service.")
    else:
        invoke_service(name)
