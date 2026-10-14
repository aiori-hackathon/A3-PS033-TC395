
import dns.resolver
import json


DOMAIN = "diagnostics.test"


ALLOWED_SERVICES = {"latency", "traceroute", "health"}


def validate_metadata(metadata, service_name):
    if not isinstance(metadata, dict):
        raise ValueError("Metadata must be a JSON object")

    if service_name not in ALLOWED_SERVICES:
        raise ValueError("Unsupported service name")

    required_fields = {"service", "url"}
    if not required_fields.issubset(metadata):
        raise ValueError("Metadata is missing required fields")

    if metadata["service"] != service_name:
        raise ValueError("Service name does not match DNS record")

    if not isinstance(metadata["url"], str) or not metadata["url"].strip():
        raise ValueError("URL must be a non-empty string")

    if not metadata["url"].startswith(("http://", "https://")):
        raise ValueError("URL must use HTTP or HTTPS")

    return metadata



def discover_service(service_name):
    """
    Look up diagnostic-service metadata in DNS TXT records.
    This first version does not yet validate DNSSEC.
    """
    hostname = f"{service_name}.{DOMAIN}"

    try:
        answers = dns.resolver.resolve(hostname, "TXT")

        for answer in answers:
            raw_record = b"".join(answer.strings).decode("utf-8")
            metadata = json.loads(raw_record)

            return validate_metadata(metadata, service_name)

    except dns.resolver.NXDOMAIN:
        print(f"Service not found: {service_name}")
    except dns.resolver.NoAnswer:
        print(f"No TXT metadata found for: {service_name}")
    except dns.exception.DNSException as exc:
        print(f"DNS lookup failed: {exc}")
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        print(f"Invalid service metadata: {exc}")

    return None


if __name__ == "__main__":
    name = input("Enter service name (latency/traceroute/health): ").strip()
    result = discover_service(name)

    if result:
        print("\nDiscovered service metadata:")
        print(json.dumps(result, indent=4))
