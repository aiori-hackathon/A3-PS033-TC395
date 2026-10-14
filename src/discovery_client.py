
import json
from pathlib import Path

import dns.dnssec
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.zone


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ZONE_PATH = PROJECT_ROOT / "dns_zone" / "diagnostics.test.zone"

DOMAIN = "diagnostics.test."
DNS_SERVER = "127.0.0.1"
DNS_PORT = 5353

ALLOWED_SERVICES = {"latency", "traceroute", "health"}


def validate_metadata(metadata, service_name):
    if not isinstance(metadata, dict):
        raise ValueError("Metadata must be a JSON object")

    if service_name not in ALLOWED_SERVICES:
        raise ValueError("Unsupported service name")

    if not {"service", "url"}.issubset(metadata):
        raise ValueError("Metadata is missing required fields")

    if metadata["service"] != service_name:
        raise ValueError("Service name does not match DNS record")

    url = metadata["url"]
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")

    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must use HTTP or HTTPS")

    return metadata


def load_dnskeys():
    zone = dns.zone.from_file(
        str(ZONE_PATH),
        origin=dns.name.from_text(DOMAIN),
        relativize=False,
    )

    origin = dns.name.from_text(DOMAIN)
    dnskeys = zone.get_rdataset(origin, dns.rdatatype.DNSKEY)

    if dnskeys is None:
        raise RuntimeError("DNSKEY record is missing")

    return {origin: dnskeys}


def discover_service(service_name):
    if service_name not in ALLOWED_SERVICES:
        print(f"Unsupported service: {service_name}")
        return None

    hostname = f"{service_name}.{DOMAIN}"

    try:
        query = dns.message.make_query(
            hostname,
            dns.rdatatype.TXT,
            want_dnssec=True,
        )

        response = dns.query.udp(
            query,
            DNS_SERVER,
            port=DNS_PORT,
            timeout=3,
        )

        if response.rcode() != dns.rcode.NOERROR:
            print(f"DNS lookup failed: {dns.rcode.to_text(response.rcode())}")
            return None

        txt_record = next(
            (
                rrset for rrset in response.answer
                if rrset.rdtype == dns.rdatatype.TXT
            ),
            None,
        )

        signature = next(
    (
        rrset
        for rrset in response.answer
        if rrset.rdtype == dns.rdatatype.RRSIG
        and rrset.covers == dns.rdatatype.TXT
    ),
    None,
)

        if txt_record is None or signature is None:
            print("DNSSEC validation failed: TXT or RRSIG missing")
            return None

        dns.dnssec.validate(
            txt_record,
            signature,
            load_dnskeys(),
        )

        raw_record = b"".join(
            next(iter(txt_record)).strings
        ).decode("utf-8")

        metadata = json.loads(raw_record)
        return validate_metadata(metadata, service_name)

    except (
        dns.exception.DNSException,
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError,
        OSError,
        RuntimeError,
    ) as exc:
        print(f"Discovery failed: {exc}")
        return None


if __name__ == "__main__":
    name = input(
        "Enter service name (latency/traceroute/health): "
    ).strip()

    result = discover_service(name)

    if result:
        print("\nDiscovered and signature-validated metadata:")
        print(json.dumps(result, indent=4))
