
from pathlib import Path
import json

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ed25519


BASE_DIR = Path(__file__).resolve().parent.parent
ZONE_DIR = BASE_DIR / "dns_zone"
ZONE_NAME = dns.name.from_text("diagnostics.test.")

SERVICES = {
    "latency": {
        "service": "latency",
        "url": "http://127.0.0.1:5001/latency",
        "description": "Simulated network latency diagnostic",
    },
    "traceroute": {
        "service": "traceroute",
        "url": "http://127.0.0.1:5001/traceroute",
        "description": "Simulated traceroute diagnostic",
    },
    "health": {
        "service": "health",
        "url": "http://127.0.0.1:5001/health",
        "description": "Simulated service health check",
    },
}


def main():
    ZONE_DIR.mkdir(parents=True, exist_ok=True)

    # Generate an Ed25519 private key for this local prototype.
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    (ZONE_DIR / "dnssec_private_key.pem").write_bytes(
        private_key.private_bytes_raw()
    )
    (ZONE_DIR / "dnssec_public_key.pem").write_bytes(
        public_key.public_bytes_raw()
    )

    metadata_path = ZONE_DIR / "service_records.json"
    metadata_path.write_text(
        json.dumps(SERVICES, indent=2),
        encoding="utf-8",
    )

    print("DNSSEC test-zone inputs created.")
    print(f"Zone: {ZONE_NAME}")
    print(f"Metadata: {metadata_path}")
    print("Key pair saved in dns_zone/.")
    print(
        "Next: build DNSKEY/RRSIG records and verify signatures "
        "using dnspython."
    )


if __name__ == "__main__":
    main()
