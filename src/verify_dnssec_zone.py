
import json
import time
from pathlib import Path

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
TTL = 300


def main():
    private_bytes = (ZONE_DIR / "dnssec_private_key.pem").read_bytes()
    public_bytes = (ZONE_DIR / "dnssec_public_key.pem").read_bytes()

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    public_key = private_key.public_key()

    if public_key.public_bytes_raw() != public_bytes:
        raise ValueError("Key pair mismatch")

    dnskey = dns.dnssec.make_dnskey(public_key, algorithm="ED25519")
    keys = {ZONE_NAME: dns.rrset.from_rdata(ZONE_NAME, TTL, dnskey)}

    services = json.loads(
        (ZONE_DIR / "service_records.json").read_text(encoding="utf-8")
    )

    verified = 0

    for service_name, metadata in services.items():
        hostname = dns.name.from_text(f"{service_name}.{ZONE_NAME}")

        txt_value = json.dumps(metadata, separators=(",", ":"))
        txt_rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.TXT,
            '"' + txt_value.replace('"', '\\"') + '"',
        )

        rrset = dns.rrset.from_rdata(hostname, TTL, txt_rdata)

        signature = dns.dnssec.sign(
            rrset,
            private_key,
            ZONE_NAME,
            dnskey,
            lifetime=86400,
        )

        rrsig_rrset = dns.rrset.from_rdata(hostname, TTL, signature)

        dns.dnssec.validate(
            rrset,
            rrsig_rrset,
            keys,
            now=time.time(),
        )

        print(f"PASS: {service_name} signature verified")
        verified += 1

    print(f"\n{verified}/{len(services)} service signatures verified.")


if __name__ == "__main__":
    main()
