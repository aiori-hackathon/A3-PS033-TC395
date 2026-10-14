
import json
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
    ZONE_DIR.mkdir(parents=True, exist_ok=True)

    private_bytes = (ZONE_DIR / "dnssec_private_key.pem").read_bytes()
    public_bytes = (ZONE_DIR / "dnssec_public_key.pem").read_bytes()

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    public_key = private_key.public_key()

    if public_key.public_bytes_raw() != public_bytes:
        raise ValueError("Public and private keys do not match")

    dnskey = dns.dnssec.make_dnskey(
        public_key,
        algorithm="ED25519",
        flags=257,
    )

    with (ZONE_DIR / "service_records.json").open(
        "r", encoding="utf-8"
    ) as file:
        services = json.load(file)

    records = []

    def add_signed_record(owner, rdtype, rdata):
        rrset = dns.rrset.from_rdata(owner, TTL, rdata)
        signature = dns.dnssec.sign(
            rrset,
            private_key,
            ZONE_NAME,
            dnskey,
            lifetime=86400,
        )
        records.append(rrset.to_text(origin=ZONE_NAME))
        records.append(
            dns.rrset.from_rdata(owner, TTL, signature).to_text(
                origin=ZONE_NAME
            )
        )

    records.extend([
        f"$ORIGIN {ZONE_NAME}",
        f"$TTL {TTL}",
        "@ IN SOA ns.diagnostics.test. hostmaster.diagnostics.test. "
        "(2026101302 3600 900 604800 300)",
        "@ IN NS ns.diagnostics.test.",
        "ns IN A 127.0.0.1",
        f"@ IN DNSKEY {dnskey.to_text()}",
    ])

    for service_name, metadata in services.items():
        owner = dns.name.from_text(f"{service_name}.{ZONE_NAME}")
        txt_value = json.dumps(metadata, separators=(",", ":"))
        txt_rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.TXT,
            json.dumps(txt_value),
        )
        add_signed_record(owner, dns.rdatatype.TXT, txt_rdata)

    zone_file = ZONE_DIR / "diagnostics.test.zone"
    zone_file.write_text("\n".join(records) + "\n", encoding="utf-8")

    print("Zone file regenerated.")
    print(f"Location: {zone_file}")
    print(f"DNSKEY key tag: {dns.dnssec.key_id(dnskey)}")
    print("The zone still needs a DNS server and trust-chain testing.")


if __name__ == "__main__":
    main()
