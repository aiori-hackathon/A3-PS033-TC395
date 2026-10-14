
import json
from pathlib import Path

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519


BASE_DIR = Path(__file__).resolve().parent.parent
ZONE_DIR = BASE_DIR / "dns_zone"
ZONE_NAME = dns.name.from_text("diagnostics.test.")
TTL = 300


def test_tampered_txt_record_is_rejected():
    private_bytes = (ZONE_DIR / "dnssec_private_key.pem").read_bytes()
    public_bytes = (ZONE_DIR / "dnssec_public_key.pem").read_bytes()

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    public_key = private_key.public_key()
    dnskey = dns.dnssec.make_dnskey(public_key, algorithm="ED25519")

    with (ZONE_DIR / "service_records.json").open(
        "r", encoding="utf-8"
    ) as file:
        services = json.load(file)

    service_name = "latency"
    hostname = dns.name.from_text(f"{service_name}.{ZONE_NAME}")

    original = json.dumps(services[service_name], separators=(",", ":"))
    original_rdata = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        '"' + original.replace('"', '\\"') + '"',
    )
    original_rrset = dns.rrset.from_rdata(hostname, TTL, original_rdata)

    signature = dns.dnssec.sign(
        original_rrset,
        private_key,
        ZONE_NAME,
        dnskey,
        lifetime=86400,
    )
    signature_rrset = dns.rrset.from_rdata(hostname, TTL, signature)

    # Change the signed TXT data but keep the original signature.
    tampered_metadata = dict(services[service_name])
    tampered_metadata["url"] = "http://127.0.0.1:5001/attacker"
    tampered_text = json.dumps(tampered_metadata, separators=(",", ":"))

    tampered_rdata = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        '"' + tampered_text.replace('"', '\\"') + '"',
    )
    tampered_rrset = dns.rrset.from_rdata(hostname, TTL, tampered_rdata)

    trusted_keys = {
        ZONE_NAME: dns.rrset.from_rdata(ZONE_NAME, TTL, dnskey)
    }

    with pytest.raises(dns.dnssec.ValidationFailure):
        dns.dnssec.validate(
            tampered_rrset,
            signature_rrset,
            trusted_keys,
        )
