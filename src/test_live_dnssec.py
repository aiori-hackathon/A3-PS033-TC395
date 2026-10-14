
import dns.dnssec
import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.zone

ZONE_NAME = "diagnostics.test."
ZONE_PATH = "dns_zone/diagnostics.test.zone"
DNS_SERVER = "127.0.0.1"
DNS_PORT = 5353

zone = dns.zone.from_file(
    ZONE_PATH,
    origin=ZONE_NAME,
    relativize=False,
)

origin = dns.name.from_text(ZONE_NAME)
dnskey = zone.get_rdataset(origin, dns.rdatatype.DNSKEY)

if dnskey is None:
    raise RuntimeError("DNSKEY record not found in zone")

keys = {origin: dnskey}

for service in ["latency", "traceroute", "health"]:
    name = dns.name.from_text(
        f"{service}.{ZONE_NAME}"
    )

    query = dns.message.make_query(
        name,
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
        print(f"FAIL: {service}: DNS error")
        continue

    txt = next(
        (
            rrset for rrset in response.answer
            if rrset.rdtype == dns.rdatatype.TXT
        ),
        None,
    )

    sig = next(
        (
            rrset for rrset in response.answer
            if rrset.rdtype == dns.rdatatype.RRSIG
        ),
        None,
    )

    if txt is None or sig is None:
        print(f"FAIL: {service}: TXT or RRSIG missing")
        continue

    try:
        dns.dnssec.validate(txt, sig, keys)
        print(f"PASS: {service}: live DNS signature validated")
    except Exception as exc:
        print(f"FAIL: {service}: {type(exc).__name__}: {exc}")
