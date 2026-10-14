
import copy

import dns.dnssec
import dns.message
import dns.query
import dns.rdatatype
import dns.zone

ZONE_NAME = "diagnostics.test."
ZONE_PATH = "dns_zone/diagnostics.test.zone"

zone = dns.zone.from_file(
    ZONE_PATH,
    origin=ZONE_NAME,
    relativize=False,
)

origin = dns.name.from_text(ZONE_NAME)
dnskey = zone.get_rdataset(origin, dns.rdatatype.DNSKEY)
keys = {origin: dnskey}

query = dns.message.make_query(
    "latency.diagnostics.test.",
    dns.rdatatype.TXT,
    want_dnssec=True,
)

response = dns.query.udp(
    query, "127.0.0.1", port=5353, timeout=3
)

original_txt = next(
    rrset for rrset in response.answer
    if rrset.rdtype == dns.rdatatype.TXT
)
signature = next(
    rrset for rrset in response.answer
    if rrset.rdtype == dns.rdatatype.RRSIG
)

tampered_txt = copy.deepcopy(original_txt)
tampered_txt.clear()
tampered_txt.add(
    dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        '"{\"service\":\"latency\",\"url\":\"http://attacker.invalid/\"}"',
    ),
)

try:
    dns.dnssec.validate(tampered_txt, signature, keys)
except dns.dnssec.ValidationFailure:
    print("PASS: altered DNS metadata was rejected")
else:
    raise AssertionError(
        "FAIL: altered metadata unexpectedly passed validation"
    )
