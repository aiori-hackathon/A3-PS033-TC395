
import json
import socketserver
from pathlib import Path

import dns.zone
import dns.flags
import dns.message
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ZONE_FILE = PROJECT_ROOT / "dns_zone" / "diagnostics.test.zone"
ZONE_NAME = "diagnostics.test."
HOST = "127.0.0.1"
PORT = 5353


def load_records():
    zone = dns.zone.from_file(
        str(ZONE_FILE),
        origin=dns.name.from_text(ZONE_NAME),
        relativize=False,
    )
    return zone


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request

        try:
            query = dns.message.from_wire(packet)
            response = dns.message.make_response(query)
            response.flags |= dns.flags.AA

            if not query.question:
                response.set_rcode(dns.rcode.FORMERR)
            else:
                question = query.question[0]
                answer = self.server.zone.get_rrset(
                    question.name,
                    question.rdtype,
                )

                if answer is None:
                    response.set_rcode(dns.rcode.NXDOMAIN)
                else:
                    response.answer.append(answer)

                    if query.edns >= 0 and query.ednsflags & dns.flags.DO:
                        node = self.server.zone.get_node(question.name)
                        if node:
                            sigs = node.get_rdataset(
                                dns.rdataclass.IN,
                                dns.rdatatype.RRSIG,
                                covers=question.rdtype,
                            )
                            if sigs:
                                response.answer.append(
                                    dns.rrset.from_rdata_list(
                                        question.name,
                                        answer.ttl,
                                        list(sigs),
                                    )
                                )

            sock.sendto(response.to_wire(), self.client_address)

        except Exception as exc:
            print(f"Request error: {exc}")


class UDPServer(socketserver.UDPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    server = UDPServer((HOST, PORT), DNSHandler)
    server.zone = load_records()

    print(f"Test DNS server listening on {HOST}:{PORT}")
    print(f"Loaded zone: {ZONE_FILE}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping DNS test server.")
    finally:
        server.server_close()
