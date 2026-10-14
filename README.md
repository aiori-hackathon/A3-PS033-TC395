# DNS-Based Discovery of Diagnostic Services
## AIORI Hackathon 3 — PS-033 | Team Phoenix (TC395)

### 1. Project Overview
This project demonstrates DNS-based discovery of diagnostic services using DNS TXT metadata, DNSSEC signature validation, and a separate authorization token for protected service invocation.

The prototype runs locally and does not use an Internet-wide registry.

### 2. Diagnostic Services
- **Latency:** Returns simulated network latency.
- **Traceroute:** Returns three simulated network hops.
- **Health:** Reports service availability.

### 3. Architecture
1. A local DNS test server publishes service TXT records and their DNSSEC signatures.
2. The discovery client queries the DNS server for service metadata.
3. The client validates the TXT record signature against a DNSKEY loaded from the local zone file.
4. The client validates the metadata and checks the destination URL against an allowlist.
5. The client invokes the diagnostic endpoint.
6. Protected endpoints require a separate bearer token.

### 4. Technology Stack
- Python 3.12
- dnspython
- Flask
- Requests
- pytest

### 5. Project Structure
- `src/diagnostic_services.py` — Flask diagnostic API
- `src/discovery_client.py` — DNS discovery and signature validation
- `src/dns_test_server.py` — local DNS test server
- `src/invoke_discovered_service.py` — discovery and invocation integration
- `src/test_metadata.py` — metadata tests
- `src/test_metadata_validation.py` — metadata validation tests
- `src/test_dnssec_tampering.py` — DNSSEC tampering test
- `src/test_service_auth.py` — service authorization tests
- `dns_zone/diagnostics.test.zone` — local DNS test zone

### 6. Setup
Run PowerShell from the project directory:

```powershell
cd D:\projects\A3-PS033-TC395
.\.venv\Scripts\Activate.ps1
```

Install dependencies if needed:

```powershell
python -m pip install dnspython Flask requests pytest cryptography
```

### 7. Running the Prototype
Open separate terminals for the processes.

**Terminal 1 — DNS server**
```powershell
python .\src\dns_test_server.py
```

**Terminal 2 — diagnostic service**
```powershell
$env:SERVICE_TOKEN = "replace-with-a-local-demo-token"
python .\src\diagnostic_services.py
```

**Terminal 3 — invoke a discovered service**
```powershell
$env:SERVICE_TOKEN = "replace-with-a-local-demo-token"
python .\src\invoke_discovered_service.py
```

Choose `latency`, `traceroute`, or `health` when prompted.

### 8. Automated Tests
Run:

```powershell
python -m pytest .\src -v
```

The current suite has passed 19 tests. Run the command again before submission and record the final result.

### 9. Security Considerations and Limitations
- DNSSEC signatures provide integrity and origin authentication for signed DNS data when validated against a trusted key.
- This prototype loads the DNSKEY directly from the local zone file. It does **not** implement a complete DNSSEC chain of trust from the DNS root.
- A valid DNSSEC signature does not grant permission to invoke a diagnostic service.
- Protected diagnostic endpoints use a separate bearer token.
- The integration client restricts destinations to an explicit local URL allowlist.
- Diagnostic results are simulated and are not measurements of real network paths.
- The bearer token used for demonstration must not be committed to the repository or published in DNS metadata.
- The local test server and zone are intended for a controlled demonstration, not production deployment.

### 10. Future Improvements
- Full DNSSEC trust-chain validation and signed denial-of-existence support.
- Stronger credential management and service identity verification.
- Additional negative tests for malformed DNS records and unavailable diagnostic services.
- Deployment automation and a demonstration interface.

### 11. Team
**Team:** Phoenix  
**Team Code:** TC395  
**Problem Statement:** PS-033 — DNS-Based Discovery of Diagnostic Services

### 12. References
- RFC 4033 — DNS Security Introduction and Requirements
- RFC 4034 — Resource Records for the DNS Security Extensions
- RFC 4035 — Protocol Modifications for the DNS Security Extensions
- DNS-AID draft subset specified for the hackathon; document the exact draft version and pinned requirements used by the team.
