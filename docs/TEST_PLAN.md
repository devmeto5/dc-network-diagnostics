# Test plan

## Automated coverage

- Configuration: valid names/IPs, invalid endpoint formats, port/type validation, duplicates, bounded input, relative CA path, finite timeout and renewal threshold.
- Evaluation: certificate-expiry boundaries and aggregate status precedence.
- Failure handling: DNS failure and dependent checks, refused sockets closed, failed worker/malformed output, deadline reporting, endpoint isolation.
- TLS policy: hostname and chain verification remain enabled; minimum TLS version; no environment-triggered session-key logging.
- Integration: real ephemeral TCP loopback server; real verified TLS with a test trust bundle; rejection of an untrusted certificate; live CLI config path; subprocess demo entry point.
- Output: HTML escaping, parseable JSON, explicit demo mode with no live collection, preservation of existing files.

Run `python -m unittest discover -s tests -v`. CI runs on Ubuntu and Windows for Python 3.11, 3.12, and 3.13, installs the package, and verifies the installed CLI. Test servers bind only 127.0.0.1 using OS-assigned ports. Fixture credentials are intentionally public, isolated to tests, and never installed into a system trust store.

## Manual environment acceptance

On authorized lab endpoints, test the actual resolver, IPv4/IPv6 routing, firewall behavior, private CA bundle, and direct TLS service. Compare findings to independent system tools. Verify an intentionally invalid name, an approved closed port, and a certificate approaching renewal without changing production services. Measure wall time for an unreachable endpoint and confirm later targets are still assessed.

Inspect HTML in a browser and a narrow viewport. Review hostnames and ports before sharing reports. No external network probing is needed to run the automated suite.

## Acceptance record

Record actual executed checks in VALIDATION.md. Distinguish fixture tests, real loopback checks, and production/lab checks. A workflow file alone is not evidence of passing CI. Do not claim revocation, DNSSEC, application health, or physical-network validation from this test suite.
