# Validation record

Date: 2026-10-27. Local environment: Windows, Python 3.12.14.

| Check | Result |
|---|---|
| Local automated suite | 24 tests passed |
| Real loopback TCP | Passed |
| Real loopback TLS with isolated trusted fixture | Passed |
| Rejection of untrusted loopback certificate | Passed |
| GitHub Linux/Windows matrix | Pending upload and execution |
| Wheel build, isolated installation, installed CLI | Passed |
| Demo JSON and HTML generation | Passed; diagnostic exit 2 expected |
| Production or physical network validation | Not performed |
| Manual HTML visual inspection | Not performed |

No public endpoints are used by the tests. The test certificate and key are intentionally public loopback fixtures, not production credentials. CI evidence will be added after its jobs finish.
