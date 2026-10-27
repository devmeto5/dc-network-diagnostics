# Validation record

Date: 2026-10-27. Local environment: Windows, Python 3.12.14.

| Check | Result |
|---|---|
| Local automated suite | 24 tests passed |
| Real loopback TCP | Passed |
| Real loopback TLS with isolated trusted fixture | Passed |
| Rejection of untrusted loopback certificate | Passed |
| GitHub Linux/Windows matrix | All 6 jobs passed: Ubuntu and Windows, Python 3.11, 3.12, 3.13 |
| Wheel build, isolated installation, installed CLI | Passed |
| Demo JSON and HTML generation | Passed; diagnostic exit 2 expected |
| Production or physical network validation | Not performed |
| Manual HTML visual inspection | Not performed |

No public endpoints are used by the tests. The test certificate and key are intentionally public loopback fixtures, not production credentials.

Verified code and tests: commit `795af9b24c617c691dda3dab6e4ff7ec155e31fd`.
CI evidence: [successful run 40521705486](https://github.com/devmeto5/dc-network-diagnostics/actions/runs/40521705486). All six jobs passed package installation, 24 tests including real loopback TCP/TLS, and the installed command check.

The first CI run identified a Windows Python 3.11 test-server disconnect error. The fixture now tolerates connection abort/reset during TLS completion, while assertions still require the client's exact verified or rejected TLS result. The complete matrix passed after this fix. The subsequent documentation-only validation commit does not change tested code.
