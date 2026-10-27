# DC Network Diagnostics

Explicit-target DNS, TCP, and TLS diagnostics for Data Center Technicians and System Administrators.

Maintained by [devmeto5](https://github.com/devmeto5). Initial release: **0.1.0**. Companion project: [DC HealthCheck Pro](https://github.com/devmeto5/dc-healthcheck-pro).

## Features

- Resolve configured hostnames through the operating system resolver.
- Connect to one explicitly configured TCP port per endpoint and record connection timing.
- Verify direct TLS connections, certificate trust and hostname, then warn before certificate expiry.
- Generate terminal, JSON, and standalone HTML reports.
- Run synthetic demonstrations without network activity.
- Bound each endpoint using a disposable worker process, including blocking DNS resolution.

Python 3.11+; no third-party runtime dependencies. CI tests Python 3.11–3.13 on Linux and Windows. No root privileges, packet capture, subnet discovery, port ranges, or service changes.

## Quick start

```bash
git clone https://github.com/devmeto5/dc-network-diagnostics.git
cd dc-network-diagnostics
python -m dc_network --demo
python -m dc_network --demo --format html --output demo-report.html
```

The demo contains intentional warning and critical findings, so exit code **2 is expected**. Open the HTML file in a browser. [Example JSON](examples/demo-report.json) and [example HTML](examples/demo-report.html) contain only synthetic data.

Optional installation:

```bash
python -m venv .venv
# Linux: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
dc-network --version
```

## Live configuration

Create `targets.toml` for endpoints you operate or are authorized to diagnose:

```toml
timeout = 5
warning_days = 30

[[targets]]
host = "your-server.example.com"
port = 443
tls = true
```

Replace the example hostname before running:

```bash
python -m dc_network --config targets.toml --format json --output network-report.json
```

The supplied `config.example.toml` intentionally uses reserved `.invalid` names. It is a template, not a list of real public targets. Live mode requires an explicit config and opens network connections; demo mode never loads live targets. Existing reports are not overwritten, and output parent directories must already exist.

For a private PKI, set top-level `ca_file = "company-ca.pem"`. Relative paths resolve beside the configuration file. The bundle replaces the default trust roots for this run; it is never installed into a system store. TLS verification cannot be disabled. Direct TLS 1.2+ is supported; STARTTLS and client certificates are not implemented.

## Results

| Exit | Meaning |
|---|---|
| 0 | All checks OK |
| 1 | Warning with no critical or unknown finding |
| 2 | At least one critical finding |
| 3 | Unknown evidence without a known critical, or a configuration/output failure |

Priority is CRITICAL > UNKNOWN > WARNING > OK. A failed prerequisite leaves dependent checks UNKNOWN. A worker deadline loses partial evidence and returns UNKNOWN for that endpoint. Argument syntax errors use argparse's exit code 2 and produce no report.

DNS OK means the system resolver returned candidates; it does not validate authoritative records, propagation, DNSSEC, or every address. IP literals use the same resolver interface and do not imply a DNS query. TCP OK means at least one connection succeeded, not that all resolved addresses are healthy. TLS OK checks trust, hostname, validity, and remaining lifetime for the connected endpoint; it does not perform revocation checks, a cipher audit, or application requests. Timing includes failed address attempts, is not ICMP latency, and has no performance threshold in v0.1.0.

## Tests and project documents

```bash
python -m unittest discover -s tests -v
```

Tests include real TCP/TLS loopback servers and synthetic negative cases. They do not depend on public endpoints. The [test-only certificate and key](tests/fixtures/README.md) are intentionally public and must never be deployed.

- [Specification, architecture, and roadmap](docs/PROJECT_PLAN.md)
- [Testing plan](docs/TEST_PLAN.md)
- [Validation evidence](docs/VALIDATION.md)
- [Operator runbook](docs/RUNBOOK.md)
- [Contribution guide](CONTRIBUTING.md)

## Limits

At most 32 targets, each with one port; up to eight resolver candidates per endpoint, attempted sequentially. An unresponsive first address can consume the entire endpoint budget. Default timeout is 5 seconds plus 1 second of worker startup allowance. OS process creation/cleanup overhead can exceed that allowance; this is not a real-time deadline. Results are point-in-time observations from the client's network location. Reports expose configured hostnames and ports; use demo reports for portfolio sharing.

No open-source license has been selected. Public visibility alone does not grant a software license.
