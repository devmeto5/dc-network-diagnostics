# Operator runbook

1. Confirm authorization for the specific host/port pairs. Begin with `--demo` to inspect report format.
2. Create a small target configuration. Enable tls only for direct TLS endpoints; SMTP STARTTLS is not supported.
3. If needed, select an approved CA bundle. Do not disable verification or install test fixtures into a trust store.
4. Run once and inspect each stage. DNS failure points to target naming/resolver issues; TCP failure suggests listener/routing/firewall checks; TLS failure suggests certificate, hostname, chain, or protocol investigation.
5. Treat UNKNOWN as missing evidence, not success. A worker deadline cannot reliably identify whether DNS, transport, or TLS stalled.
6. Confirm findings using service logs and existing monitoring. Obtain ordinary operational authorization before remediation; this tool makes no infrastructure changes.
7. Share only sanitized reports. Portfolio examples should use `--demo`.

Typical commands:

```bash
python -m dc_network --demo
python -m dc_network --config targets.toml
python -m dc_network --config targets.toml --format html --output assessment.html
```

Connections may appear in endpoint logs. A TCP or TLS handshake is an active check even though it sends no application request. Resolver behavior may include hosts-file entries and local caches. Results represent the client location and the first successful address, not all load-balancer backends.
