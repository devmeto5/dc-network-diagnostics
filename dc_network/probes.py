"""Single endpoint probe, run in a subprocess by the orchestrator."""

import socket
import ssl
import time

from .reporting import finding


def expiry_finding(not_after, warning_days, now=None):
    days = (ssl.cert_time_to_seconds(not_after) - (time.time() if now is None else now)) / 86400
    status = "CRITICAL" if days <= 0 else "WARNING" if days <= warning_days else "OK"
    return finding("tls", status, f"Verified certificate; {days:.2f} days until expiry",
                   "Renew the certificate and verify deployment." if status != "OK" else "No action required.")


def tls_context(ca_file):
    # Explicit context avoids SSLKEYLOGFILE-triggered key logging.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_file:
        context.load_verify_locations(cafile=ca_file)
    else:
        context.load_default_certs()
    return context


def probe(target, timeout, warning_days, ca_file=None):
    host, port = target["host"], target["port"]
    checks = []
    result = {"host": host, "port": port, "checks": checks}
    deadline = time.monotonic() + timeout

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("Endpoint deadline exhausted")
        return seconds

    def skip_dependencies(names):
        for name in names:
            checks.append(finding(name, "UNKNOWN", "Not attempted: prerequisite failed",
                                  "Resolve the preceding failure and run again."))

    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        # Deduplicate and cap attempts; this is not a subnet or port scanner.
        unique = list(dict.fromkeys(addresses))[:8]
        if not unique:
            raise socket.gaierror("No addresses")
        checks.append(finding("dns", "OK", f"Resolver returned {len(unique)} candidate address(es), capped at 8"))
    except socket.gaierror:
        checks.append(finding("dns", "CRITICAL", "System resolver could not resolve the target",
                              "Verify target spelling, resolver configuration, and DNS availability."))
        skip_dependencies(["tcp"] + (["tls"] if target["tls"] else []))
        return result
    except OSError:
        checks.append(finding("dns", "UNKNOWN", "Resolver unavailable", "Inspect the local resolver."))
        skip_dependencies(["tcp"] + (["tls"] if target["tls"] else []))
        return result

    connected = None
    started = time.monotonic()
    for family, kind, protocol, _, address in unique:
        candidate = None
        try:
            candidate = socket.socket(family, kind, protocol)
            candidate.settimeout(remaining())
            candidate.connect(address)
            connected = candidate
            break
        except OSError:
            if candidate is not None:
                candidate.close()
    if connected is None:
        checks.append(finding("tcp", "CRITICAL", "No TCP connection established within the endpoint budget",
                              "Check listener, routing, firewall policy, and address-family reachability."))
        skip_dependencies(["tls"] if target["tls"] else [])
        return result
    elapsed = (time.monotonic() - started) * 1000
    checks.append(finding("tcp", "OK", f"TCP connection established in {elapsed:.2f} ms (including retries)"))
    with connected:
        if target["tls"]:
            try:
                context = tls_context(ca_file)
                connected.settimeout(remaining())
                with context.wrap_socket(connected, server_hostname=host) as secure:
                    certificate = secure.getpeercert()
                    check = expiry_finding(certificate["notAfter"], warning_days)
                    check["evidence"] += f"; negotiated {secure.version()}"
                    checks.append(check)
            except ssl.SSLCertVerificationError:
                checks.append(finding("tls", "CRITICAL", "Certificate chain, hostname, or validity verification failed",
                                      "Check hostname, certificate validity, intermediate chain, and trusted CA."))
            except (ssl.SSLError, TimeoutError):
                checks.append(finding("tls", "CRITICAL", "TLS handshake failed or timed out",
                                      "Verify this is a direct TLS endpoint supporting TLS 1.2 or newer."))
            except (OSError, KeyError, ValueError):
                checks.append(finding("tls", "UNKNOWN", "TLS evidence or local trust configuration unavailable",
                                      "Inspect the CA bundle and endpoint certificate data."))
    return result
