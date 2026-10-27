# Public test credentials — never deploy

The certificate and private key in this directory are intentionally public fixtures used only by ephemeral loopback TLS servers in automated tests. They are not production secrets. Never use this private key on a real service, and never install this certificate into a system trust store.

Tests pass the certificate explicitly to the diagnostic client as an isolated trust bundle. Its SANs are localhost and 127.0.0.1; validity is 2020-01-01 through 2040-01-01. Replace this fixture before 2040. No external servers are used by the tests. Runtime and tests require only Python's standard library; fixture generation does not run during installation or CI.
