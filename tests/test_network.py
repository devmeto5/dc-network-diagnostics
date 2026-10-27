import contextlib
import io
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from dc_network.cli import main
from dc_network.config import load, validate
from dc_network.probes import expiry_finding, probe, tls_context
from dc_network.reporting import finding, make_report, overall, render
from dc_network.runner import collect, run_target

FIXTURES = Path(__file__).parent / 'fixtures'
CERT = FIXTURES / 'localhost-cert.pem'
KEY = FIXTURES / 'localhost-test-key.pem'


@contextlib.contextmanager
def local_server(tls=False):
    """Serve one connection on an OS-assigned loopback port, then stop."""
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    server.settimeout(8)
    port = server.getsockname()[1]
    errors = []
    def accept():
        try:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                if tls:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(CERT, KEY)
                    try:
                        with context.wrap_socket(connection, server_side=True):
                            pass
                    except (ssl.SSLError, ConnectionAbortedError, ConnectionResetError):
                        # A diagnostic client closes immediately after verification.
                        # Windows can abort server-side TLS 1.3 session-ticket writes;
                        # certificate rejection also ends the server handshake early.
                        # The caller still asserts the client's exact TLS result.
                        pass
        except OSError as error:
            errors.append(error)
    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.close()
        thread.join(timeout=9)
        if thread.is_alive():
            raise AssertionError('Loopback server did not terminate')
        if errors:
            raise AssertionError(f'Loopback server failed: {errors}')


def configuration(port=443, tls=True, ca_file=None):
    data = {'targets': [{'host': '127.0.0.1', 'port': port, 'tls': tls}], 'timeout': 5}
    if ca_file:
        data['ca_file'] = str(ca_file.resolve())
    return validate(data)


class ConfigTests(unittest.TestCase):
    def test_valid_ipv4_ipv6_hostname(self):
        for host in ('127.0.0.1', '::1', 'server.example.com'):
            self.assertEqual(validate({'targets': [{'host': host, 'port': 443}]})['targets'][0]['host'], host)

    def test_invalid_targets(self):
        for host in ('https://example.com', '*.example.com', '10.0.0.0/24', 'a;echo x', '', '../etc'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                validate({'targets': [{'host': host, 'port': 443}]})

    def test_invalid_ports_and_types(self):
        for port in (0, 65536, True, '443', 4.5):
            with self.subTest(port=port), self.assertRaises(ValueError):
                validate({'targets': [{'host': 'localhost', 'port': port}]})

    def test_invalid_global_settings(self):
        for extra in ({'timeout': float('nan')}, {'timeout': 0}, {'timeout': True},
                      {'warning_days': 0}, {'warning_days': True}, {'surprise': 1}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                validate({'targets': [{'host': 'localhost', 'port': 443}], **extra})

    def test_duplicate_and_empty_targets(self):
        for targets in ([], [{'host': 'localhost', 'port': 443}] * 2):
            with self.assertRaises(ValueError):
                validate({'targets': targets})

    def test_relative_ca_bundle(self):
        config = validate({'ca_file': CERT.name, 'targets': [{'host': 'localhost', 'port': 443}]}, FIXTURES)
        self.assertEqual(config['ca_file'], str(CERT.resolve()))

    def test_config_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'large.toml'
            path.write_text(' ' * 65537)
            with self.assertRaises(ValueError):
                load(path)


class ProbeTests(unittest.TestCase):
    def test_expiry_boundaries(self):
        expires = 'Jan  1 00:00:00 2040 GMT'
        epoch = ssl.cert_time_to_seconds(expires)
        for days, status in ((31, 'OK'), (30, 'WARNING'), (1, 'WARNING'), (0, 'CRITICAL'), (-1, 'CRITICAL')):
            with self.subTest(days=days):
                self.assertEqual(expiry_finding(expires, 30, epoch - days * 86400)['status'], status)

    def test_context_keeps_verification_enabled(self):
        with patch.dict('os.environ', {'SSLKEYLOGFILE': 'must-not-create.log'}):
            context = tls_context(str(CERT))
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertIsNone(context.keylog_filename)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_dns_failure_skips_dependents(self):
        config = configuration()
        with patch('dc_network.probes.socket.getaddrinfo', side_effect=socket.gaierror), \
             patch('dc_network.probes.socket.socket') as create:
            result = probe(config['targets'][0], 5, 30)
        self.assertEqual([c['status'] for c in result['checks']], ['CRITICAL', 'UNKNOWN', 'UNKNOWN'])
        create.assert_not_called()

    def test_tcp_refusal_closes_socket(self):
        config = configuration()
        with patch('dc_network.probes.socket.getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 1))]), \
             patch('dc_network.probes.socket.socket') as create:
            create.return_value.connect.side_effect = ConnectionRefusedError()
            result = probe(config['targets'][0], 5, 30)
            create.return_value.close.assert_called_once()
        self.assertEqual([c['status'] for c in result['checks']], ['OK', 'CRITICAL', 'UNKNOWN'])

    def test_real_loopback_tcp(self):
        with local_server() as port:
            config = configuration(port, False)
            result = run_target(config['targets'][0], config)
        self.assertEqual([c['status'] for c in result['checks']], ['OK', 'OK'], result)

    def test_real_loopback_verified_tls(self):
        with local_server(tls=True) as port:
            config = configuration(port, True, CERT)
            result = run_target(config['targets'][0], config)
        self.assertEqual([c['status'] for c in result['checks']], ['OK', 'OK', 'OK'], result)

    def test_real_loopback_untrusted_certificate(self):
        with local_server(tls=True) as port:
            config = configuration(port, True)
            result = run_target(config['targets'][0], config)
        self.assertEqual([c['status'] for c in result['checks']], ['OK', 'OK', 'CRITICAL'], result)
        self.assertIn('verification failed', result['checks'][-1]['evidence'])

    def test_worker_timeout(self):
        config = configuration()
        with patch('dc_network.runner.subprocess.run', side_effect=subprocess.TimeoutExpired('worker', 6)) as run:
            result = run_target(config['targets'][0], config)
        self.assertTrue(all(c['status'] == 'UNKNOWN' for c in result['checks']))
        self.assertEqual(run.call_args.kwargs['timeout'], 6)
        self.assertNotIn('shell', run.call_args.kwargs)

    def test_broken_worker_response(self):
        config = configuration()
        for code, output in ((1, ''), (0, 'not json'), (0, '{}')):
            with patch('dc_network.runner.subprocess.run', return_value=subprocess.CompletedProcess([], code, output)):
                self.assertTrue(all(c['status'] == 'UNKNOWN' for c in run_target(config['targets'][0], config)['checks']))

    def test_one_endpoint_failure_does_not_stop_next(self):
        config = configuration()
        config['targets'].append({'host': 'localhost', 'port': 22, 'tls': False})
        with patch('dc_network.runner.run_target', side_effect=[{'checks': []}, {'checks': []}]) as run:
            self.assertEqual(len(collect(config)), 2)
            self.assertEqual(run.call_count, 2)


class ReportingAndCliTests(unittest.TestCase):
    def test_status_precedence(self):
        checks = [finding('a', 'WARNING', ''), finding('b', 'UNKNOWN', '')]
        self.assertEqual(overall(checks), 'UNKNOWN')
        self.assertEqual(overall(checks + [finding('c', 'CRITICAL', '')]), 'CRITICAL')
        self.assertEqual(overall([]), 'UNKNOWN')

    def test_html_escapes_all_evidence(self):
        data = make_report([{'host': '<script>x</script>', 'port': 443,
                             'checks': [finding('tls', 'UNKNOWN', '<img src=x>')]}], 'DEMO')
        html = render(data, 'html')
        self.assertNotIn('<script>', html)
        self.assertNotIn('<img', html)
        self.assertIn('&lt;script&gt;', html)

    def test_demo_has_no_live_collection(self):
        with patch('dc_network.cli.collect', side_effect=AssertionError('Network forbidden')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['--demo', '--format', 'json']), 2)
        self.assertEqual(json.loads(output.getvalue())['mode'], 'DEMO')

    def test_cli_requires_explicit_mode(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            main([])
        self.assertEqual(error.exception.code, 2)

    def test_report_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.html'
            self.assertEqual(main(['--demo', '--format', 'html', '--output', str(path)]), 2)
            original = path.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['--demo', '--output', str(path)]), 3)
            self.assertEqual(path.read_bytes(), original)

    def test_cli_live_loopback_configuration(self):
        with local_server() as port, tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.toml'
            path.write_text(f'[[targets]]\nhost="127.0.0.1"\nport={port}\ntls=false\n')
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(['--config', str(path), '--format', 'json']), 0)
            self.assertEqual(json.loads(output.getvalue())['mode'], 'LIVE')

    def test_module_entry_point(self):
        result = subprocess.run([sys.executable, '-m', 'dc_network', '--demo', '--format', 'json'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['schema_version'], '1.0')


if __name__ == '__main__':
    unittest.main()
