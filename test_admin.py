import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import admin
import test_configure


class AdminTests(unittest.TestCase):
    def test_rejects_incompatible_options_and_bad_urls(self):
        for args in [('install', '--url', 'https://example.com'), ('logs', '--endpoint', '127.0.0.1'),
                     ('doctor', '--url', 'file:///etc/passwd'), ('doctor', '--url', 'https://user:pass@example.com'),
                     ('client-profile', '--port', '0'), ('client-profile', '--endpoint', 'bad host')]:
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                admin.parse_args(args)

    def test_export_overrides_only_client_endpoint(self):
        fixture = test_configure.ConfigureTests()
        fixture.setUp()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'settings.json').write_text(json.dumps(fixture.settings))
            (root / 'credentials.json').write_text(json.dumps(fixture.credentials))
            before = (root / 'settings.json').read_bytes()
            output = io.StringIO()
            with patch.object(admin, 'ROOT', root), patch('sys.argv', ['admin.py', 'client-profile', '--endpoint', '192.168.1.5', '--port', '443']), contextlib.redirect_stdout(output):
                self.assertEqual(admin.main(), 0)
            profile = json.loads(output.getvalue())
            outbound = profile['outbounds'][0]
            self.assertEqual(outbound['server'], '192.168.1.5')
            self.assertEqual(outbound['server_port'], 443)
            self.assertEqual(outbound['uuid'], fixture.credentials['uuid'])
            self.assertEqual(outbound['tls']['server_name'], fixture.settings['reality_host'])
            self.assertNotIn('private_key', output.getvalue())
            self.assertEqual(before, (root / 'settings.json').read_bytes())

    def test_qr_uses_current_credentials_and_stdin_without_mutating_settings(self):
        fixture = test_configure.ConfigureTests()
        fixture.setUp()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in [('settings', fixture.settings), ('credentials', fixture.credentials)]:
                (root / (name + '.json')).write_text(json.dumps(value))
            original = (root / 'settings.json').read_bytes()
            with patch.object(admin, 'ROOT', root), patch('sys.argv', [
                    'admin.py', 'client-qr', '--endpoint', '2001:db8::1', '--port', '443']), patch.object(
                    admin.shutil, 'which', return_value='/usr/bin/qrencode'), patch.object(
                    admin.subprocess, 'run') as run, contextlib.redirect_stderr(io.StringIO()):
                run.return_value.returncode = 0
                self.assertEqual(admin.main(), 0)
            link = run.call_args.kwargs['input']
            self.assertIn('@[2001:db8::1]:443?', link)
            self.assertIn(fixture.credentials['uuid'], link)
            self.assertIn('pbk=' + fixture.credentials['public_key'], link)
            self.assertNotIn(fixture.credentials['private_key'], link)
            self.assertEqual(run.call_args.args[0], ['qrencode', '-t', 'ANSIUTF8', '-m', '2'])
            self.assertEqual((root / 'settings.json').read_bytes(), original)

    def test_doctor_does_not_hide_vless_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'settings.json').write_text('{"dns_port":5353}')
            response = type('Result', (), {'returncode': 0, 'stdout': 'status: NOERROR\nexample.com. 60 IN A 1.2.3.4'})()
            with patch.object(admin, 'ROOT', root), patch.object(admin, 'status', return_value=True), patch.object(admin, 'run_check', return_value=True), patch.object(admin.subprocess, 'run', return_value=response), patch.object(admin.probe, 'probe', side_effect=RuntimeError('failed')), contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(admin.doctor(admin.parse_args(['doctor'])))

    def test_doctor_rejects_dns_servfail_with_zero_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'settings.json').write_text('{"dns_port":5353}')
            response = type('Result', (), {'returncode': 0, 'stdout': 'status: SERVFAIL'})()
            with patch.object(admin, 'ROOT', root), patch.object(admin, 'status', return_value=True), patch.object(admin, 'run_check', return_value=True), patch.object(admin.subprocess, 'run', return_value=response), patch.object(admin.probe, 'probe'), contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(admin.doctor(admin.parse_args(['doctor'])))


if __name__ == '__main__':
    unittest.main()
