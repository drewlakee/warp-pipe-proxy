import contextlib
import io
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import admin
import configure
import test_configure


class AccessTests(unittest.TestCase):
    def setUp(self):
        fixture = test_configure.ConfigureTests()
        fixture.setUp()
        self.settings = fixture.settings
        self.old = fixture.credentials

    def test_device_migration_revoke_and_reissue(self):
        added = configure.prepare_credentials(self.old, 'device-add', 'phone')
        self.assertEqual(added['devices']['default'], self.old['uuid'])
        revoked = configure.prepare_credentials(added, 'device-revoke', 'default')
        self.assertEqual(revoked['devices']['phone'], added['devices']['phone'])
        with self.assertRaises(ValueError):
            configure.for_device(revoked, 'default')
        config = configure.render(self.settings, revoked)
        self.assertNotIn(self.old['uuid'], json.dumps(config))
        issued = configure.prepare_credentials(revoked, 'device-add', 'default')
        self.assertNotEqual(issued['devices']['default'], self.old['uuid'])
        self.assertEqual(issued['probe_uuid'], added['probe_uuid'])
        with self.assertRaises(ValueError):
            configure.prepare_credentials(issued, 'device-add', 'phone')

    def test_rotate_all_preserves_revocations(self):
        creds = configure.prepare_credentials(self.old, 'device-add', 'phone')
        creds = configure.prepare_credentials(creds, 'device-revoke', 'default')
        keys = 'PrivateKey: ' + 'd'*43 + '\nPublicKey: ' + 'e'*43
        with patch.object(configure.subprocess, 'check_output', return_value=keys):
            rotated = configure.prepare_credentials(creds, 'render-rotated', None)
        self.assertIsNone(rotated['devices']['default'])
        self.assertNotEqual(rotated['devices']['phone'], creds['devices']['phone'])
        self.assertNotEqual(rotated['probe_uuid'], creds['probe_uuid'])

    def test_exports_after_default_revocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            creds = configure.prepare_credentials(self.old, 'device-add', 'phone')
            creds = configure.prepare_credentials(creds, 'device-revoke', 'default')
            configure.write(root / 'settings.json', self.settings)
            configure.write(root / 'credentials.json', creds)
            out = root / 'stage'
            subprocess.run([sys.executable, 'configure.py', 'render', '--out', str(out),
                            '--root', tmp], cwd=Path(__file__).parent, check=True)
            self.assertFalse((out / 'clients.txt').exists())
            self.assertFalse((out / 'client-sing-box.json').exists())
            for command in ('device-list', 'client-config', 'client-profile'):
                args = [command] if command == 'device-list' else [command, '--device', 'phone']
                with patch.object(admin, 'ROOT', root), patch.object(sys, 'argv', ['admin', *args]), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(admin.main(), 0)
                result = output.getvalue()
                self.assertNotIn(creds['probe_uuid'], result)
                self.assertNotIn(creds['private_key'], result)
                if command == 'device-list':
                    self.assertEqual(result.splitlines(), ['default\trevoked', 'phone\tactive'])
                else:
                    self.assertIn(creds['devices']['phone'], result)

    def test_private_policy_and_subnet_exceptions(self):
        settings = dict(self.settings, allowed_private_subnets=['10.3.4.0/24', 'fd00:123::/64'])
        rules = configure.render(settings, self.old)['route']['rules']
        self.assertEqual([r['action'] for r in rules], ['reject', 'resolve', 'reject'])
        self.assertEqual(rules[-1]['inbound'], 'vless-reality')
        blocked = list(map(ipaddress.ip_network, rules[-1]['ip_cidr']))
        for address in ('127.0.0.1', '169.254.1.1', '10.3.5.1', '::1', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1'):
            self.assertTrue(any(ipaddress.ip_address(address) in net for net in blocked), address)
        for address in ('1.1.1.1', '10.3.4.2', '::ffff:10.3.4.2', 'fd00:123::1', '2606:4700:4700::1111'):
            self.assertFalse(any(ipaddress.ip_address(address) in net for net in blocked), address)
        for bad in ('10.0.0.0/8', ['0.0.0.0/0'], ['10.0.0.1/24']):
            with self.assertRaises(ValueError):
                configure.blocked_destinations(dict(self.settings, allowed_private_subnets=bad))
