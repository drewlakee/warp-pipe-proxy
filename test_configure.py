import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('configure', BASE / 'configure.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ConfigureTests(unittest.TestCase):
    def setUp(self):
        self.settings = {'public_ip': '8.8.8.8', 'reality_host': 'www.example.com',
                         'socks_port': 1081, 'vless_port': 10443, 'dns_port': 5353, 'socks_user': 'telegram'}
        self.credentials = {'uuid': '96051898-0bda-4891-9358-f1ef308dffab', 'socks_password': 'a'*64,
                            'short_id': 'a'*8, 'private_key': 'b'*43, 'public_key': 'c'*43}

    def test_existing_credentials_are_not_regenerated(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name, value in [('settings', self.settings), ('credentials', self.credentials)]:
                module.write(root / (name + '.json'), value)
            before = (root / 'credentials.json').read_bytes()
            subprocess.run(['python3', str(BASE/'configure.py'), 'init', '--root', d], check=True)
            self.assertEqual(before, (root / 'credentials.json').read_bytes())
            self.assertEqual((root/'credentials.json').stat().st_mode & 0o777, 0o600)

    def test_vless_only_settings_are_valid(self):
        settings = {k: v for k, v in self.settings.items() if not k.startswith('socks_')}
        credentials = {k: v for k, v in self.credentials.items() if k != 'socks_password'}
        module.validate(settings, credentials)
        self.assertEqual([i['type'] for i in module.render(settings, credentials)['inbounds']], ['vless'])

    def test_firewall_cleanup_preserves_unrelated_rules(self):
        rules = """Added user rules (see 'ufw status' for running firewall):
ufw allow 1081/tcp comment 'warp-pipe-proxy SOCKS'
ufw allow 2048/tcp comment 'warp-pipe-proxy SOCKS'
ufw allow 1081/tcp comment 'other service'
ufw allow 10443/tcp comment 'warp-pipe-proxy Reality'
"""
        with patch.object(module.subprocess, 'check_output', return_value=rules), patch.object(module.subprocess, 'run') as run:
            module.remove_legacy_socks_rules()
            self.assertEqual([call.args[0] for call in run.call_args_list], [
                ['ufw', '--force', 'delete', 'allow', port, 'comment', 'warp-pipe-proxy SOCKS']
                for port in ('1081/tcp', '2048/tcp')])

    def test_missing_installed_credentials_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            module.write(root/'settings.json', self.settings)
            (root/'installed').touch()
            r = subprocess.run(['python3', str(BASE/'configure.py'), 'init', '--root', d], capture_output=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse((root/'credentials.json').exists())

    def test_invalid_settings(self):
        for patch in [{'public_ip':'127.0.0.1'}, {'reality_host':'x;touch /tmp/oops'},
                      {'dns_port':10443}, {'dns_port':-1}]:
            with self.subTest(patch=patch):
                s = dict(self.settings, **patch)
                with self.assertRaises(ValueError): module.validate(s, self.credentials)

    def test_client_profile_allows_both_ip_versions_without_private_key(self):
        config = module.render_client(self.settings, self.credentials)
        self.assertNotIn('strategy', config['dns'])
        self.assertFalse(config['dns'].get('rules'))
        self.assertFalse(any(rule.get('ip_version') == 6 and rule.get('action') == 'reject'
                             for rule in config['route']['rules']))
        self.assertEqual(len(config['inbounds'][0]['address']), 2)
        self.assertEqual(config['outbounds'][0]['uuid'], self.credentials['uuid'])
        self.assertEqual(config['outbounds'][0]['server'], self.settings['public_ip'])
        self.assertNotIn('private_key', json.dumps(config))
        self.assertNotIn('socks_password', json.dumps(config))

    def test_config_and_links_agree(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            module.write(root/'settings.json', self.settings)
            module.write(root/'credentials.json', self.credentials)
            out = root/'stage'
            subprocess.run(['python3', str(BASE/'configure.py'), 'render', '--root', d, '--out', str(out)], check=True)
            self.assertEqual((out/'client-sing-box.json').stat().st_mode & 0o777, 0o600)
            config = json.loads((out/'config.json').read_text())
            self.assertEqual([i['type'] for i in config['inbounds']], ['vless'])
            self.assertEqual(config['dns']['servers'][0]['server_port'], self.settings['dns_port'])
            links = (out/'clients.txt').read_text()
            self.assertIn(self.credentials['public_key'], links)
            self.assertNotIn(self.credentials['private_key'], links)
            self.assertNotIn(self.credentials['socks_password'], links)
            self.assertNotIn('t.me/socks', links)
            migrated_settings = json.loads((out/'settings.json').read_text())
            migrated_credentials = json.loads((out/'credentials.json').read_text())
            self.assertNotIn('socks_port', migrated_settings)
            self.assertNotIn('socks_user', migrated_settings)
            self.assertEqual(migrated_credentials, {k: v for k, v in self.credentials.items() if k != 'socks_password'})
            self.assertEqual(json.loads((root/'credentials.json').read_text()), self.credentials)
            self.assertEqual((out/'clients.txt').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__': unittest.main()
