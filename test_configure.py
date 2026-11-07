import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

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
                      {'socks_port':10443}, {'dns_port':-1}, {'socks_user':'a\nb'}]:
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
            self.assertEqual([i['type'] for i in config['inbounds']], ['socks', 'vless'])
            self.assertEqual(config['dns']['servers'][0]['server_port'], self.settings['dns_port'])
            links = (out/'clients.txt').read_text()
            self.assertIn(self.credentials['public_key'], links)
            self.assertNotIn(self.credentials['private_key'], links)
            self.assertIn(self.credentials['socks_password'], links)
            self.assertEqual((out/'clients.txt').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__': unittest.main()
