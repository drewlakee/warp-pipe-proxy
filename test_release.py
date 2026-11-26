import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release


class FakePackages:
    """Only known read-only commands are accepted; no real package tools run."""
    def __init__(self, versions):
        self.versions = dict(versions)
        self.status = {}
        self.architecture = 'amd64'
        self.owner = 'sing-box: /usr/bin/sing-box\n'
        self.runtime = 'sing-box version 1.14.4\nEnvironment: test\n'
        self.calls = []
        self.failures = {}

    def __call__(self, arguments, **kwargs):
        self.calls.append(arguments)
        key = tuple(arguments)
        if key in self.failures:
            return subprocess.CompletedProcess(arguments, self.failures[key], '', 'simulated error')
        if arguments == ['dpkg', '--print-architecture']:
            return subprocess.CompletedProcess(arguments, 0, self.architecture + '\n')
        if arguments[:2] == ['dpkg-query', '--show']:
            name = arguments[-1]
            if name not in self.versions:
                return subprocess.CompletedProcess(arguments, 1, '', 'no packages found')
            output = f'{self.status.get(name, "installed")}\t{self.versions[name]}\n'
            return subprocess.CompletedProcess(arguments, 0, output)
        if arguments == ['dpkg-query', '--search', '/usr/bin/sing-box']:
            return subprocess.CompletedProcess(arguments, 0, self.owner)
        if arguments[:2] == ['dpkg', '--compare-versions']:
            _, _, actual, operator, expected = arguments
            ranks = {'0.9-1': 0, '1.0-1': 1, '1.1-1': 2}
            left, right = ranks[actual], ranks[expected]
            result = left < right if operator == 'lt' else left > right
            return subprocess.CompletedProcess(arguments, 0 if result else 1, '')
        if arguments[0].endswith('/usr/bin/sing-box') and arguments[1:] == ['version']:
            return subprocess.CompletedProcess(arguments, 0, self.runtime)
        raise AssertionError(f'Unexpected command, possibly a mutation: {arguments}')


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.project = self.base / 'project'
        self.project.mkdir()
        self.system = self.base / 'system'
        (self.system / 'etc').mkdir(parents=True)
        (self.system / 'etc/os-release').write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        (self.project / 'VERSION').write_text('0.1.0\n')
        self.metadata = {
            'schema': 1, 'release': '0.1.0',
            'os': {'id': 'ubuntu', 'version_id': '24.04'}, 'architectures': ['amd64'],
            'packages': {
                'common': {name: '1.0-1' for name in ('curl', 'ca-certificates', 'openssl', 'python3',
                            'dnsutils', 'iproute2', 'unbound', 'dns-root-data', 'qrencode')},
                'host': {'ufw': '1.0-1', 'fail2ban': '1.0-1'},
                'engine': {'sing-box': '1.14.4'},
            },
            'engine_version': '1.14.4', 'provenance': {'run': 'verified-test-fixture'},
        }
        self.save_metadata()
        versions = {name: version for group in self.metadata['packages'].values() for name, version in group.items()}
        self.packages = FakePackages(versions)
        self.binary = self.system / 'usr/bin/sing-box'
        self.binary.parent.mkdir(parents=True)
        self.binary.write_text('packaged test binary; never executed')
        self.binary.chmod(0o755)
        self.chosen_binary = str(self.binary)

    def save_metadata(self):
        (self.project / 'dependencies.lock.json').write_text(json.dumps(self.metadata))

    def manager(self):
        return release.Release(self.project, self.system, self.packages, lambda name: self.chosen_binary)

    def test_exact_specs_and_package_lookup_never_fall_back_to_latest(self):
        manager = self.manager()
        self.assertEqual(manager.specs(), [f'{name}={version}' for name, version in {
            **self.metadata['packages']['common'], **self.metadata['packages']['host']}.items()])
        self.assertNotIn('sing-box=1.14.4', manager.specs())
        self.assertNotIn('ufw=1.0-1', manager.specs(container=True))
        self.assertEqual(manager.package('sing-box'), 'sing-box=1.14.4')
        self.assertEqual(manager.package('iproute2'), 'iproute2=1.0-1')
        with self.assertRaisesRegex(ValueError, 'not pinned'):
            manager.package('unlisted-package')
        self.assertFalse(self.packages.calls)

    def test_malformed_metadata_and_nonexact_pins_are_rejected(self):
        original = copy.deepcopy(self.metadata)
        changes = [
            lambda data: data.update(schema=True),
            lambda data: data.update(schema=2),
            lambda data: data.update(release='0.2.0'),
            lambda data: data.update(os={'id': 'ubuntu'}),
            lambda data: data.update(architectures=[]),
            lambda data: data.update(architectures=['amd64', 'amd64']),
            lambda data: data.update(provenance={}),
            lambda data: data.update(engine_version='latest'),
            lambda data: data['packages']['common'].update(curl='latest'),
            lambda data: data['packages']['common'].update(curl='1.*'),
            lambda data: data['packages']['common'].update(curl='1.0\n--allow-downgrades'),
            lambda data: data['packages']['host'].update(curl='1.0-1'),
            lambda data: data['packages'].update(engine={'other-engine': '1.0'}),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                self.metadata = copy.deepcopy(original)
                change(self.metadata)
                self.save_metadata()
                with self.assertRaises(ValueError):
                    self.manager()
        self.assertFalse(self.packages.calls)

    def test_missing_lock_or_invalid_version_cannot_use_defaults(self):
        (self.project / 'dependencies.lock.json').unlink()
        with self.assertRaises(FileNotFoundError):
            self.manager()
        (self.project / 'VERSION').write_text('latest\n')
        with self.assertRaisesRegex(ValueError, 'VERSION'):
            release.release_version(self.project)

    def test_unsupported_platform_or_architecture_refuses_before_package_inspection(self):
        manager = self.manager()
        (self.system / 'etc/os-release').write_text('ID=ubuntu\nVERSION_ID=22.04\n')
        with self.assertRaisesRegex(ValueError, 'operating system'):
            manager.preflight()
        self.assertFalse(self.packages.calls)
        (self.system / 'etc/os-release').write_text('ID=ubuntu\nVERSION_ID=24.04\n')
        self.packages.architecture = 'arm64'
        with self.assertRaisesRegex(ValueError, 'architecture'):
            manager.preflight()
        self.assertEqual(self.packages.calls, [['dpkg', '--print-architecture']])

    def test_missing_dependencies_are_allowed_only_in_preflight(self):
        self.packages.versions.clear()
        self.binary.unlink()
        self.chosen_binary = None
        manager = self.manager()
        manager.preflight()
        with self.assertRaisesRegex(ValueError, 'not installed'):
            manager.verify()

    def test_lower_system_dependency_is_allowed_but_verify_requires_exact_pin(self):
        self.packages.versions['curl'] = '0.9-1'
        manager = self.manager()
        manager.preflight()
        with self.assertRaisesRegex(ValueError, 'curl=1.0-1'):
            manager.verify()

    def test_newer_system_dependency_is_not_downgraded(self):
        self.packages.versions['curl'] = '1.1-1'
        with self.assertRaisesRegex(ValueError, 'newer.*downgrade'):
            self.manager().preflight()

    def test_container_does_not_require_or_inspect_host_only_packages(self):
        self.packages.versions['ufw'] = '1.1-1'
        del self.packages.versions['fail2ban']
        manager = self.manager()
        manager.preflight(container=True)
        manager.verify(container=True)
        queried = [command[-1] for command in self.packages.calls if command[:2] == ['dpkg-query', '--show']]
        self.assertNotIn('ufw', queried)
        self.assertNotIn('fail2ban', queried)
        with self.assertRaisesRegex(ValueError, 'newer.*downgrade'):
            manager.preflight()

    def test_engine_never_automatically_changes_even_from_an_older_version(self):
        for version in ('1.13.0', '1.15.0'):
            with self.subTest(version=version):
                self.packages.versions['sing-box'] = version
                self.packages.calls.clear()
                with self.assertRaisesRegex(ValueError, 'no automatic engine upgrade or downgrade'):
                    self.manager().preflight()
                self.assertFalse(any(command[0] == str(self.binary) for command in self.packages.calls))

    def test_manual_engine_is_rejected_before_executing_it(self):
        del self.packages.versions['sing-box']
        with self.assertRaisesRegex(ValueError, 'manual'):
            self.manager().preflight()
        self.assertFalse(any(command[0] == str(self.binary) for command in self.packages.calls))

    def test_path_shadow_is_rejected_even_with_the_exact_package_version(self):
        shadow = self.system / 'usr/local/bin/sing-box'
        shadow.parent.mkdir(parents=True)
        shadow.write_text('must not execute')
        self.chosen_binary = str(shadow)
        with self.assertRaisesRegex(ValueError, 'shadowed'):
            self.manager().preflight()
        self.assertFalse(any(command[0].endswith('/sing-box') for command in self.packages.calls))

    def test_symlink_replacement_of_packaged_binary_is_rejected(self):
        target = self.base / 'manual-engine'
        target.write_text('must not execute')
        self.binary.unlink()
        self.binary.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'shadowed'):
            self.manager().preflight()

    def test_unowned_engine_or_changed_runtime_version_is_rejected(self):
        self.packages.owner = 'unrelated-package: /usr/bin/sing-box\n'
        with self.assertRaisesRegex(ValueError, 'belongs'):
            self.manager().preflight()
        self.packages.owner = 'sing-box:amd64: /usr/bin/sing-box\n'
        self.packages.runtime = 'sing-box version 1.15.0\n'
        with self.assertRaisesRegex(ValueError, 'does not report'):
            self.manager().preflight()

    def test_incomplete_package_status_and_query_errors_fail_closed(self):
        self.packages.status['curl'] = 'half-installed'
        with self.assertRaisesRegex(ValueError, 'not fully installed'):
            self.manager().preflight()
        self.packages.status.clear()
        key = ('dpkg-query', '--show', '--showformat=${db:Status-Status}\t${Version}\n', 'curl')
        self.packages.failures[key] = 2
        with self.assertRaisesRegex(ValueError, 'Cannot inspect'):
            self.manager().preflight()

    def test_verify_accepts_only_the_complete_exact_set(self):
        manager = self.manager()
        manager.verify()
        del self.packages.versions['qrencode']
        with self.assertRaisesRegex(ValueError, 'qrencode=1.0-1.*missing'):
            manager.verify()

    def test_cli_outputs_only_requested_values_and_readonly_checks_are_silent(self):
        manager = self.manager()
        cases = [('package', ['sing-box'], 'sing-box=1.14.4\n'), ('preflight', [], ''), ('verify', [], '')]
        for action, extra, expected in cases:
            with self.subTest(action=action), patch.object(release, 'Release', return_value=manager), \
                    patch.object(sys, 'argv', ['release.py', action, *extra]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                release.main()
                self.assertEqual(output.getvalue(), expected)
        with patch.object(release, 'release_version', return_value='0.1.0'), \
                patch.object(sys, 'argv', ['release.py', 'version']), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            release.main()
            self.assertEqual(output.getvalue(), '0.1.0\n')


if __name__ == '__main__':
    unittest.main()
