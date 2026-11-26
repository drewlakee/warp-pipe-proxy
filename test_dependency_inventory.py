import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    'dependency_inventory', Path(__file__).parent / 'tests/dependency_inventory.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class DependencyInventoryTests(unittest.TestCase):
    def test_actual_installed_versions_keep_debian_epoch_and_multiarch_names(self):
        packages = inventory.parse_packages(
            'dnsutils\t1:9.18.39-0ubuntu0.24.04.9\tall\tinstalled\n'
            'libexample:amd64\t2.1-3\tamd64\tinstalled\n'
            'old-package\t1.0\tamd64\tconfig-files\n')
        self.assertEqual(packages, [
            {'name': 'dnsutils', 'version': '1:9.18.39-0ubuntu0.24.04.9', 'architecture': 'all'},
            {'name': 'libexample:amd64', 'version': '2.1-3', 'architecture': 'amd64'},
        ])

    def test_inventory_cannot_report_a_lock_as_tested_when_actual_package_differs(self):
        lock = {'packages': {'common': {'python3': '3.12.3-0ubuntu2.1'},
                             'host': {'ufw': '0.36.2-6'}, 'engine': {'sing-box': '1.14.4'}}}
        packages = inventory.parse_packages(
            'python3\t3.12.3-0ubuntu2.1\tamd64\tinstalled\n'
            'ufw\t0.36.2-6\tall\tinstalled\n'
            'sing-box\t1.14.4\tamd64\tinstalled\n')
        self.assertEqual(inventory.direct_inventory(lock, packages)['sing-box'],
                         {'version': '1.14.4', 'architecture': 'amd64'})
        for changed in (packages[:-1], [dict(item, version='9.9') for item in packages]):
            with self.subTest(packages=changed), self.assertRaisesRegex(ValueError, 'disagrees with lock'):
                inventory.direct_inventory(lock, changed)

    def test_os_release_quoted_fields_are_recorded_without_shell_evaluation(self):
        self.assertEqual(inventory.parse_os_release(
            '# comment\nID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n'
            'VARIANT="$(must-not-run)"\n'),
            {'ID': 'ubuntu', 'VERSION_ID': '24.04', 'PRETTY_NAME': 'Ubuntu 24.04 LTS',
             'VARIANT': '$(must-not-run)'})


if __name__ == '__main__':
    unittest.main()
