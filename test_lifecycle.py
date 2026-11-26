import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import configure
import lifecycle
import test_configure


RUN = '20261126T120000Z-123'


class FakeSystemd:
    def __init__(self):
        self.calls = []
        self.states = {'warp-pipe-proxy': ('loaded', 'active'),
                       'unbound': ('loaded', 'active'), 'fail2ban': ('loaded', 'inactive')}
        self.fail_reload = False
        self.vendor_unit = False

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        if command[1] == 'show':
            load, active = self.states[command[-1]]
            return subprocess.CompletedProcess(command, 0, f'LoadState={load}\nActiveState={active}\n')
        if command[1] in ('disable', 'stop'):
            self.states['warp-pipe-proxy'] = ('loaded', 'inactive')
        if command[1] == 'daemon-reload':
            if self.fail_reload:
                raise subprocess.CalledProcessError(1, command)
            self.states['warp-pipe-proxy'] = ('loaded' if self.vendor_unit else 'not-found', 'inactive')
        return subprocess.CompletedProcess(command, 0)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'etc/warp-pipe-proxy'
        self.root.mkdir(mode=0o700, parents=True)
        self.backup = self.base / 'var/lib/warp-pipe-proxy-installer'
        self.backup.mkdir(mode=0o700, parents=True)
        self.systemd = FakeSystemd()
        self.firewall_calls = []
        self.manager = lifecycle.Lifecycle(self.root, self.backup, self.base, self.systemd,
                                          firewall_cleanup=self.cleanup_firewall)
        fixture = test_configure.ConfigureTests()
        fixture.setUp()
        self.settings, self.credentials = fixture.settings, fixture.credentials
        for name, value in [('settings.json', self.settings), ('credentials.json', self.credentials)]:
            lifecycle.write_json(self.root / name, value)
        for name in ('managed', 'installed'):
            lifecycle.write_private(self.root / name, b'')
        for name in lifecycle.ALL_FILES:
            path = self.manager.target(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('owned content: ' + name)
            path.chmod(0o640 if name == lifecycle.CONFIG else 0o644)
        for directory in (self.manager.path(lifecycle.LOG_DIRECTORY), self.manager.path(lifecycle.STATE_DIRECTORY)):
            directory.mkdir(mode=0o700, parents=True)
            (directory / 'old-secret').write_text('old secret must be deleted')
        (self.backup / 'old-private-key').write_text('historic-private-key')
        self.manager.record(apt_source_created=True)
        self.manager.record_host_files(applied=True)

    def cleanup_firewall(self, run):
        self.firewall_calls.append('cleanup')
        return 2

    def test_purge_leaves_no_keys_backups_logs_or_snapshot(self):
        retained = {}
        for name in ('/etc/ufw/user.rules', '/etc/apt/keyrings/sagernet.asc',
                     '/etc/unbound/unbound.conf', '/etc/fail2ban/jail.conf'):
            path = self.manager.path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('shared host data')
            retained[path] = path.read_bytes()
        with (patch.object(lifecycle.shutil, 'copytree', side_effect=AssertionError('no backup')),
                patch.object(lifecycle.shutil, 'copy2', side_effect=AssertionError('no backup')),
                patch.object(lifecycle.tempfile, 'mkdtemp', side_effect=AssertionError('no snapshot'))):
            self.assertTrue(self.manager.uninstall())
        self.assertTrue(all(not self.manager.target(name).exists() for name in lifecycle.ALL_FILES))
        self.assertTrue(all(not directory.exists() for directory in self.manager.project_directories()))
        self.assertFalse(self.manager.path(lifecycle.PURGE_MARKER).exists())
        self.assertFalse(self.manager.path(lifecycle.BUNDLE).exists())
        self.assertFalse(self.manager.target(lifecycle.CONFIG).parent.exists())
        for path, original in retained.items():
            self.assertEqual(path.read_bytes(), original)
        self.assertEqual(self.firewall_calls, ['cleanup'])
        self.assertIn(['systemctl', 'try-restart', 'unbound'], self.systemd.calls)
        self.assertNotIn(['systemctl', 'try-restart', 'fail2ban'], self.systemd.calls)
        self.assertFalse(any(command[1] in ('enable', 'start') for command in self.systemd.calls))
        calls = list(self.systemd.calls)
        self.assertFalse(self.manager.uninstall())
        self.assertEqual(self.systemd.calls, calls)

    def test_interruption_after_data_deletion_leaves_only_nonsecret_retry_marker(self):
        self.systemd.fail_reload = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.manager.uninstall()
        marker = self.manager.path(lifecycle.PURGE_MARKER)
        content = marker.read_text()
        self.assertNotIn('private_key', content)
        self.assertNotIn('historic-private-key', content)
        self.assertNotIn('uuid', content)
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertTrue(all(not directory.exists() for directory in self.manager.project_directories()))
        with self.assertRaisesRegex(ValueError, 'interrupted'):
            self.manager.check_install()
        self.systemd.fail_reload = False
        self.assertTrue(self.manager.uninstall())
        self.assertFalse(marker.exists())
        self.manager.check_install()

    def test_corrupted_credentials_and_failed_revocation_can_be_purged(self):
        lifecycle.write_private(self.root / 'credentials.json', b'broken credentials')
        lifecycle.write_private(self.root / 'settings.json', b'broken settings')
        lifecycle.write_private(self.root / 'revocation-pending.json', b'broken intent JSON')
        self.manager.target(lifecycle.CONFIG).write_text('configuration after partial revocation')
        self.assertTrue(self.manager.uninstall())
        self.assertFalse(self.root.exists())
        self.assertFalse(self.backup.exists())
        self.assertFalse(any(command[1] in ('enable', 'start', 'restart') for command in self.systemd.calls))

    def test_corrupted_credentials_without_pending_revocation_do_not_block_purge(self):
        lifecycle.write_private(self.root / 'credentials.json', b'{invalid')
        self.assertTrue(self.manager.uninstall())
        self.assertFalse(self.root.exists())

    def test_modified_owned_host_file_refuses_before_stopping_or_deleting(self):
        target = self.manager.target(lifecycle.UNBOUND)
        target.write_text('administrator change')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.manager.uninstall()
        self.assertEqual(target.read_text(), 'administrator change')
        self.assertTrue((self.root / 'credentials.json').exists())
        self.assertFalse(self.systemd.calls)
        self.assertFalse(self.manager.path(lifecycle.PURGE_MARKER).exists())

    def test_modified_server_config_without_private_revocation_intent_refuses(self):
        self.manager.target(lifecycle.CONFIG).write_text('untracked change')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.manager.uninstall()
        self.assertFalse(self.systemd.calls)

    def test_symlinked_project_root_or_owned_file_never_deletes_external_data(self):
        external = self.base / 'external'
        external.mkdir()
        secret = external / 'secret'
        secret.write_text('keep')
        config = self.manager.target(lifecycle.CONFIG)
        original = config.read_bytes()
        config.unlink()
        config.symlink_to(secret)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.manager.uninstall()
        self.assertEqual(secret.read_text(), 'keep')
        config.unlink()
        config.write_bytes(original)
        self.backup.rename(self.base / 'saved-backup')
        self.backup.symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlinked project'):
            self.manager.uninstall()
        self.assertEqual(secret.read_text(), 'keep')
        self.assertFalse(self.systemd.calls)

    def test_nested_data_symlink_is_unlinked_without_following_it(self):
        external = self.base / 'external'
        external.mkdir()
        (external / 'secret').write_text('keep')
        (self.backup / 'external-link').symlink_to(external, target_is_directory=True)
        self.manager.uninstall()
        self.assertEqual((external / 'secret').read_text(), 'keep')
        self.assertFalse(self.backup.exists())

    def test_nested_same_filesystem_bind_mount_refuses_before_mutation(self):
        nested = self.backup / 'foreign-bind'
        nested.mkdir()
        protected = nested / 'secret'
        protected.write_text('keep')
        with patch.object(self.manager, 'mountpoints', return_value=[nested]), patch.object(
                lifecycle.os.path, 'ismount', return_value=False):
            with self.assertRaisesRegex(ValueError, 'bind mounts'):
                self.manager.uninstall()
        self.assertEqual(protected.read_text(), 'keep')
        self.assertFalse(self.systemd.calls)
        self.assertFalse(self.manager.path(lifecycle.PURGE_MARKER).exists())

    def test_mountinfo_parser_decodes_escaped_paths(self):
        mountinfo = '1 0 0:1 / / rw - tmpfs tmpfs rw\n2 1 0:1 / /var/lib/project\\040data rw - tmpfs tmpfs rw\n'
        with patch.object(lifecycle.Path, 'read_text', return_value=mountinfo):
            self.assertEqual(self.manager.mountpoints(), [Path('/'), Path('/var/lib/project data')])

    def test_foreign_manifest_path_and_unsafe_manifest_refuse(self):
        path = self.root / 'ownership.json'
        value = self.manager.read_manifest()
        value['files']['/etc/passwd'] = 'a' * 64
        lifecycle.write_json(path, value)
        with self.assertRaisesRegex(ValueError, 'Invalid ownership'):
            self.manager.uninstall()
        path.chmod(0o666)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.manager.uninstall()
        self.assertFalse(self.systemd.calls)

    def test_legacy_manifest_preserves_unproven_host_files_with_warning(self):
        manifest = self.manager.read_manifest()
        manifest['version'] = 1
        manifest['files'] = {name: manifest['files'][name] for name in lifecycle.LEGACY_FILES}
        lifecycle.write_json(self.root / 'ownership.json', manifest)
        self.manager.target(lifecycle.BUNDLE + '/uninstall_firewall.py').unlink()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.manager.uninstall()
        for name in lifecycle.HOST_FILES:
            self.assertTrue(self.manager.target(name).exists())
            self.assertIn(name, output.getvalue())
        self.assertFalse(self.root.exists())

    def test_current_manifest_requires_firewall_cleanup_module(self):
        manifest = self.manager.read_manifest()
        manifest['files'].pop(lifecycle.BUNDLE + '/uninstall_firewall.py')
        lifecycle.write_json(self.root / 'ownership.json', manifest)
        with self.assertRaisesRegex(ValueError, 'Invalid ownership'):
            self.manager.uninstall()
        self.assertFalse(self.systemd.calls)

    def test_manifest_missing_cannot_delete_shared_location_files(self):
        (self.root / 'ownership.json').unlink()
        with self.assertRaisesRegex(ValueError, 'No ownership manifest'):
            self.manager.uninstall()
        self.assertFalse(self.systemd.calls)

    def test_missing_unit_does_not_authorize_removing_a_vendor_replacement(self):
        self.manager.target(lifecycle.UNIT).unlink()
        self.systemd.vendor_unit = True
        self.systemd.states['warp-pipe-proxy'] = ('loaded', 'inactive')
        with self.assertRaisesRegex(ValueError, 'replacement'):
            self.manager.uninstall()
        self.assertTrue((self.root / 'credentials.json').exists())
        self.assertFalse(self.firewall_calls)
        self.assertNotIn(['systemctl', 'disable', '--now', 'warp-pipe-proxy'], self.systemd.calls)

    def test_only_aborted_install_data_without_manifest_does_not_change_firewall(self):
        (self.root / 'ownership.json').unlink()
        for name in lifecycle.OWNED_FILES:
            self.manager.target(name).unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(self.manager.uninstall())
        self.assertFalse(self.firewall_calls)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.backup.exists())

    def test_optional_bbr_refresh_skips_container_and_apt_changes_remain_detectable(self):
        old = self.manager.read_manifest()['files']
        self.manager.target(lifecycle.BBR_FILES[0]).write_text('administrator BBR change')
        self.manager.target(lifecycle.APT_SOURCE).write_text('administrator APT change')
        self.manager.record(container=True)
        self.manager.record_host_files(applied=True)
        current = self.manager.read_manifest()['files']
        self.assertEqual(current[lifecycle.BBR_FILES[0]], old[lifecycle.BBR_FILES[0]])
        self.assertEqual(current[lifecycle.APT_SOURCE], old[lifecycle.APT_SOURCE])
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.manager.uninstall()

    def test_skipped_bbr_keeps_previous_hash_for_administrator_changes(self):
        old = self.manager.read_manifest()['files']
        self.manager.target(lifecycle.BBR_FILES[0]).write_text('administrator BBR change')
        self.manager.record()
        self.manager.record_host_files()
        self.assertEqual(self.manager.read_manifest()['files'][lifecycle.BBR_FILES[0]],
                         old[lifecycle.BBR_FILES[0]])
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.manager.uninstall()

    def test_existing_untracked_bbr_and_apt_files_are_not_adopted_without_receipts(self):
        manifest = self.manager.read_manifest()
        untracked = (*lifecycle.BBR_FILES, lifecycle.APT_SOURCE)
        for name in untracked:
            manifest['files'].pop(name)
            self.manager.target(name).write_text('preexisting administrator content')
        lifecycle.write_json(self.root / 'ownership.json', manifest)
        self.manager.record()
        self.manager.record_host_files()
        self.assertTrue(all(name not in self.manager.read_manifest()['files'] for name in untracked))
        with contextlib.redirect_stdout(io.StringIO()):
            self.manager.uninstall()
        for name in untracked:
            self.assertEqual(self.manager.target(name).read_text(), 'preexisting administrator content')

    def test_container_purge_skips_firewall_cleanup(self):
        self.manager.record(container=True)
        self.manager.uninstall()
        self.assertFalse(self.firewall_calls)

    def test_existing_python_caches_are_removed_but_unknown_bundle_files_refuse(self):
        path = self.manager.target(lifecycle.BUNDLE + '/admin.py')
        path.write_text('VALUE = 42\n')
        subprocess.run([sys.executable, '-c',
                        'import importlib.util,sys; sys.dont_write_bytecode=False; '
                        's=importlib.util.spec_from_file_location("temporary_admin",sys.argv[1]); '
                        'm=importlib.util.module_from_spec(s); s.loader.exec_module(m)', str(path)], check=True)
        self.manager.record()
        unknown = path.parent / 'notes.txt'
        unknown.write_text('keep')
        with self.assertRaisesRegex(ValueError, 'Unknown bundle'):
            self.manager.uninstall()
        unknown.unlink()
        self.manager.uninstall()
        self.assertFalse(path.parent.exists())

    def test_malformed_service_state_is_never_treated_as_stopped(self):
        for output in ('', 'ActiveState=inactive\n',
                       'LoadState=loaded\nLoadState=not-found\nActiveState=inactive\n'):
            with self.subTest(output=output):
                self.manager.run = lambda command, **kwargs: subprocess.CompletedProcess(command, 0, output)
                with self.assertRaisesRegex(ValueError, 'determine'):
                    self.manager.service_state()

    def prepare_revocation(self):
        candidate = self.backup / RUN / 'revocation'
        candidate.parent.mkdir(mode=0o700)
        candidate.mkdir(mode=0o700)
        revoked = configure.prepare_credentials(self.credentials, 'device-revoke', 'default')
        lifecycle.write_json(candidate / 'settings.json', self.settings)
        lifecycle.write_json(candidate / 'credentials.json', revoked)
        self.manager.prepare_revoke(RUN)
        return candidate

    def test_uncommitted_revocation_blocks_install_but_allows_destructive_purge(self):
        candidate = self.prepare_revocation()
        with self.assertRaisesRegex(ValueError, str(candidate / 'credentials.json')):
            self.manager.check_install()
        self.assertTrue(self.manager.uninstall())
        self.assertFalse(self.root.exists())
        self.assertFalse(candidate.exists())

    def test_committed_revocation_can_reinstall_and_record_clears_intent(self):
        candidate = self.prepare_revocation()
        lifecycle.write_private(self.root / 'credentials.json', (candidate / 'credentials.json').read_bytes())
        self.manager.check_install()
        self.assertTrue((self.root / 'revocation-pending.json').exists())
        self.manager.record()
        self.assertFalse((self.root / 'revocation-pending.json').exists())
        self.assertIsNone(json.loads((self.root / 'credentials.json').read_text())['devices']['default'])

    def test_legacy_record_config_clears_only_committed_revocation(self):
        candidate = self.prepare_revocation()
        (self.root / 'ownership.json').unlink()
        with self.assertRaisesRegex(ValueError, 'Unfinished revocation'):
            self.manager.record_config()
        lifecycle.write_private(self.root / 'credentials.json', (candidate / 'credentials.json').read_bytes())
        self.manager.record_config()
        self.assertFalse((self.root / 'revocation-pending.json').exists())
        self.assertFalse((self.root / 'ownership.json').exists())

    def test_corrupt_candidate_or_manifest_cannot_clear_pending_revocation(self):
        candidate = self.prepare_revocation()
        original = (candidate / 'credentials.json').read_bytes()
        lifecycle.write_private(self.root / 'credentials.json', original)
        lifecycle.write_private(candidate / 'credentials.json', b'{}')
        with self.assertRaisesRegex(ValueError, 'corrupted'):
            self.manager.record_config()
        lifecycle.write_private(candidate / 'credentials.json', original)
        (self.root / 'ownership.json').chmod(0o666)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.manager.record_config()
        self.assertTrue((self.root / 'revocation-pending.json').exists())

    def test_live_revocation_sync_failure_preserves_pending_marker(self):
        candidate = self.prepare_revocation()
        lifecycle.write_private(self.root / 'credentials.json', (candidate / 'credentials.json').read_bytes())
        marker = self.root / 'revocation-pending.json'
        original_marker = marker.read_bytes()
        fsync = os.fsync
        for action in (self.manager.record_config, self.manager.record):
            for live in (self.root / 'credentials.json', self.manager.target(lifecycle.CONFIG)):
                with self.subTest(action=action.__name__, path=live):
                    expected = live.stat()

                    def fail_live_sync(descriptor):
                        current = os.fstat(descriptor)
                        if (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino):
                            raise OSError('simulated live-file fsync failure')
                        return fsync(descriptor)

                    with patch.object(lifecycle.os, 'fsync', side_effect=fail_live_sync):
                        with self.assertRaisesRegex(OSError, 'live-file fsync failure'):
                            action()
                    self.assertEqual(marker.read_bytes(), original_marker)
        self.manager.record_config()
        self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
