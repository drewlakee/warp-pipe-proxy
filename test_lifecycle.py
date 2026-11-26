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
        self.active = 'active'
        self.load = 'loaded'
        self.fail_reload = False

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        if command[1] == 'show':
            return subprocess.CompletedProcess(command, 0, f'LoadState={self.load}\nActiveState={self.active}\n')
        if command[1] in ('disable', 'stop'):
            self.active = 'inactive'
        if command[1] == 'daemon-reload':
            if self.fail_reload:
                raise subprocess.CalledProcessError(1, command)
            self.load = 'not-found'
        return subprocess.CompletedProcess(command, 0)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'etc/warp-pipe-proxy'
        self.root.mkdir(mode=0o700, parents=True)
        self.backup = self.base / 'var/lib/warp-pipe-proxy-installer'
        self.systemd = FakeSystemd()
        self.manager = lifecycle.Lifecycle(self.root, self.backup, self.base, self.systemd)
        fixture = test_configure.ConfigureTests()
        fixture.setUp()
        self.settings = fixture.settings
        self.credentials = fixture.credentials
        for name, value in [('settings.json', self.settings), ('credentials.json', self.credentials)]:
            lifecycle.write_json(self.root / name, value)
        for name in ('managed', 'installed'):
            lifecycle.write_private(self.root / name, b'')
        for name in lifecycle.OWNED_FILES:
            path = self.base / name.lstrip('/')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('owned content: ' + name)
            path.chmod(0o640 if name == lifecycle.CONFIG else 0o644)
        self.manager.record(container=True)

    def test_uninstall_and_restore_retain_keys_and_host_configuration(self):
        retained = {}
        for name in ('etc/ufw/user.rules', 'etc/unbound/unbound.conf.d/warp-pipe-proxy.conf',
                     'etc/fail2ban/jail.d/warp-pipe-proxy.local', 'etc/sysctl.d/90-warp-pipe-proxy.conf'):
            path = self.base / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('host configuration')
            retained[path] = path.read_bytes()
        original = {name: (self.root / name).read_bytes() for name in lifecycle.STATE_FILES}
        self.assertEqual(self.manager.uninstall(RUN), RUN)
        self.assertFalse((self.root / 'installed').exists())
        self.assertTrue(all(not self.manager.target(name).exists() for name in lifecycle.OWNED_FILES))
        self.assertEqual(self.manager.marker()['phase'], 'complete')
        for path, value in retained.items():
            self.assertEqual(path.read_bytes(), value)
        for name, value in original.items():
            self.assertEqual((self.root / name).read_bytes(), value)
            self.assertEqual((self.backup / RUN / name).read_bytes(), value)
            self.assertEqual((self.backup / RUN / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.backup / RUN).stat().st_mode & 0o777, 0o700)
        out = self.base / 'restore'
        self.assertTrue(self.manager.prepare_restore(RUN, out))
        self.assertEqual({name: (out / name).read_bytes() for name in lifecycle.STATE_FILES}, original)
        self.assertTrue(all(command[0] == 'systemctl' for command in self.systemd.calls))
        self.assertFalse(any(any(component in command for component in ('ufw', 'fail2ban', 'unbound', 'sing-box'))
                             for command in self.systemd.calls))

    def test_edited_file_refuses_before_stopping_or_snapshot(self):
        config = self.manager.target(lifecycle.CONFIG)
        config.write_text('administrator changes')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.manager.uninstall(RUN)
        self.assertEqual(config.read_text(), 'administrator changes')
        self.assertFalse(self.systemd.calls)
        self.assertFalse(self.backup.exists())
        self.assertFalse((self.root / 'uninstalled.json').exists())

    def test_unknown_manifest_path_never_deleted(self):
        manifest = self.manager.read_manifest()
        manifest['files']['/etc/passwd'] = 'a' * 64
        lifecycle.write_json(self.root / 'ownership.json', manifest)
        with self.assertRaisesRegex(ValueError, 'Invalid ownership'):
            self.manager.uninstall(RUN)
        self.assertFalse(self.systemd.calls)

    def test_symlinks_and_insecure_metadata_refused(self):
        manifest_path = self.root / 'ownership.json'
        manifest_path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.manager.uninstall(RUN)
        manifest_path.chmod(0o600)
        config = self.manager.target(lifecycle.CONFIG)
        real = self.base / 'unrelated'
        real.write_text('do not delete')
        config.unlink()
        config.symlink_to(real)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.manager.uninstall(RUN)
        self.assertEqual(real.read_text(), 'do not delete')
        self.assertFalse(self.systemd.calls)

    def test_pending_uninstall_can_resume_after_service_reload_failure(self):
        self.systemd.fail_reload = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.manager.uninstall(RUN)
        self.assertEqual(self.manager.marker()['phase'], 'pending')
        self.assertTrue((self.backup / RUN / 'credentials.json').is_file())
        with self.assertRaisesRegex(ValueError, 'interrupted'):
            self.manager.prepare_restore(RUN, self.base / 'restore')
        self.systemd.fail_reload = False
        self.assertEqual(self.manager.uninstall('different-new-run'), RUN)
        self.assertEqual(self.manager.marker()['phase'], 'complete')
        self.assertEqual(self.manager.uninstall('another-run'), RUN)
        self.assertFalse((self.backup / 'different-new-run').exists())

    def test_resume_refuses_modified_remaining_file(self):
        manifest = self.manager.read_manifest()
        self.manager.snapshot(RUN, manifest)
        self.manager.target(lifecycle.CONFIG).write_text('intervening change')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.manager.uninstall('another-run')
        self.assertFalse(self.systemd.calls)

    def test_restore_rejects_old_snapshot_newer_credentials_and_active_service(self):
        self.manager.uninstall(RUN)
        with self.assertRaisesRegex(ValueError, 'latest'):
            self.manager.prepare_restore('old-run', self.base / 'restore')
        credentials = json.loads((self.root / 'credentials.json').read_text())
        credentials['short_id'] = 'deadbeef'
        lifecycle.write_json(self.root / 'credentials.json', credentials)
        with self.assertRaisesRegex(ValueError, 'newer state'):
            self.manager.prepare_restore(RUN, self.base / 'restore')
        lifecycle.write_json(self.root / 'credentials.json', self.credentials)
        self.systemd.active = 'active'
        with self.assertRaisesRegex(ValueError, 'not stopped'):
            self.manager.prepare_restore(RUN, self.base / 'restore')
        self.assertFalse((self.base / 'restore').exists())

    def test_restore_rejects_tampered_snapshot_existing_install_or_unknown_unit_state(self):
        self.manager.uninstall(RUN)
        lifecycle.write_private(self.root / 'installed', b'')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.manager.prepare_restore(RUN, self.base / 'restore')
        (self.root / 'installed').unlink()
        original = (self.backup / RUN / 'recovery.json').read_bytes()
        lifecycle.write_private(self.backup / RUN / 'recovery.json', b'{}')
        with self.assertRaisesRegex(ValueError, 'corrupted'):
            self.manager.prepare_restore(RUN, self.base / 'restore')
        lifecycle.write_private(self.backup / RUN / 'recovery.json', original)
        self.systemd.load = 'error'
        with self.assertRaisesRegex(ValueError, 'determine'):
            self.manager.prepare_restore(RUN, self.base / 'restore')

    def test_restore_does_not_shadow_a_new_vendor_unit(self):
        self.manager.uninstall(RUN)
        self.systemd.load = 'loaded'
        with self.assertRaisesRegex(ValueError, 'Another proxy unit'):
            self.manager.prepare_restore(RUN, self.base / 'restore')
        with self.assertRaisesRegex(ValueError, 'Another proxy unit'):
            self.manager.uninstall('unused')
        self.assertFalse((self.base / 'restore').exists())

    def test_revocation_refreshes_config_manifest_and_legacy_is_noop(self):
        old = self.manager.read_manifest()['files'][lifecycle.CONFIG]
        self.manager.target(lifecycle.CONFIG).write_text('revoked user removed')
        self.manager.record_config()
        self.assertNotEqual(self.manager.read_manifest()['files'][lifecycle.CONFIG], old)
        self.manager.uninstall(RUN)
        (self.root / 'ownership.json').unlink()
        self.manager.record_config()
        self.assertFalse((self.root / 'ownership.json').exists())

    def test_legacy_uninstall_requires_reapply_and_identifiers_are_safe(self):
        (self.root / 'ownership.json').unlink()
        with self.assertRaisesRegex(ValueError, 'reapply'):
            self.manager.uninstall(RUN)
        self.assertFalse(self.systemd.calls)
        for value in ('../escape', '/absolute', '..', '', None, 'with spaces', 'a' * 100):
            self.assertFalse(self.manager.valid_run(value))

    def test_successful_reinstall_clears_recovery_marker(self):
        self.manager.uninstall(RUN)
        for name in lifecycle.OWNED_FILES:
            path = self.manager.target(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('reinstalled')
            path.chmod(0o644)
        lifecycle.write_private(self.root / 'installed', b'')
        self.manager.record(container=False)
        self.assertFalse((self.root / 'uninstalled.json').exists())
        self.assertFalse(self.manager.read_manifest()['container'])

    def test_install_refuses_pending_or_malformed_removal_marker(self):
        self.manager.check_install()
        self.manager.snapshot(RUN, self.manager.read_manifest())
        with self.assertRaisesRegex(ValueError, 'interrupted'):
            self.manager.check_install()
        self.manager.uninstall('unused')
        self.manager.check_install()
        lifecycle.write_json(self.root / 'uninstalled.json', [])
        with self.assertRaisesRegex(ValueError, 'Invalid uninstall'):
            self.manager.check_install()

    def test_uninstall_removes_actual_import_caches_and_restore_has_no_bundle_conflict(self):
        path = self.manager.target(lifecycle.BUNDLE + '/admin.py')
        path.write_text('VALUE = 42\n')
        # unittest may run with -B; a separate interpreter exercises real import caching.
        subprocess.run([sys.executable, '-c',
                        'import importlib.util,sys; sys.dont_write_bytecode=False; '
                        's=importlib.util.spec_from_file_location("temporary_admin",sys.argv[1]); '
                        'm=importlib.util.module_from_spec(s); s.loader.exec_module(m)', str(path)], check=True)
        cache = path.parent / '__pycache__'
        self.assertTrue(list(cache.glob('admin.cpython-*.pyc')))
        self.manager.record(container=True)
        self.manager.uninstall(RUN)
        self.assertFalse(path.parent.exists())
        self.assertTrue(self.manager.prepare_restore(RUN, self.base / 'restore'))

    def test_unknown_bundle_or_cache_files_refuse_before_removal(self):
        bundle = self.base / lifecycle.BUNDLE.lstrip('/')
        unknown = bundle / 'notes.txt'
        unknown.write_text('user notes')
        with self.assertRaisesRegex(ValueError, 'Unknown bundle'):
            self.manager.uninstall(RUN)
        unknown.unlink()
        cache = bundle / '__pycache__'
        cache.mkdir()
        unknown = cache / 'other.cpython-312.pyc'
        unknown.write_bytes(b'user data')
        with self.assertRaisesRegex(ValueError, 'Unknown Python cache'):
            self.manager.uninstall(RUN)
        self.assertEqual(unknown.read_bytes(), b'user data')
        self.assertFalse(self.systemd.calls)
        self.assertFalse((self.root / 'uninstalled.json').exists())

    def test_malformed_or_empty_service_state_is_never_treated_as_stopped(self):
        for output in ('', 'ActiveState=inactive\n',
                       'LoadState=loaded\nLoadState=not-found\nActiveState=inactive\n',
                       'unexpected\nLoadState=not-found\nActiveState=inactive\n'):
            with self.subTest(output=output):
                self.manager.run = lambda command, **kwargs: subprocess.CompletedProcess(command, 0, output)
                with self.assertRaisesRegex(ValueError, 'determine'):
                    self.manager.require_stopped()

    def prepare_revocation(self):
        self.backup.mkdir(mode=0o700, parents=True)
        candidate = self.backup / RUN / 'revocation'
        candidate.parent.mkdir(mode=0o700)
        candidate.mkdir(mode=0o700)
        revoked = configure.prepare_credentials(self.credentials, 'device-revoke', 'default')
        lifecycle.write_json(candidate / 'settings.json', self.settings)
        lifecycle.write_json(candidate / 'credentials.json', revoked)
        self.manager.prepare_revoke(RUN)
        return candidate

    def test_uncommitted_revocation_blocks_install_uninstall_and_restore(self):
        candidate = self.prepare_revocation()
        with self.assertRaisesRegex(ValueError, str(candidate / 'credentials.json')):
            self.manager.check_install()
        with self.assertRaisesRegex(ValueError, 'revocation is unfinished'):
            self.manager.uninstall('unused')
        with self.assertRaisesRegex(ValueError, 'revocation is unfinished'):
            self.manager.prepare_restore('unused', self.base / 'restore')
        self.assertFalse(self.systemd.calls)
        self.assertTrue((self.root / 'installed').exists())

    def test_committed_revocation_can_reinstall_and_record_clears_intent(self):
        candidate = self.prepare_revocation()
        lifecycle.write_private(self.root / 'credentials.json', (candidate / 'credentials.json').read_bytes())
        self.manager.check_install()
        self.assertTrue((self.root / 'revocation-pending.json').exists())
        with self.assertRaisesRegex(ValueError, 'revocation is unfinished'):
            self.manager.uninstall('unused')
        self.manager.record(container=True)
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
