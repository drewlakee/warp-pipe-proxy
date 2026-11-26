from pathlib import Path
import subprocess
import tempfile
import unittest

BASE = Path(__file__).resolve().parent


class RevocationTests(unittest.TestCase):
    def revoke(self, *, active=True, probe_fail=False, restart_fail=False, write_fail=False,
               invalid_config=False, credentials_write_fail=False, manifest_fail=False, enabled='enabled'):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        credentials = root / 'etc/warp-pipe-proxy'
        credentials.mkdir(parents=True)
        (root / 'etc/sing-box').mkdir()
        (credentials / 'installed').touch()
        (credentials / 'settings.json').write_text('unchanged')
        for name in ('credentials.json', 'clients.txt', 'client-sing-box.json'):
            (credentials / name).write_text('old')
        server = root / 'etc/sing-box/config.json'
        server.write_text('old')
        (root / 'active').write_text('yes' if active else 'no')
        (root / 'enabled').write_text(enabled)
        runtime = (BASE / 'runtime.sh').read_text()
        runtime = runtime.replace('/etc/', str(root) + '/etc/').replace('/var/lib/', str(root) + '/var/lib/')
        script = root / 'runtime.sh'
        script.write_text(runtime)
        result = subprocess.run(['bash', '-c', f'''
set -Eeuo pipefail
umask 077
source "{script}"
ROOT="{credentials}"
BASE="{BASE}"
MODE=device-revoke
DEVICE=phone
RUN=test
log() {{ echo "$*"; }}
stage() {{ echo "$*"; }}
systemctl() {{
    echo "$*" >> "{root}/services"
    case "$1" in
        is-active)
            if [[ $(cat "{root}/active") == yes ]]; then
                [[ $* == *--quiet* ]] || echo active
                return 0
            fi
            [[ $* == *--quiet* ]] || echo inactive
            return 3
            ;;
        is-enabled)
            cat "{root}/enabled"
            [[ $(cat "{root}/enabled") == enabled* ]]
            ;;
        stop) echo no > "{root}/active";;
        disable) echo disabled > "{root}/enabled";;
        enable)
            if [[ $* == *--runtime* ]]; then
                echo enabled-runtime > "{root}/enabled"
            else
                echo enabled > "{root}/enabled"
            fi
            ;;
        restart)
            if (( {int(restart_fail)} )); then return 42; fi
            echo yes > "{root}/active"
            ;;
    esac
}}
sing-box() {{
    echo "$*" >> "{root}/checks"
    if (( {int(invalid_config)} )); then return 13; fi
}}
install() {{
    local args=()
    if (( {int(write_fail)} )) && [[ ${{*: -1}} == "{server}.tmp" ]]; then return 28; fi
    if (( {int(credentials_write_fail)} )) && [[ ${{*: -1}} == "$ROOT/credentials.json.tmp" ]]; then
        echo truncated > "$ROOT/credentials.json.tmp"
        return 28
    fi
    while (( $# )); do
        case "$1" in -o|-g) shift 2;; *) args+=("$1"); shift;; esac
    done
    command install "${{args[@]}}"
}}
python3() {{
    if [[ $1 == */lifecycle.py ]]; then
        if [[ $2 == record-config ]] && (( {int(manifest_fail)} )); then return 29; fi
        return 0
    fi
    if [[ $1 == */probe.py ]]; then
        echo probe >> "{root}/probes"
        return {int(probe_fail)}
    fi
    for name in credentials.json config.json client-sing-box.json clients.txt; do
        echo revoked > "$STAGE/$name"
    done
}}
update_credentials
'''], text=True, capture_output=True)
        return root, result

    def test_external_failure_does_not_undo_revocation(self):
        root, result = self.revoke(probe_fail=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Device remains revoked', result.stdout)
        self.assertNotIn('Rolling back', result.stdout)
        for path in ('etc/warp-pipe-proxy/credentials.json', 'etc/sing-box/config.json',
                     'etc/warp-pipe-proxy/clients.txt', 'etc/warp-pipe-proxy/client-sing-box.json'):
            self.assertEqual((root / path).read_text().strip(), 'revoked')
        self.assertEqual((root / 'active').read_text().strip(), 'yes')
        self.assertEqual((root / 'enabled').read_text().strip(), 'enabled')
        self.assertEqual((root / 'probes').read_text().strip(), 'probe')

    def test_inactive_service_can_be_revoked_without_start_or_network(self):
        root, result = self.revoke(active=False, probe_fail=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((root / 'active').read_text().strip(), 'no')
        self.assertEqual((root / 'etc/warp-pipe-proxy/credentials.json').read_text().strip(), 'revoked')
        self.assertFalse((root / 'probes').exists())
        self.assertNotIn('restart', (root / 'services').read_text())
        self.assertIn('remains stopped', result.stdout)

    def test_restart_failure_keeps_revocation_and_disables_service(self):
        root, result = self.revoke(restart_fail=True)
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual((root / 'etc/warp-pipe-proxy/credentials.json').read_text().strip(), 'revoked')
        self.assertEqual((root / 'etc/sing-box/config.json').read_text().strip(), 'revoked')
        self.assertEqual((root / 'active').read_text().strip(), 'no')
        self.assertEqual((root / 'enabled').read_text().strip(), 'disabled')
        self.assertNotIn('Rolling back', result.stdout)
        self.assertFalse((root / 'probes').exists())

    def test_partial_write_failure_stays_off_and_keeps_validated_recovery_copy(self):
        root, result = self.revoke(write_fail=True)
        self.assertEqual(result.returncode, 28, result.stderr)
        self.assertEqual((root / 'active').read_text().strip(), 'no')
        self.assertEqual((root / 'enabled').read_text().strip(), 'disabled')
        self.assertEqual((root / 'etc/warp-pipe-proxy/credentials.json').read_text().strip(), 'revoked')
        self.assertEqual((root / 'etc/sing-box/config.json').read_text(), 'old')
        recovery = root / 'var/lib/warp-pipe-proxy-installer/test/revocation'
        self.assertEqual((recovery / 'config.json').read_text().strip(), 'revoked')
        self.assertEqual((recovery / 'credentials.json').read_text().strip(), 'revoked')
        self.assertNotIn('Rolling back', result.stdout)
        self.assertIn('Do not restore the pre-revocation credentials', result.stdout)

    def test_invalid_staged_config_leaves_existing_state_untouched(self):
        root, result = self.revoke(invalid_config=True)
        self.assertEqual(result.returncode, 13, result.stderr)
        self.assertEqual((root / 'active').read_text(), 'yes')
        self.assertEqual((root / 'enabled').read_text(), 'enabled')
        self.assertEqual((root / 'etc/warp-pipe-proxy/credentials.json').read_text(), 'old')
        self.assertEqual((root / 'etc/sing-box/config.json').read_text(), 'old')
        self.assertFalse((root / 'services').exists())

    def test_manifest_failure_does_not_restore_revoked_access(self):
        root, result = self.revoke(manifest_fail=True)
        self.assertEqual(result.returncode, 29, result.stderr)
        self.assertEqual((root / 'etc/warp-pipe-proxy/credentials.json').read_text().strip(), 'revoked')
        self.assertEqual((root / 'active').read_text().strip(), 'no')
        self.assertEqual((root / 'enabled').read_text().strip(), 'disabled')
        self.assertNotIn('Rolling back', result.stdout)
        self.assertFalse((root / 'probes').exists())

    def test_failed_credential_write_does_not_corrupt_authority(self):
        root, result = self.revoke(credentials_write_fail=True)
        self.assertEqual(result.returncode, 28, result.stderr)
        self.assertEqual((root / 'etc/warp-pipe-proxy/credentials.json').read_text(), 'old')
        self.assertFalse((root / 'etc/warp-pipe-proxy/credentials.json.tmp').exists())
        self.assertEqual((root / 'active').read_text().strip(), 'no')
        self.assertEqual((root / 'enabled').read_text().strip(), 'disabled')
        self.assertEqual((root / 'var/lib/warp-pipe-proxy-installer/test/revocation/credentials.json').read_text().strip(), 'revoked')

    def test_success_preserves_enablement_and_activity(self):
        for active in (False, True):
            for enabled in ('enabled', 'disabled', 'enabled-runtime'):
                with self.subTest(active=active, enabled=enabled):
                    root, result = self.revoke(active=active, enabled=enabled)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((root / 'enabled').read_text().strip(), enabled)
                    self.assertEqual((root / 'active').read_text().strip(), 'yes' if active else 'no')
                    if active:
                        calls = (root / 'services').read_text().splitlines()
                        self.assertLess(calls.index('disable warp-pipe-proxy'), calls.index('restart warp-pipe-proxy'))


if __name__ == '__main__':
    unittest.main()
