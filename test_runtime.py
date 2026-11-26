import importlib.util
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('probe', BASE / 'probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class RuntimeTests(unittest.TestCase):
    def shell(self, body, setup=''):
        return subprocess.run(['bash', '-c', f'''
set -Eeuo pipefail
source "{BASE}/runtime.sh"
log() {{ echo "$*"; }}
{setup}
{body}
'''], capture_output=True, text=True)

    def pristine_package_check(self, change=None, query_fails=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'etc/unbound'
            config.mkdir(parents=True)
            source = config / 'unbound.conf'
            source.write_text('package default configuration\n')
            checksum = hashlib.md5(source.read_bytes()).hexdigest()
            metadata = root / 'conffiles'
            metadata.write_text(f' {source} {checksum}\n')
            commands = root / 'bin'
            commands.mkdir()
            query = commands / 'dpkg-query'
            query.write_text('#!/bin/sh\n' + ('exit 1\n' if query_fails else f'cat {shlex.quote(str(metadata))}\n'))
            query.chmod(0o700)
            if change:
                change(config, source)
            return self.shell(f'check_pristine_package_tree {shlex.quote(str(config))} unbound',
                              f'export PATH={shlex.quote(str(commands))}:"$PATH"')

    def test_reinstall_accepts_only_pristine_dependency_configuration(self):
        result = self.pristine_package_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        changes = (
            lambda root, source: source.write_text('administrator configuration\n'),
            lambda root, source: (root / 'custom.conf').write_text('new configuration\n'),
            lambda root, source: (root / 'linked.conf').symlink_to(source),
            lambda root, source: source.chmod(0o666),
            lambda root, source: source.unlink(),
        )
        for change in changes:
            with self.subTest(change=change):
                result = self.pristine_package_check(change)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('refusing to overwrite an unmanaged installation', result.stderr)

    def test_reinstall_refuses_unverifiable_package_configuration(self):
        result = self.pristine_package_check(query_fails=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not pristine unbound configuration', result.stderr)

    def test_individual_service_failure(self):
        result = self.shell('wait_services', '''
systemctl() { [[ ${*: -1} != fail2ban ]]; }
sleep() { :; }
''')
        self.assertNotEqual(result.returncode, 0)

    def test_udp_listener_refuses_firewall(self):
        result = self.shell('protect_listeners', '''
UFW_ACTIVE=no
SSH_PORTS=22
ROOT=/nonexistent
ss() {
 if [[ $* == *-lun* ]]; then echo 'UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*'; fi
}
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unmanaged udp listener', result.stdout)

    def test_active_firewall_does_not_reject_existing_services(self):
        result = self.shell('protect_listeners', 'UFW_ACTIVE=yes\nss() { return 99; }')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_listener_query_error_stops_install(self):
        result = self.shell('protect_listeners', 'UFW_ACTIVE=no\nss() { return 42; }')
        self.assertEqual(result.returncode, 42)

    def test_bbr_failure_is_optional_and_restores_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = (BASE / 'runtime.sh').read_text().replace('/etc/', directory + '/etc/').replace('/usr/local/', directory + '/usr/local/')
            path = Path(directory) / 'runtime.sh'
            path.write_text(runtime)
            result = subprocess.run(['bash', '-c', f'''
set -Eeuo pipefail
source "{path}"
BACKUP={directory}/backup
log() {{ echo "$*"; }}
systemd-detect-virt() {{ return 1; }}
modprobe() {{ return 0; }}
sysctl() {{
 if [[ $1 == -n ]]; then echo original; return 0; fi
 echo "$*"
 [[ $* != *'=bbr'* ]]
}}
configure_bbr
'''], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('net.ipv4.tcp_congestion_control=original', result.stdout)
            self.assertIn('installation remains successful', result.stdout)

    def test_bbr_receipt_requires_both_persistent_files(self):
        for succeeded in (True, False):
            with self.subTest(succeeded=succeeded), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for folder in ('etc/modules-load.d', 'etc/sysctl.d', 'stage', 'backup'):
                    (root / folder).mkdir(parents=True)
                runtime = (BASE / 'runtime.sh').read_text().replace('/etc/', directory + '/etc/')
                path = root / 'runtime.sh'
                path.write_text(runtime)
                if not succeeded:
                    # A failed persistent write must not authorize adopting
                    # preexisting host configuration as newly owned.
                    (root / 'etc/sysctl.d/90-warp-pipe-proxy.conf').mkdir()
                result = subprocess.run(['bash', '-c', f'''
set -Eeuo pipefail
source "{path}"
trap - EXIT
STAGE={shlex.quote(str(root / 'stage'))}
BACKUP={shlex.quote(str(root / 'backup'))}
log() {{ :; }}
systemd-detect-virt() {{ return 1; }}
modprobe() {{ return 0; }}
sysctl() {{ if [[ $1 == -n ]]; then echo original; fi; return 0; }}
configure_bbr
'''], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root / 'stage/bbr-applied').exists(), succeeded)

    def test_exit_failure_restores_files_and_removes_new_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = (BASE / 'runtime.sh').read_text().replace('/etc/', directory + '/etc/').replace('/usr/local/', directory + '/usr/local/')
            (root / 'runtime.sh').write_text(runtime)
            for folder in ('etc/sing-box', 'etc/unbound/unbound.conf.d', 'etc/fail2ban/jail.d',
                           'etc/systemd/system', 'etc/default', 'etc/ufw', 'root', 'backup'):
                (root / folder).mkdir(parents=True, exist_ok=True)
            config = root / 'etc/sing-box/config.json'
            config.write_text('old')
            launcher = root / 'usr/local/bin/warp-pipe-proxy'
            launcher.parent.mkdir(parents=True)
            launcher.write_text('old launcher')
            for name in ('settings.json', 'credentials.json'):
                (root / 'root' / name).write_text('legacy')
            result = subprocess.run(['bash', '-c', f'''
set -Eeuo pipefail
source "{root}/runtime.sh"
ROOT={root}/root
BACKUP={root}/backup
log() {{ echo "$*"; }}
systemctl() {{
 case "$1" in
 is-active) echo inactive; return 3;;
 is-enabled) echo disabled; return 1;;
 *) return 0;;
 esac
}}
UFW_ACTIVE=no
begin_transaction
FIREWALL_CHANGED=1
ufw() {{ echo "FIREWALL: $*"; }}
printf new > "{config}"
printf new > "$ROOT/clients.txt"
printf migrated > "$ROOT/settings.json"
printf migrated > "$ROOT/credentials.json"
printf changed > "{launcher}"
mkdir -p "{root}/usr/local/lib/warp-pipe-proxy"
printf new > "{root}/usr/local/lib/warp-pipe-proxy/admin.py"
exit 17
'''], text=True, capture_output=True)
            self.assertEqual(result.returncode, 17, result.stderr)
            self.assertEqual(config.read_text(), 'old')
            self.assertEqual(launcher.read_text(), 'old launcher')
            self.assertFalse((root / 'usr/local/lib/warp-pipe-proxy').exists())
            for name in ('settings.json', 'credentials.json'):
                self.assertEqual((root / 'root' / name).read_text(), 'legacy')
            self.assertFalse((root / 'root/clients.txt').exists())
            self.assertIn('service states restored', result.stdout)
            self.assertIn('FIREWALL: --force disable', result.stdout)

    def test_container_skips_firewall_and_bbr_commands(self):
        result = self.shell(
            'firewall_preflight; firewall_backend_check; protect_listeners; configure_bbr',
            """
CONTAINER_MODE=1
iptables() { echo UNEXPECTED; return 91; }
ip6tables() { echo UNEXPECTED; return 91; }
ufw() { echo UNEXPECTED; return 91; }
ss() { echo UNEXPECTED; return 91; }
sysctl() { echo UNEXPECTED; return 91; }
modprobe() { echo UNEXPECTED; return 91; }
systemd-detect-virt() { echo UNEXPECTED; return 91; }
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('UNEXPECTED', result.stdout)

    def test_rollback_preserves_active_firewall_and_intervening_admin_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = (BASE / 'runtime.sh').read_text().replace('/etc/', directory + '/etc/').replace('/usr/local/', directory + '/usr/local/')
            (root / 'runtime.sh').write_text(runtime)
            rules = root / 'etc/ufw/user.rules'
            rules.parent.mkdir(parents=True)
            rules.write_text('original administrator policy')
            result = subprocess.run(['bash', '-c', f'''
set -Eeuo pipefail
source "{root}/runtime.sh"
ROOT="{root}/root"
BACKUP="{root}/backup"
UFW_ACTIVE=yes
log() {{ echo "$*"; }}
systemctl() {{
    case "$1" in
        is-active) echo inactive; return 3;;
        is-enabled) echo disabled; return 1;;
        *) return 0;;
    esac
}}
ufw() {{ echo UNEXPECTED_FIREWALL_CHANGE; return 99; }}
begin_transaction
printf 'intervening administrator policy' > "{rules}"
exit 17
'''], text=True, capture_output=True)
            self.assertEqual(result.returncode, 17, result.stderr)
            self.assertEqual(rules.read_text(), 'intervening administrator policy')
            self.assertNotIn('UNEXPECTED_FIREWALL_CHANGE', result.stdout)
            self.assertNotIn('/etc/ufw', (root / 'backup/paths').read_text())

    def test_container_does_not_require_fail2ban_service(self):
        result = self.shell('wait_services', """
CONTAINER_MODE=1
systemctl() {
    echo "$*"
    [[ ${*: -1} != fail2ban ]]
}
sleep() { :; }
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('fail2ban', result.stdout)

    def test_container_rollback_leaves_firewall_and_fail2ban_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = (BASE / 'runtime.sh').read_text().replace('/etc/', directory + '/etc/').replace('/usr/local/', directory + '/usr/local/')
            (root / 'runtime.sh').write_text(runtime)
            for folder in ('etc/sing-box', 'etc/unbound/unbound.conf.d', 'etc/fail2ban/jail.d',
                           'etc/systemd/system', 'etc/default', 'etc/ufw', 'root', 'backup'):
                (root / folder).mkdir(parents=True, exist_ok=True)
            sentinel = root / 'etc/ufw/keep'
            sentinel.write_text('original')
            config = root / 'etc/sing-box/config.json'
            config.write_text('original')
            result = subprocess.run(['bash', '-c', f'''
set -Eeuo pipefail
CONTAINER_MODE=1
source "{root}/runtime.sh"
ROOT={root}/root
BACKUP={root}/backup
log() {{ echo "$*"; }}
systemctl() {{
 echo "$*" >> "{root}/calls"
 case "$1" in
 is-active) echo inactive; return 3;;
 is-enabled) echo disabled; return 1;;
 *) return 0;;
 esac
}}
ufw() {{ echo UNEXPECTED; return 91; }}
begin_transaction
printf modified > "{config}"
printf external-change > "{sentinel}"
exit 17
'''], text=True, capture_output=True)
            self.assertEqual(result.returncode, 17, result.stderr)
            self.assertEqual(config.read_text(), 'original')
            self.assertEqual(sentinel.read_text(), 'external-change')
            self.assertNotIn('fail2ban', (root / 'calls').read_text())
            self.assertNotIn('UNEXPECTED', result.stdout)
            self.assertNotIn('/etc/ufw', (root / 'backup/paths').read_text())

    def test_installed_command_survives_source_removal_and_reinstall(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = (BASE / 'runtime.sh').read_text().replace('/usr/local/', directory + '/usr/local/')
            (root / 'runtime.sh').write_text(runtime)
            source = root / 'source'
            source.mkdir()
            for name in ('warp-pipe-proxy.sh', 'runtime.sh', 'logging.sh', 'configure.py', 'probe.py', 'admin.py', 'activity.py', 'lifecycle.py', 'uninstall_firewall.py'):
                (source / name).write_text((BASE / name).read_text())
            stage = root / 'stage'
            stage.mkdir()
            result = subprocess.run(['bash', '-c', f'''
set -Eeuo pipefail
source "{root}/runtime.sh"
BASE="{source}"
STAGE="{stage}"
log() {{ :; }}
install_cli_command
rm -rf "$BASE"
"{root}/usr/local/bin/warp-pipe-proxy" --help
BASE="{root}/usr/local/lib/warp-pipe-proxy"
install_cli_command
"{root}/usr/local/bin/warp-pipe-proxy" --help
'''], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('doctor', result.stdout)

    def test_cli_refuses_unmanaged_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = (BASE / 'runtime.sh').read_text().replace('/usr/local/', directory + '/usr/local/')
            (root / 'runtime.sh').write_text(runtime)
            command = root / 'usr/local/bin/warp-pipe-proxy'
            command.parent.mkdir(parents=True)
            command.write_text('unrelated command')
            result = subprocess.run(['bash', '-c', f'source "{root}/runtime.sh"; log() {{ :; }}; check_cli_paths'], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(command.read_text(), 'unrelated command')

    def test_probe_has_no_direct_fallback_or_private_key(self):
        config = probe.client_config({'vless_port': 10443, 'reality_host': 'example.com'},
                                    {'uuid': 'uuid', 'public_key': 'public', 'short_id': 'abcd'}, 2080)
        self.assertEqual([o['type'] for o in config['outbounds']], ['vless'])
        self.assertEqual(config['route']['final'], 'probe')
        self.assertNotIn('private_key', json.dumps(config))


if __name__ == '__main__':
    unittest.main()
