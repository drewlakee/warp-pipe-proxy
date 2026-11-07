import importlib.util
import json
from pathlib import Path
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
            runtime = (BASE / 'runtime.sh').read_text().replace('/etc/', directory + '/etc/')
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

    def test_exit_failure_restores_files_and_removes_new_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = (BASE / 'runtime.sh').read_text().replace('/etc/', directory + '/etc/')
            (root / 'runtime.sh').write_text(runtime)
            for folder in ('etc/sing-box', 'etc/unbound/unbound.conf.d', 'etc/fail2ban/jail.d',
                           'etc/systemd/system', 'etc/default', 'etc/ufw', 'root', 'backup'):
                (root / folder).mkdir(parents=True, exist_ok=True)
            config = root / 'etc/sing-box/config.json'
            config.write_text('old')
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
begin_transaction
FIREWALL_CHANGED=1
UFW_ACTIVE=yes
ufw() {{ echo "FIREWALL: $*"; }}
printf new > "{config}"
printf new > "$ROOT/clients.txt"
exit 17
'''], text=True, capture_output=True)
            self.assertEqual(result.returncode, 17, result.stderr)
            self.assertEqual(config.read_text(), 'old')
            self.assertFalse((root / 'root/clients.txt').exists())
            self.assertIn('service states restored', result.stdout)
            self.assertIn('FIREWALL: reload', result.stdout)

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
            runtime = (BASE / 'runtime.sh').read_text().replace('/etc/', directory + '/etc/')
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

    def test_probe_has_no_direct_fallback_or_private_key(self):
        config = probe.client_config({'vless_port': 10443, 'reality_host': 'example.com'},
                                    {'uuid': 'uuid', 'public_key': 'public', 'short_id': 'abcd'}, 2080)
        self.assertEqual([o['type'] for o in config['outbounds']], ['vless'])
        self.assertEqual(config['route']['final'], 'probe')
        self.assertNotIn('private_key', json.dumps(config))


if __name__ == '__main__':
    unittest.main()
