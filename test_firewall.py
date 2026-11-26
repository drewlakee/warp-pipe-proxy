from pathlib import Path
import subprocess
import unittest


BASE = Path(__file__).resolve().parent
INSTALLER = (BASE / 'warp-pipe-proxy.sh').read_text()
START = INSTALLER.index('configure_firewall() {')
CONFIGURE_FIREWALL = INSTALLER[START:INSTALLER.index('\n}\n', START) + 3]


class FirewallTests(unittest.TestCase):
    def shell(self, body, setup=''):
        # All firewall and listener commands are replaced. These tests never
        # inspect or change the host firewall, packages, services or sockets.
        return subprocess.run(['bash', '-c', f'''
set -Eeuo pipefail
source "{BASE}/runtime.sh"
log() {{ echo "$*"; }}
stage() {{ echo "$*"; }}
read_setting() {{ echo 10443; }}
iptables-save() {{ printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' ':FORWARD ACCEPT [0:0]' ':OUTPUT ACCEPT [0:0]' 'COMMIT'; }}
ip6tables-save() {{ iptables-save; }}
nft() {{ echo '{{"nftables":[{{"metainfo":{{}}}},{{"table":{{"family":"ip","name":"filter"}}}},{{"chain":{{"hook":"input","policy":"accept"}}}}]}}'; }}
ufw() {{
    case "$*" in
        status) echo 'Status: inactive';;
        'show added') echo "Added user rules (see 'ufw status' for running firewall):";;
        *) echo "MUTATION: $*";;
    esac
}}
ss() {{ :; }}
SSH_PORTS=$'22\\n2222'
ROOT=/nonexistent-firewall-test
{CONFIGURE_FIREWALL}
{setup}
{body}
'''], text=True, capture_output=True)

    def test_active_ufw_keeps_all_rules_and_policies(self):
        result = self.shell('configure_firewall; echo "changed=$FIREWALL_CHANGED"', '''
ufw() { echo "UFW: $*" >&2; [[ $* == status ]] || return 99; echo 'Status: active'; }
iptables-save() { echo UNEXPECTED; return 98; }
ip6tables-save() { echo UNEXPECTED; return 98; }
nft() { echo UNEXPECTED; return 98; }
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Existing active UFW preserved', result.stdout)
        self.assertIn('Allow inbound TCP 10443', result.stdout)
        self.assertIn('changed=0', result.stdout)
        self.assertEqual(result.stderr.splitlines(), ['UFW: status'])
        self.assertNotIn('UNEXPECTED', result.stdout)

    def test_empty_policy_bootstraps_ssh_proxy_then_enables_ufw(self):
        result = self.shell('configure_firewall; echo "changed=$FIREWALL_CHANGED; previous=$UFW_ACTIVE"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([line for line in result.stdout.splitlines() if line.startswith('MUTATION:')], [
            'MUTATION: allow 22/tcp comment warp-pipe-proxy SSH preservation',
            'MUTATION: allow 2222/tcp comment warp-pipe-proxy SSH preservation',
            'MUTATION: allow 10443/tcp comment warp-pipe-proxy Reality',
            'MUTATION: default deny incoming',
            'MUTATION: default allow outgoing',
            'MUTATION: --force enable',
        ])
        self.assertIn('changed=1; previous=no', result.stdout)

    def test_disabled_preconfigured_ufw_is_not_activated(self):
        result = self.shell('configure_firewall', '''
ufw() {
    case "$*" in
        status) echo 'Status: inactive';;
        'show added') echo 'ufw allow from 192.0.2.1 to any port 22 proto tcp';;
        *) echo MUTATION;;
    esac
}
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('disabled but has saved user rules', result.stdout)
        self.assertNotIn('MUTATION', result.stdout)

    def test_changed_firewall_state_rejects_a_stale_apply_plan(self):
        result = self.shell('UFW_ACTIVE=yes; configure_firewall')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('UFW state changed during installation', result.stdout)
        self.assertNotIn('MUTATION:', result.stdout)

    def test_absent_ufw_still_checks_native_policy(self):
        setup = '''
command() {
    if [[ $* == '-v ufw' ]]; then return 1; fi
    builtin command "$@"
}
ufw() { echo UNEXPECTED; return 99; }
'''
        result = self.shell('firewall_backend_check; echo "previous=$UFW_ACTIVE"', setup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('previous=no', result.stdout)
        self.assertNotIn('UNEXPECTED', result.stdout)
        result = self.shell('firewall_backend_check', setup + '\niptables-save() { echo ":INPUT DROP [0:0]"; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('refusing to enable a competing firewall', result.stdout)

    def test_existing_native_policies_refuse_competing_ufw(self):
        setups = [
            "iptables-save() { printf '%s\\n' ':INPUT DROP [0:0]'; }",
            "ip6tables-save() { printf '%s\\n' '-A INPUT -s 2001:db8::1 -j ACCEPT'; }",
            "iptables-save() { printf '%s\\n' ':MY_CHAIN - [0:0]'; }",
            "nft() { echo '{\"nftables\":[{\"chain\":{\"hook\":\"input\",\"policy\":\"drop\"}}]}'; }",
            "nft() { echo '{\"nftables\":[{\"rule\":{\"chain\":\"input\"}}]}'; }",
        ]
        for setup in setups:
            with self.subTest(setup=setup):
                result = self.shell('configure_firewall', setup)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('refusing to enable a competing firewall', result.stdout)
                self.assertNotIn('MUTATION:', result.stdout)

    def test_firewall_inspection_failure_does_not_initialize(self):
        for setup in ('iptables-save() { return 42; }', 'nft() { return 42; }', 'ufw() { return 42; }'):
            with self.subTest(setup=setup):
                result = self.shell('configure_firewall', setup)
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertNotIn('MUTATION:', result.stdout)

    def test_dhcp_clients_are_safe_but_arbitrary_udp_listeners_are_not(self):
        for owner, port, allowed in [
            ('systemd-network', 68, True), ('systemd-networkd', 546, True),
            ('dhclient', 68, True), ('dhcpcd', 68, True), ('NetworkManager', 68, True),
            ('unrelated', 68, False), ('', 68, False), ('systemd-network', 51820, False),
        ]:
            with self.subTest(owner=owner, port=port):
                metadata = f'users:(("{owner}",pid=123,fd=5))' if owner else ''
                result = self.shell('UFW_ACTIVE=no; protect_listeners', f'''
ss() {{
    if [[ $* == *-lunp* ]]; then
        echo 'UNCONN 0 0 10.0.0.2%eth0:{port} 0.0.0.0:* {metadata}'
    fi
}}
''')
                self.assertEqual(result.returncode == 0, allowed, result.stdout + result.stderr)
                if not allowed:
                    self.assertIn('Unmanaged udp listener', result.stdout)

    def test_container_does_not_inspect_or_mutate_firewall(self):
        result = self.shell('configure_firewall; echo "changed=$FIREWALL_CHANGED"', '''
CONTAINER_MODE=1
ufw() { echo UNEXPECTED; return 99; }
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('changed=0', result.stdout)
        self.assertNotIn('UNEXPECTED', result.stdout)


if __name__ == '__main__':
    unittest.main()
