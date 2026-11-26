import contextlib
import io
import shlex
import subprocess
import unittest

import uninstall_firewall as firewall


def rule(port, comment=firewall.COMMENT):
    return ('ufw', 'allow', f'{port}/tcp', 'comment', comment)


class FakeUfw:
    def __init__(self, rules=(), ssh='port 22\n', active=True):
        # Entries model separate saved IPv4 and IPv6 rules. show-added
        # deduplicates command strings exactly as upstream UFW does.
        self.rules = list(rules)
        self.ssh = ssh
        self.active = active
        self.calls = []
        self.report_override = None
        self.inspections = 0
        self.before_inspect = None
        self.delete_error = False
        self.noop_delete = False
        self.ssh_error = False

    def __call__(self, command, **options):
        self.calls.append(command)
        if options.get('env', {}).get('LC_ALL') != 'C':
            raise AssertionError('UFW inspection must use stable English output')
        if command == ['ufw', 'show', 'added']:
            self.inspections += 1
            if self.before_inspect is not None:
                self.before_inspect(self)
            if self.report_override is not None:
                return subprocess.CompletedProcess(command, 0, self.report_override)
            unique = list(dict.fromkeys(value for _, value in self.rules))
            text = firewall.HEADER + '\n' + ('\n'.join(shlex.join(value) for value in unique) if unique else '(None)')
            return subprocess.CompletedProcess(command, 0, text)
        if command == ['/usr/sbin/sshd', '-T']:
            if self.ssh_error:
                raise subprocess.CalledProcessError(1, command)
            return subprocess.CompletedProcess(command, 0, self.ssh)
        if command[:3] == ['ufw', '--force', 'delete']:
            if self.delete_error:
                raise subprocess.CalledProcessError(1, command)
            target = ('ufw', *command[3:])
            if not self.noop_delete:
                self.rules = [(family, value) for family, value in self.rules if value != target]
            return subprocess.CompletedProcess(command, 0, 'Rule deleted\n')
        raise AssertionError(f'Unexpected firewall mutation or command: {command}')

    @property
    def deletions(self):
        return [command for command in self.calls if command[:3] == ['ufw', '--force', 'delete']]


class UninstallFirewallTests(unittest.TestCase):
    def test_active_and_inactive_saved_policies_remove_both_families_and_old_ports(self):
        for active in (False, True):
            with self.subTest(active=active):
                preserved = [
                    ('v4', rule(22, 'warp-pipe-proxy SSH preservation')),
                    ('v6', rule(22, 'warp-pipe-proxy SSH preservation')),
                    ('v6', rule(10443, 'administrator-owned IPv6')),
                    ('v4', ('ufw', 'allow', 'from', '192.0.2.1', 'to', 'any', 'port', '22')),
                ]
                fake = FakeUfw([('v4', rule(10443)), ('v4', rule(15443)), ('v6', rule(15443)), *preserved], active=active)
                self.assertEqual(firewall.remove_proxy_rules(fake), 2)
                self.assertEqual(fake.rules, preserved)
                self.assertEqual(fake.active, active)
                self.assertEqual(fake.deletions, [
                    ['ufw', '--force', 'delete', *rule(10443)[1:]],
                    ['ufw', '--force', 'delete', *rule(15443)[1:]],
                ])
                self.assertEqual(firewall.remove_proxy_rules(fake), 0)

    def test_admin_relabelled_or_unlabelled_rules_remain_without_reading_ssh(self):
        entries = [('v4', rule(10443, 'administrator')), ('v6', ('ufw', 'allow', '10443/tcp')),
                   ('v4', rule(22, 'warp-pipe-proxy SSH preservation'))]
        fake = FakeUfw(entries)
        fake.ssh_error = True
        self.assertEqual(firewall.remove_proxy_rules(fake), 0)
        self.assertEqual(fake.rules, entries)
        self.assertEqual(fake.calls, [['ufw', 'show', 'added']])

    def test_modified_shape_with_old_label_is_preserved_with_warning(self):
        modified = [
            ('ufw', 'allow', 'from', '192.0.2.1', 'to', 'any', 'port', '10443', 'proto', 'tcp', 'comment', firewall.COMMENT),
            ('ufw', 'allow', 'out', '10443/tcp', 'comment', firewall.COMMENT),
            ('ufw', 'allow', '10443/udp', 'comment', firewall.COMMENT),
            ('ufw', 'route', 'allow', '10443/tcp', 'comment', firewall.COMMENT),
            ('ufw', 'deny', '10443/tcp', 'comment', firewall.COMMENT),
        ]
        entries = [('v4', value) for value in modified]
        fake = FakeUfw(entries)
        with contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(firewall.remove_proxy_rules(fake), 0)
        self.assertEqual(fake.rules, entries)
        self.assertEqual(output.getvalue().count('Preserved modified UFW rule'), len(modified))
        self.assertFalse(fake.deletions)

    def test_current_ssh_ports_are_preserved_including_former_proxy_port(self):
        kept = [('v4', rule(22)), ('v6', rule(10443))]
        fake = FakeUfw([*kept, ('v4', rule(15443))], ssh='port 22\nport 10443\naddressfamily any\n')
        with contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(firewall.remove_proxy_rules(fake), 1)
        self.assertEqual(fake.rules, kept)
        self.assertIn('TCP 22', output.getvalue())
        self.assertIn('TCP 10443', output.getvalue())

    def test_malformed_or_ambiguous_reports_fail_before_any_delete(self):
        own = shlex.join(rule(10443))
        for report in ('', 'Status: inactive', firewall.HEADER, firewall.HEADER + '\n(None)\n' + own,
                       firewall.HEADER + '\n' + own + '\n' + own,
                       firewall.HEADER + "\nufw allow 10443/tcp comment 'unterminated"):
            with self.subTest(report=report):
                fake = FakeUfw([('v4', rule(10443))])
                fake.report_override = report
                with self.assertRaises(ValueError):
                    firewall.remove_proxy_rules(fake)
                self.assertFalse(fake.deletions)

    def test_missing_or_invalid_ssh_config_aborts_before_any_delete(self):
        for configuration in ('', 'port bogus', 'port 0', 'port 65536', 'port 22 extra'):
            with self.subTest(configuration=configuration):
                fake = FakeUfw([('v4', rule(10443))], ssh=configuration)
                with self.assertRaisesRegex(ValueError, 'SSH ports'):
                    firewall.remove_proxy_rules(fake)
                self.assertFalse(fake.deletions)
        fake = FakeUfw([('v4', rule(10443))])
        fake.ssh_error = True
        with self.assertRaises(subprocess.CalledProcessError):
            firewall.remove_proxy_rules(fake)
        self.assertFalse(fake.deletions)

    def test_ufw_inspection_errors_are_not_treated_as_empty_policy(self):
        for error in (FileNotFoundError('ufw'), subprocess.CalledProcessError(1, ['ufw']),
                      subprocess.TimeoutExpired(['ufw'], 30)):
            with self.subTest(error=error):
                calls = []

                def fail(command, **options):
                    calls.append(command)
                    raise error

                with self.assertRaises(type(error)):
                    firewall.remove_proxy_rules(fail)
                self.assertEqual(calls, [['ufw', 'show', 'added']])

    def test_concurrent_policy_change_is_detected_before_delete(self):
        fake = FakeUfw([('v4', rule(10443))])

        def take_over(current):
            if current.inspections == 2:
                current.rules = [('v4', rule(10443, 'administrator takeover'))]

        fake.before_inspect = take_over
        with self.assertRaisesRegex(ValueError, 'policy changed'):
            firewall.remove_proxy_rules(fake)
        self.assertFalse(fake.deletions)
        self.assertEqual(fake.rules, [('v4', rule(10443, 'administrator takeover'))])

    def test_unsuccessful_or_unverified_deletion_stops_cleanup(self):
        for fail in (True, False):
            with self.subTest(fail=fail):
                fake = FakeUfw([('v4', rule(10443)), ('v4', rule(15443))])
                fake.delete_error = fail
                fake.noop_delete = not fail
                with self.assertRaises(subprocess.CalledProcessError if fail else ValueError):
                    firewall.remove_proxy_rules(fake)
                self.assertEqual(len(fake.deletions), 1)
                self.assertEqual(len(fake.rules), 2)

    def test_header_with_no_rules_is_supported(self):
        fake = FakeUfw()
        self.assertEqual(firewall.remove_proxy_rules(fake), 0)
        self.assertEqual(fake.calls, [['ufw', 'show', 'added']])


if __name__ == '__main__':
    unittest.main()
