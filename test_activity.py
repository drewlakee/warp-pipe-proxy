import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import activity
import admin


def entry(payload, second=1, logger='inbound/vless[vless-reality]'):
    return {'MESSAGE': f'+0000 2026-11-26 14:32:08 INFO [42 1ms] {logger}: {payload}',
            '__REALTIME_TIMESTAMP': str(second * 1_000_000)}


class ActivityTests(unittest.TestCase):
    def test_only_authenticated_inbound_requests(self):
        for record in [
            entry('inbound connection from 192.0.2.10:5001'),
            entry('[@probe] inbound connection to example.com:443'),
            entry('[phone] inbound connection to example.com:443', logger='outbound/direct[direct]'),
            entry('error: inbound/vless[vless-reality]: [phone] inbound connection to example.com:443'),
            entry('[phone] inbound connection to example.com\x1b[2J:443'),
            {'MESSAGE': None},
        ]:
            with self.subTest(record=record):
                self.assertIsNone(activity.parse_request(record))
        record = entry('[phone] inbound packet connection to [2001:db8::1]:53')
        record['MESSAGE'] = list(record['MESSAGE'].replace('INFO', '\x1b[36mINFO\x1b[0m').encode())
        self.assertEqual(activity.parse_request(record), ('phone', 1, 'UDP', '[2001:db8::1]:53'))
        self.assertEqual(activity.parse_request(entry('[phone] inbound packet addr connection')),
                         ('phone', 1, 'UDP', '-'))

    def report(self, arguments, entries, credentials, exit_code=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'credentials.json').write_text(json.dumps(credentials))
            output = io.StringIO()
            with patch.object(admin, 'ROOT', root), patch.object(activity, 'LOCK', root / 'lock'), \
                    patch('sys.argv', ['warp-pipe-proxy', 'activity', *arguments]), \
                    patch.object(activity.time, 'time', return_value=80), \
                    patch.object(activity.subprocess, 'Popen') as launch, contextlib.redirect_stdout(output):
                process = launch.return_value.__enter__.return_value
                process.stdout = io.StringIO(''.join(json.dumps(e) + '\n' for e in entries))
                process.wait.return_value = exit_code
                rc = admin.main()
                return rc, output.getvalue(), launch.call_args.args[0] if launch.called else []

    def test_summary_counts_and_orders_devices_without_destinations(self):
        entries = [entry('[old] inbound connection to secret.example:80', 1),
                   entry('[phone] inbound connection to 192.0.2.10:80', 3),
                   entry('[phone] inbound packet connection to dns.example:53', 74),
                   entry('[@probe] inbound connection to secret.example:443', 79)]
        rc, output, cmd = self.report([], entries, {'devices': {'old': None, 'idle': 'i', 'phone': 'p'}})
        self.assertEqual(rc, 0)
        self.assertEqual([line.split() for line in output.splitlines()],
                         [['DEVICE', 'LAST', 'ACTIVITY', 'REQUESTS'], ['phone', '6s', 'ago', '2'],
                          ['old', '1m', 'ago', '1'], ['idle', '-', '0']])
        self.assertEqual(cmd[-2:], ['--since', '1 hour ago'])

    def test_device_history_includes_only_exact_name(self):
        entries = [entry('[default2] inbound connection to wrong.example:443'),
                   entry('[default] inbound connection to example.com:443')]
        rc, output, cmd = self.report(['--device', 'default', '--since', 'yesterday', '--follow'],
                                      entries, {'uuid': 'legacy'})
        self.assertEqual(rc, 0)
        self.assertEqual(output.splitlines()[-1].split(), ['1970-01-01', '00:00:01', 'TCP', 'example.com:443'])
        self.assertEqual(len(output.splitlines()), 2)
        self.assertEqual(cmd[-4:], ['--follow', '--no-tail', '--since', 'yesterday'])

    def test_follow_defaults_to_new_events_and_journal_errors_fail(self):
        rc, output, cmd = self.report(['--device', 'phone', '--follow'], [], {'devices': {'phone': 'p'}}, 1)
        self.assertEqual(rc, 1)
        self.assertNotIn('No requests', output)
        self.assertEqual(cmd[-3:], ['--follow', '-n', '0'])

    def test_empty_registry_and_unknown_device(self):
        self.assertEqual(self.report([], [], {'devices': {}}), (0, 'No devices registered.\n', []))
        with self.assertRaisesRegex(ValueError, 'Unknown device: tablet'):
            self.report(['--device', 'tablet'], [], {'devices': {}})
        _, output, _ = self.report(['--device', 'phone'], [], {'devices': {'phone': None}})
        self.assertIn('No requests in this period.', output)

    def test_rejects_unsupported_options(self):
        for args in [['--follow'], ['--filter', 'secret'], ['--device', '@probe']]:
            with self.subTest(args=args), self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                admin.parse_args(['activity', *args])
