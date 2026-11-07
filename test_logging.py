import errno
import os
from pathlib import Path
import pty
import subprocess
import tempfile
import unittest

BASE = Path(__file__).resolve().parent


class LoggingTests(unittest.TestCase):
    def render(self, terminal, no_color=False, term='xterm-256color'):
        environment = dict(os.environ, TERM=term)
        environment.pop('NO_COLOR', None)
        if no_color:
            environment['NO_COLOR'] = ''
        with tempfile.TemporaryDirectory() as directory:
            logfile = Path(directory) / 'installer.log'
            script = '''
set -Eeuo pipefail
source "$1/logging.sh"
{
    log 'Default message'
    log SUCCESS 'Connection verified'
    log WARN 'Optional step skipped'
    log ERROR 'Connection failed'
    banner 'Checking services'
    banner 'ERROR | Checking services'
    banner 'DONE | Installation completed'
    printf 'External command output\n'
} | tee "$2" | colorize_output
'''
            command = ['bash', '-c', script, 'test', str(BASE), str(logfile)]
            if terminal:
                master, slave = pty.openpty()
                try:
                    process = subprocess.Popen(command, stdout=slave, stderr=subprocess.PIPE, env=environment)
                    os.close(slave)
                    slave = None
                    output = bytearray()
                    while True:
                        try:
                            chunk = os.read(master, 4096)
                        except OSError as error:
                            if error.errno == errno.EIO:
                                break
                            raise
                        if not chunk:
                            break
                        output.extend(chunk)
                finally:
                    os.close(master)
                    if slave is not None:
                        os.close(slave)
                _, stderr = process.communicate(timeout=10)
                result = subprocess.CompletedProcess(command, process.returncode, stderr=stderr)
                output = bytes(output).replace(b'\r\n', b'\n')
            else:
                result = subprocess.run(command, capture_output=True, env=environment)
                output = result.stdout
            self.assertEqual(result.returncode, 0, result.stderr)
            saved = logfile.read_bytes()
            self.assertNotIn(b'\x1b', saved)
            return output, saved

    def test_terminal_has_all_colors_but_log_is_plain(self):
        output, saved = self.render(terminal=True)
        for code in (31, 32, 33, 36):
            self.assertIn(f'\x1b[1;{code}m'.encode(), output)
        for level in ('INFO', 'SUCCESS', 'WARN', 'ERROR'):
            self.assertIn(f'[{level}]'.encode(), saved)
        self.assertIn(b'\x1b[1;31m  ERROR | Checking services', output)
        self.assertIn(b'\x1b[1;32m  DONE | Installation completed', output)
        self.assertTrue(output.endswith(b'External command output\n'))

    def test_pipe_has_no_color(self):
        output, saved = self.render(terminal=False)
        self.assertEqual(output, saved)

    def test_no_color_disables_terminal_colors_even_when_empty(self):
        output, saved = self.render(terminal=True, no_color=True)
        self.assertEqual(output, saved)

    def test_dumb_terminal_has_no_color(self):
        output, saved = self.render(terminal=True, term='dumb')
        self.assertEqual(output, saved)


if __name__ == '__main__':
    unittest.main()
