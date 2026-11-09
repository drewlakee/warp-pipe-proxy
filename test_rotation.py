import os
from pathlib import Path
import subprocess
import tempfile
import unittest

BASE = Path(__file__).resolve().parent


class RotationTests(unittest.TestCase):
    def test_rotation_success_and_probe_failure_rollback(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = root / 'etc/warp-pipe-proxy'
                config.mkdir(parents=True)
                (root / 'etc/sing-box').mkdir()
                paths = [config / name for name in ('credentials.json', 'clients.txt', 'client-sing-box.json')]
                paths.append(root / 'etc/sing-box/config.json')
                for path in paths:
                    path.write_text('old')
                (config / 'installed').touch()
                (config / 'settings.json').write_text('unchanged')
                runtime = (BASE / 'runtime.sh').read_text()
                runtime = runtime.replace('/etc/', directory + '/etc/').replace('/var/lib/', directory + '/var/lib/')
                script = root / 'runtime.sh'
                script.write_text(runtime)
                result = subprocess.run(['bash', '-c', f'''
set -Eeuo pipefail
umask 077
source "{script}"
ROOT="{config}"
BASE="{BASE}"
MODE=rotate-keys
RUN=test
log() {{ echo "$*"; }}
stage() {{ echo "$*"; }}
systemctl() {{
 echo "$*" >> "{root}/services"
 case "$1" in is-active) echo active;; is-enabled) echo enabled;; esac
}}
sing-box() {{ return 0; }}
install() {{
 local args=()
 while (( $# )); do
   case "$1" in -o|-g) shift 2;; *) args+=("$1"); shift;; esac
 done
 command install "${{args[@]}}"
}}
python3() {{
 if [[ $1 == */probe.py ]]; then return {1 if fail else 0}; fi
 for name in credentials.json config.json client-sing-box.json clients.txt; do
   echo new > "$STAGE/$name"
 done
}}
rotate_keys
'''], capture_output=True, text=True)
                self.assertEqual(result.returncode, 1 if fail else 0, result.stderr)
                for path in paths:
                    self.assertEqual(path.read_text().strip(), 'old' if fail else 'new')
                self.assertEqual((config / 'settings.json').read_text(), 'unchanged')
                services = (root / 'services').read_text()
                self.assertNotIn('unbound', services)
                self.assertNotIn('fail2ban', services)
                self.assertIn('restart warp-pipe-proxy', services)
                if fail:
                    self.assertIn('restored', result.stdout)


if __name__ == '__main__':
    unittest.main()
