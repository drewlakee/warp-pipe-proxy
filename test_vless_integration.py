import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
sys.path.insert(0, str(Path(__file__).resolve().parent))
BASE = Path(__file__).resolve().parent
import configure
import probe

def main():
    os.environ.update(VPS_PUBLIC_IP='8.8.8.8', VPS_REALITY_HOST='www.microsoft.com')
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        subprocess.run(['python3', str(BASE / 'configure.py'), 'init', '--root', directory], check=True)
        settings = json.loads((root / 'settings.json').read_text())
        credentials = json.loads((root / 'credentials.json').read_text())
        config = configure.render(settings, credentials)
        config['dns']['servers'] = [{'type': 'local', 'tag': 'unbound'}]
        path = root / 'server.json'
        path.write_text(json.dumps(config))
        subprocess.run(['sing-box', 'check', '-c', str(path)], check=True)
        with (root / 'server.log').open('w') as output:
            server = subprocess.Popen(['sing-box', 'run', '-c', str(path)], stdout=output, stderr=output)
            try:
                time.sleep(1)
                probe.probe(root)
                credentials['uuid'] = '00000000-0000-4000-8000-000000000001'
                (root / 'credentials.json').write_text(json.dumps(credentials))
                try:
                    probe.probe(root)
                except subprocess.CalledProcessError:
                    print('PASS: incorrect VLESS UUID rejected')
                else:
                    raise AssertionError('Incorrect UUID unexpectedly passed')
            finally:
                server.terminate()
                server.wait(timeout=5)


if __name__ == '__main__':
    main()
