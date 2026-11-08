import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time


def client_config(settings, credentials, port):
    return {
        'log': {'level': 'error'},
        'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': port}],
        'outbounds': [{
            'type': 'vless', 'tag': 'probe', 'server': '127.0.0.1',
            'server_port': settings['vless_port'], 'uuid': credentials['uuid'],
            'flow': 'xtls-rprx-vision',
            'tls': {'enabled': True, 'server_name': settings['reality_host'],
                    'utls': {'enabled': True, 'fingerprint': 'chrome'},
                    'reality': {'enabled': True, 'public_key': credentials['public_key'],
                                'short_id': credentials['short_id']}}
        }],
        'route': {'final': 'probe'}
    }


def owns_port(port):
    config = json.loads(Path('/etc/sing-box/config.json').read_text())
    if not any(i.get('listen_port') == int(port) for i in config['inbounds']):
        return False
    pid = subprocess.check_output(
        ['systemctl', 'show', '-p', 'MainPID', '--value', 'warp-pipe-proxy'], text=True).strip()
    if not pid.isdigit() or int(pid) == 0:
        return False
    listeners = subprocess.check_output(['ss', '-H', '-ltnp', 'sport', '=', ':' + port], text=True)
    lines = listeners.splitlines()
    return bool(lines) and all(re.search(r'pid=' + pid + r',', line) for line in lines)


def probe(root, url='https://example.com', diagnostic=False):
    settings = json.loads((root / 'settings.json').read_text())
    credentials = json.loads((root / 'credentials.json').read_text())
    with tempfile.TemporaryDirectory(prefix='vps-reality-probe-') as directory:
        path = Path(directory) / 'client.json'
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        path.write_text(json.dumps(client_config(settings, credentials, port)))
        path.chmod(0o600)
        subprocess.run(['sing-box', 'check', '-c', str(path)], check=True, timeout=15)
        with open(Path(directory) / 'client.log', 'w+') as output:
            process = subprocess.Popen(['sing-box', 'run', '-c', str(path)], stdout=output, stderr=output)
            try:
                for _ in range(50):
                    if process.poll() is not None:
                        raise RuntimeError('Temporary VLESS client exited before becoming ready')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError('Temporary VLESS client did not become ready')
                subprocess.run([
                    'curl', '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{port}',
                    *([] if diagnostic else ['--fail']),
                    '--silent', '--show-error', '--connect-timeout', '5', '--max-time', '20',
                    '--write-out', 'HTTP %{http_code}; downloaded %{size_download} bytes\n',
                    url, '-o', os.devnull
                ], check=True, timeout=35)
                if process.poll() is not None:
                    raise RuntimeError('Temporary VLESS client exited during probe')
                print('VLESS Reality authenticated HTTPS request passed' if not diagnostic
                      else 'VLESS transport passed; inspect the HTTP status above')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'owns-port':
        sys.exit(0 if owns_port(sys.argv[2]) else 1)
    probe(Path('/etc/warp-pipe-proxy'))
