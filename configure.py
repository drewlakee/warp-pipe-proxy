import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import uuid
from urllib.parse import urlencode


def write(path, value):
    temp = path.with_suffix(path.suffix + '.tmp')
    with temp.open('w', encoding='utf-8') as f:
        os.chmod(temp, 0o600)
        f.write(value if isinstance(value, str) else json.dumps(value, indent=2) + '\n')
    temp.replace(path)


def validate(settings, credentials):
    if not ipaddress.IPv4Address(settings['public_ip']).is_global:
        raise ValueError('public_ip must be a public IPv4 address')
    host = settings['reality_host']
    if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}', host):
        raise ValueError('Invalid reality_host')
    ports = [settings['vless_port'], settings['dns_port']]
    if any(type(p) is not int or not 1024 <= p <= 65535 for p in ports) or len(set(ports)) != 2:
        raise ValueError('Proxy and DNS ports must be distinct integers in 1024..65535')
    uuid.UUID(credentials['uuid'])
    for key, size in [('short_id', 8)]:
        if not re.fullmatch('[0-9a-f]{' + str(size) + '}', credentials[key]):
            raise ValueError('Invalid ' + key)
    for key in ('private_key', 'public_key'):
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}=?', credentials[key]):
            raise ValueError('Invalid Reality key encoding')


def render(s, c):
    return {
        'log': {'level': 'info', 'timestamp': True},
        'dns': {'servers': [{'type': 'tcp', 'tag': 'unbound', 'server': '127.0.0.1',
                            'server_port': s['dns_port']}], 'final': 'unbound'},
        'route': {'final': 'direct', 'default_domain_resolver': {'server': 'unbound', 'strategy': 'prefer_ipv4'}},
        'inbounds': [
            {'type': 'vless', 'tag': 'vless-reality', 'listen': '0.0.0.0', 'listen_port': s['vless_port'],
             'users': [{'uuid': c['uuid'], 'flow': 'xtls-rprx-vision'}],
             'tls': {'enabled': True, 'server_name': s['reality_host'], 'min_version': '1.3',
                     'reality': {'enabled': True, 'handshake': {'server': s['reality_host'], 'server_port': 443},
                                 'private_key': c['private_key'], 'short_id': [c['short_id']]}}}
        ], 'outbounds': [{'type': 'direct', 'tag': 'direct'}]
    }


def render_client(settings, credentials):
    # Клиент получает только публичный ключ; приватный остаётся на сервере.
    return {
        'log': {'level': 'info', 'timestamp': True},
        'dns': {
            'servers': [{'type': 'https', 'tag': 'dns-proxy', 'server': '1.1.1.1',
                         'detour': 'proxy'}],
            'final': 'dns-proxy'
        },
        'inbounds': [{'type': 'tun', 'tag': 'tun-in',
                      'address': ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
                      'auto_route': True, 'strict_route': True}],
        'outbounds': [{
            'type': 'vless', 'tag': 'proxy', 'server': settings['public_ip'],
            'server_port': settings['vless_port'], 'uuid': credentials['uuid'],
            'flow': 'xtls-rprx-vision',
            'tls': {'enabled': True, 'server_name': settings['reality_host'],
                    'utls': {'enabled': True, 'fingerprint': 'chrome'},
                    'reality': {'enabled': True, 'public_key': credentials['public_key'],
                                'short_id': credentials['short_id']}}
        }],
        'route': {
            'auto_detect_interface': True,
            'rules': [{'action': 'sniff'}, {'protocol': 'dns', 'action': 'hijack-dns'}],
            'final': 'proxy'
        }
    }


def remove_legacy_socks_rules():
    # Удаляем только правила с нашей точной меткой, сохраняя чужие разрешения на тот же порт.
    output = subprocess.check_output(['ufw', 'show', 'added'], text=True)
    for line in output.splitlines():
        args = shlex.split(line)
        if args[:2] == ['ufw', 'allow'] and args[-2:] == ['comment', 'warp-pipe-proxy SOCKS']:
            subprocess.run(['ufw', '--force', 'delete', *args[1:]], check=True)


def render_vless_link(settings, credentials):
    host = settings['public_ip']
    if ':' in host:
        host = '[' + host + ']'
    return f"vless://{credentials['uuid']}@{host}:{settings['vless_port']}?" + urlencode({
        'encryption': 'none', 'flow': 'xtls-rprx-vision', 'security': 'reality',
        'sni': settings['reality_host'], 'fp': 'chrome', 'pbk': credentials['public_key'],
        'sid': credentials['short_id'], 'type': 'tcp'}) + '#vps-reality'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['init', 'render', 'render-rotated', 'get', 'summary', 'client-profile', 'remove-legacy-socks-rules'])
    parser.add_argument('--root', type=Path, default=Path('/etc/warp-pipe-proxy'))
    parser.add_argument('--out', type=Path)
    parser.add_argument('--key')
    args = parser.parse_args()
    if args.action == 'remove-legacy-socks-rules':
        remove_legacy_socks_rules()
        return
    root = args.root
    if args.action == 'init':
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not (root / 'settings.json').exists():
            write(root / 'settings.json', {'public_ip': os.environ['VPS_PUBLIC_IP'],
                'reality_host': os.environ['VPS_REALITY_HOST'],
                'vless_port': 10443, 'dns_port': 5353})
        if not (root / 'credentials.json').exists():
            if (root / 'installed').exists():
                raise ValueError('Credentials are missing; restore backup instead of rotating silently')
            output = subprocess.check_output(['sing-box', 'generate', 'reality-keypair'], text=True)
            keys = dict(re.findall(r'(PrivateKey|PublicKey):\s*(\S+)', output))
            write(root / 'credentials.json', {'uuid': str(uuid.uuid4()),
                'short_id': secrets.token_hex(4), 'private_key': keys['PrivateKey'], 'public_key': keys['PublicKey']})
    s = json.loads((root / 'settings.json').read_text())
    c = json.loads((root / 'credentials.json').read_text())
    validate(s, c)
    if args.action == 'render-rotated':
        output = subprocess.check_output(['sing-box', 'generate', 'reality-keypair'], text=True)
        keys = dict(re.findall(r'(PrivateKey|PublicKey):\s*(\S+)', output))
        c = {'uuid': str(uuid.uuid4()), 'short_id': secrets.token_hex(4),
             'private_key': keys['PrivateKey'], 'public_key': keys['PublicKey']}
        validate(s, c)
    if args.action == 'client-profile':
        print(json.dumps(render_client(s, c), indent=2))
    elif args.action == 'get':
        print(s[args.key])
    elif args.action == 'summary':
        print(json.dumps(s, indent=2))
    elif args.action in ('render', 'render-rotated'):
        args.out.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Удаление старых полей применяется установщиком только после снимка отката.
        write(args.out / 'settings.json', {k: v for k, v in s.items() if k not in ('socks_port', 'socks_user')})
        write(args.out / 'credentials.json', {k: v for k, v in c.items() if k != 'socks_password'})
        write(args.out / 'config.json', render(s, c))
        write(args.out / 'client-sing-box.json', render_client(s, c))
        write(args.out / 'unbound.conf', f'''server:
  interface: 127.0.0.1
  port: {s['dns_port']}
  do-ip6: no
  access-control: 127.0.0.0/8 allow
  hide-identity: yes
  hide-version: yes
  qname-minimisation: yes
  harden-dnssec-stripped: yes
  edns-buffer-size: 1232
  prefetch: yes
  msg-cache-size: 32m
  rrset-cache-size: 64m
  num-threads: 1
''')
        vless = render_vless_link(s, c)
        write(args.out / 'clients.txt', 'VLESS Reality:\n' + vless + '\n')


if __name__ == '__main__':
    main()
