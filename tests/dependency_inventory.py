#!/usr/bin/env python3
"""Record the actual Ubuntu VM used by the release integration test."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess


BINARY_COMMANDS = {
    'sing-box': ('sing-box', 'version'),
    'unbound': ('unbound', '-V'),
    'fail2ban': ('fail2ban-client', '--version'),
    'ufw': ('ufw', '--version'),
    'python3': ('python3', '--version'),
    'bash': ('bash', '--version'),
    'openssl': ('openssl', 'version', '-a'),
    'curl': ('curl', '--version'),
    'dig': ('dig', '-v'),
    'ip': ('ip', '-V'),
    'qrencode': ('qrencode', '--version'),
    'sshd': ('sshd', '-V'),
    'systemd': ('systemctl', '--version'),
    'iptables': ('iptables', '--version'),
    'nftables': ('nft', '--version'),
}


def command_output(arguments):
    return subprocess.run(arguments, check=True, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, env={**os.environ, 'LC_ALL': 'C'}).stdout.strip()


def parse_os_release(source):
    values = {}
    for line in source.splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, raw = line.partition('=')
        if not separator or not key:
            raise ValueError('Malformed os-release entry')
        parts = shlex.split(raw, comments=False)
        if len(parts) > 1:
            raise ValueError('Malformed os-release value: ' + key)
        values[key] = parts[0] if parts else ''
    return values


def parse_packages(source):
    packages = []
    seen = set()
    for line in source.splitlines():
        name, version, architecture, status = line.split('\t')
        if status != 'installed':
            continue
        if not name or not version or not architecture or name in seen:
            raise ValueError('Invalid or duplicate dpkg inventory entry: ' + name)
        seen.add(name)
        packages.append({'name': name, 'version': version, 'architecture': architecture})
    return sorted(packages, key=lambda item: item['name'])


def direct_inventory(lock, packages):
    expected = {}
    for group in ('common', 'host', 'engine'):
        for name, version in lock['packages'][group].items():
            if name in expected:
                raise ValueError('Duplicate direct dependency in lock: ' + name)
            expected[name] = version
    installed = {item['name']: item for item in packages}
    direct = {}
    for name, version in sorted(expected.items()):
        package = installed.get(name)
        if package is None or package['version'] != version:
            actual = package['version'] if package else 'missing'
            raise ValueError(f'Inventory disagrees with lock: {name}: expected {version}, found {actual}')
        direct[name] = {key: package[key] for key in ('version', 'architecture')}
    return direct


def collect(lock_path):
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes)
    version = lock_path.with_name('VERSION').read_text().strip()
    if version != lock['release']:
        raise ValueError('VERSION and dependency lock disagree')
    os_release = parse_os_release(Path('/etc/os-release').read_text())
    architecture = command_output(['dpkg', '--print-architecture'])
    if (os_release.get('ID'), os_release.get('VERSION_ID'), architecture) != ('ubuntu', '24.04', 'amd64'):
        raise ValueError('This integration inventory covers only Ubuntu 24.04 amd64 VM')
    packages = parse_packages(command_output([
        'dpkg-query', '--show',
        '--showformat=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n',
    ]))
    direct = direct_inventory(lock, packages)
    binaries = {}
    for name, command in BINARY_COMMANDS.items():
        path = shutil.which(command[0])
        if path is None:
            binaries[name] = {'present': False}
            continue
        result = subprocess.run([path, *command[1:]], check=False, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env={**os.environ, 'LC_ALL': 'C'})
        binaries[name] = {'path': path, 'resolved_path': str(Path(path).resolve()),
                          'arguments': list(command[1:]), 'exit_code': result.returncode,
                          'output': result.stdout.strip()}
    engine_path = Path(binaries['sing-box']['resolved_path'])
    with engine_path.open('rb') as stream:
        engine_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {
        'schema': 1,
        'scope': 'ubuntu-24.04-amd64-vm',
        'captured_at': datetime.now(timezone.utc).isoformat(),
        'captured_after': 'first_install',
        'release': version,
        'lock_sha256': hashlib.sha256(lock_bytes).hexdigest(),
        'lock': lock,
        'os_release': os_release,
        'architecture': architecture,
        'kernel': command_output(['uname', '-srmo']),
        'direct_packages': direct,
        'packages': packages,
        'binaries': binaries,
        'sing_box_sha256': engine_sha256,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, required=True)
    args = parser.parse_args()
    try:
        inventory = collect(args.lock)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Cannot collect release dependency inventory: {error}\n')
    print(json.dumps(inventory, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
