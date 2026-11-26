"""Report authenticated VLESS requests from the systemd journal."""

from datetime import datetime, timezone
import fcntl
import json
import re
import subprocess
import time

import configure


LOCK = '/run/lock/warp-pipe-proxy.lock'
REQUEST = re.compile(r'\[([^\]]+)\] inbound (?:(packet )?connection to (\S+)|packet addr connection)')


def parse_request(entry):
    message = entry.get('MESSAGE')
    # journalctl represents non-printable fields (including colored logs) as byte arrays.
    if isinstance(message, list):
        message = bytes(message).decode('utf-8', errors='replace')
    if not isinstance(message, str):
        return None
    prefix, _, payload = message.partition(': ')
    if prefix.rsplit(' ', 1)[-1] != 'inbound/vless[vless-reality]':
        return None
    match = REQUEST.fullmatch(payload)
    if not match:
        return None
    name, packet, destination = match.groups()
    if not configure.valid_device_name(name) or (destination and not destination.isprintable()):
        return None
    protocol = 'TCP' if destination and not packet else 'UDP'
    return name, int(entry['__REALTIME_TIMESTAMP']) // 1_000_000, protocol, destination or '-'


def time_ago(seconds):
    seconds = max(0, seconds)
    for size, unit in ((86400, 'd'), (3600, 'h'), (60, 'm')):
        if seconds >= size:
            return f'{seconds // size}{unit} ago'
    return f'{seconds}s ago'


def run(root, device, since, follow):
    # Release the shared installer lock before scanning or following the journal.
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        names = sorted(configure.devices(json.loads((root / 'credentials.json').read_text())))
    if device and device not in names:
        raise ValueError(f'Unknown device: {device}')
    if not names:
        print('No devices registered.')
        return 0

    command = ['journalctl', '-u', 'warp-pipe-proxy', '--no-pager', '-o', 'json', '--output-fields=MESSAGE']
    if follow:
        command += ['--follow', '--no-tail'] if since else ['--follow', '-n', '0']
    if since or not follow:
        command += ['--since', since or '1 hour ago']

    counts = dict.fromkeys(names, 0)
    last_seen = {}
    if device:
        print('TIME (UTC)           PROTOCOL  DESTINATION', flush=True)
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True, encoding='utf-8') as journal:
        try:
            for line in journal.stdout:
                event = parse_request(json.loads(line))
                if event is None:
                    continue
                name, timestamp, protocol, destination = event
                if name not in counts or (device and device != name):
                    continue
                counts[name] += 1
                last_seen[name] = timestamp
                if device:
                    date = datetime.fromtimestamp(timestamp, timezone.utc)
                    print(f'{date:%Y-%m-%d %H:%M:%S}  {protocol:<8}  {destination}', flush=True)
            if journal.wait() != 0:
                return 1
        finally:
            if journal.poll() is None:
                journal.terminate()
    if device:
        if not counts[device]:
            print('No requests in this period.')
    else:
        width = max(len('DEVICE'), *(len(name) for name in names))
        print(f'{"DEVICE":<{width}}  {"LAST ACTIVITY":<13}  REQUESTS')
        now = int(time.time())
        for name in sorted(names, key=lambda name: -last_seen.get(name, -1)):
            last = time_ago(now - last_seen[name]) if name in last_seen else '-'
            print(f'{name:<{width}}  {last:<13}  {counts[name]}')
    return 0
