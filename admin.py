import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit

import configure
import probe

ROOT = Path('/etc/warp-pipe-proxy')


def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog='warp-pipe-proxy.sh', description='Warp Pipe Proxy: install, inspect and troubleshoot VLESS Reality')
    parser.add_argument('command', choices=['install', 'check', 'status', 'doctor', 'logs', 'client-config', 'client-profile', 'rotate-keys'])
    parser.add_argument('--container', action='store_true', help='Do not manage host firewall or fail2ban')
    parser.add_argument('--url', help='HTTP(S) site to compare directly and through VLESS; no redirects followed')
    parser.add_argument('--endpoint', help='Override client server IP (including private LAN IP); does not change server settings')
    parser.add_argument('--port', type=int, help='Override published client port')
    parser.add_argument('--follow', action='store_true', help='Follow new journal entries')
    parser.add_argument('--since', help='Journal start time, e.g. "10 minutes ago"')
    parser.add_argument('--filter', help='Literal journal substring, e.g. destination IP or connection ID')
    parser.add_argument('--validate-only', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    for names, commands in [(('url',), ('check', 'doctor')), (('endpoint', 'port'), ('client-profile',)),
                            (('follow', 'since', 'filter'), ('logs',))]:
        if args.command not in commands and any(getattr(args, name) not in (None, False) for name in names):
            parser.error(f'{", ".join(names)} only supported for {", ".join(commands)}')
    if args.endpoint is not None:
        try:
            ipaddress.ip_address(args.endpoint)
        except ValueError:
            parser.error('--endpoint must be an IPv4 or IPv6 address without brackets')
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error('--port must be in 1..65535')
    if args.url is not None:
        try:
            url = urlsplit(args.url)
            valid = url.scheme in ('http', 'https') and url.hostname and not url.username and not url.password
            valid = valid and not any(ord(c) < 33 for c in args.url)
            _ = url.port
        except ValueError:
            valid = False
        if not valid:
            parser.error('--url must be an HTTP(S) URL without credentials or whitespace')
    return args


def run_check(label, command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=25)
        ok = result.returncode == 0
        detail = (result.stdout or result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        ok, detail = False, str(error)
    print(f'{label}: {"PASS" if ok else "FAIL"}', flush=True)
    if detail:
        print(detail, flush=True)
    return ok


def status():
    # Быстрый статус не обращается в интернет и не показывает секреты.
    ok = run_check('Proxy service', ['systemctl', 'is-active', 'warp-pipe-proxy'])
    ok = run_check('DNS service', ['systemctl', 'is-active', 'unbound']) and ok
    settings = json.loads((ROOT / 'settings.json').read_text())
    owned = probe.owns_port(str(settings['vless_port']))
    print(f'VLESS TCP port {settings["vless_port"]}: {"PASS" if owned else "FAIL"}', flush=True)
    print('Network connectivity is not tested by status; run doctor.', flush=True)
    return ok and owned


def doctor(args):
    ok = status()
    ok = run_check('Server configuration', ['sing-box', 'check', '-c', '/etc/sing-box/config.json']) and ok
    settings = json.loads((ROOT / 'settings.json').read_text())
    dns = True
    for transport in ('+notcp', '+tcp'):
        result = subprocess.run(['dig', '+time=3', '+tries=1', transport, '@127.0.0.1', '-p',
                                 str(settings['dns_port']), 'example.com', 'A'],
                                capture_output=True, text=True, timeout=10)
        answer = result.returncode == 0 and 'status: NOERROR' in result.stdout and any(
            line and not line.startswith(';') and ' IN A ' in ' '.join(line.split())
            for line in result.stdout.splitlines())
        print(f'Recursive DNS {transport}: {"PASS" if answer else "FAIL"}', flush=True)
        dns = dns and answer
    url = args.url or 'https://example.com'
    command = ['curl', '--noproxy', '*', '--silent', '--show-error', '--connect-timeout', '5',
               '--max-time', '20', '-o', os.devnull, '--write-out',
               'HTTP %{http_code}; downloaded %{size_download} bytes\n', url]
    ipv4 = run_check('Direct IPv4 transport', [*command[:1], '-4', *command[1:]])
    ipv6 = run_check('Direct IPv6 transport', [*command[:1], '-6', *command[1:]])
    if not ipv6:
        print('WARN: IPv6 test failed (DNS, route or destination). IPv6 destinations may be unavailable.', flush=True)
    print('Testing local authenticated VLESS transport...', flush=True)
    try:
        probe.probe(ROOT, url=url, diagnostic=True)
        vless = True
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'VLESS: FAIL ({type(error).__name__}). Inspect logs and the client configuration.', flush=True)
        vless = False
    print('HTTP 3xx = redirect; 4xx/5xx = HTTP response, not a transport failure. Redirects and page assets are not tested.', flush=True)
    print('Local tests do not verify phone routing, published ports or the provider firewall.', flush=True)
    return ok and dns and ipv4 and vless


def logs(args):
    command = ['journalctl', '-u', 'warp-pipe-proxy', '-o', 'cat', '--no-pager']
    command += ['--since', args.since] if args.since else ['-n', '100']
    if args.follow:
        command.append('-f')
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
        try:
            for line in process.stdout:
                if args.filter is None or args.filter in line:
                    print(line, end='', flush=True)
            return process.wait() == 0
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait()


def main():
    args = parse_args()
    if args.validate_only:
        return 0
    if args.command == 'client-profile':
        settings = json.loads((ROOT / 'settings.json').read_text())
        credentials = json.loads((ROOT / 'credentials.json').read_text())
        configure.validate(settings, credentials)
        profile = configure.render_client(settings, credentials)
        if args.endpoint is not None:
            profile['outbounds'][0]['server'] = args.endpoint
        if args.port is not None:
            profile['outbounds'][0]['server_port'] = args.port
        print(json.dumps(profile, indent=2))
        return 0
    if args.command == 'status':
        return 0 if status() else 1
    if args.command == 'doctor':
        return 0 if doctor(args) else 1
    if args.command == 'logs':
        return 0 if logs(args) else 1
    raise ValueError('Use warp-pipe-proxy.sh for installation and checks')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f'ERROR: {error}. Run on the installed server with sudo; use --help for usage.', file=sys.stderr)
        sys.exit(1)
