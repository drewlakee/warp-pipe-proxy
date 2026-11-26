"""Remove unchanged project proxy allowances without changing other UFW policy."""

import os
import re
import shlex
import subprocess
import sys


COMMENT = 'warp-pipe-proxy Reality'
HEADER = "Added user rules (see 'ufw status' for running firewall):"


def parse_added(output):
    """Parse UFW's saved-rule report, which is available even while inactive."""
    if not isinstance(output, str):
        raise ValueError('Cannot read UFW saved-rule report; refusing firewall cleanup')
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) < 2 or lines[0] != HEADER:
        raise ValueError('Cannot recognize UFW saved-rule report; refusing firewall cleanup')
    if lines[1:] == ['(None)']:
        return ()
    rules = []
    for line in lines[1:]:
        try:
            rule = tuple(shlex.split(line))
        except ValueError as error:
            raise ValueError('Cannot parse UFW saved rule; refusing firewall cleanup') from error
        if len(rule) < 2 or rule[0] != 'ufw' or rule in rules:
            raise ValueError('Ambiguous UFW saved-rule report; refusing firewall cleanup')
        rules.append(rule)
    return tuple(rules)


def proxy_port(rule):
    if rule[-2:] != ('comment', COMMENT):
        return None
    specification = rule[1:-2]
    if specification[:2] == ('allow', 'in'):
        specification = ('allow', *specification[2:])
    if len(specification) != 2 or specification[0] != 'allow':
        return None
    match = re.fullmatch(r'([1-9][0-9]{0,4})/tcp', specification[1])
    if not match or int(match[1]) > 65535:
        return None
    return int(match[1])


def remove_proxy_rules(run=subprocess.run):
    """Delete original-shaped, exactly labelled rules; return logical rule count.

    UFW deduplicates equivalent IPv4/IPv6 commands in ``show added``. Deleting
    the complete command removes both matching families. A nonempty comment
    participates in UFW's rule comparison, so an administrator's relabelled
    allowance cannot be deleted by a stale command. Numbered deletes do not
    provide that protection and cannot inspect inactive saved rules.
    """
    environment = dict(os.environ, LC_ALL='C')

    def execute(command):
        return run(command, capture_output=True, text=True, check=True, timeout=30, env=environment)

    def inspect():
        return parse_added(execute(['ufw', 'show', 'added']).stdout)

    rules = inspect()
    eligible = []
    for rule in rules:
        port = proxy_port(rule)
        if port is not None:
            eligible.append((rule, port))
        elif rule[-2:] == ('comment', COMMENT):
            print('WARN: Preserved modified UFW rule with the project label; review it manually: '
                  + shlex.join(rule), file=sys.stderr)
    if not eligible:
        return 0

    # SSH may have moved onto a former proxy port after installation. Never
    # close that administrative path merely because its old label remains.
    configuration = execute(['/usr/sbin/sshd', '-T']).stdout
    ssh_ports = set()
    for line in configuration.splitlines():
        fields = line.split()
        if fields and fields[0] == 'port':
            if len(fields) != 2 or not fields[1].isdigit() or not 1 <= int(fields[1]) <= 65535:
                raise ValueError('Cannot determine current SSH ports; refusing firewall cleanup')
            ssh_ports.add(int(fields[1]))
    if not ssh_ports:
        raise ValueError('Cannot determine current SSH ports; refusing firewall cleanup')

    removed = 0
    for rule, port in eligible:
        if port in ssh_ports:
            print(f'WARN: Preserved UFW permission on TCP {port}: it is now an SSH port', file=sys.stderr)
            continue
        if inspect() != rules:
            raise ValueError('UFW policy changed during cleanup; rerun uninstall after reviewing the policy')
        execute(['ufw', '--force', 'delete', *rule[1:]])
        expected = tuple(existing for existing in rules if existing != rule)
        current = inspect()
        if current != expected:
            raise ValueError('UFW cleanup could not verify the exact removal; inspect the policy before retrying')
        rules = current
        removed += 1
    return removed
