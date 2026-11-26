#!/usr/bin/env bash
# Run on a Linux host with an initialized LXD bridge, VM support and Internet access.
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
name=warp-vm-${tmp##*.}
name=${name,,}
other=$name-client
created=()
cleanup() {
    for instance in "${created[@]}"; do lxc delete -f "$instance" || true; done
    rm -rf -- "$tmp"
}
trap cleanup EXIT

lxc init ubuntu:24.04 "$name" --vm -c limits.memory=2GiB
created+=("$name")
lxc start "$name"
lxc init ubuntu:24.04 "$other"
created+=("$other")
lxc start "$other"
guest() { lxc exec "$name" -- "$@"; }
assert_purged() {
    guest python3 - <<'PY'
from pathlib import Path
paths = (
    '/etc/warp-pipe-proxy', '/etc/sing-box/config.json',
    '/etc/systemd/system/warp-pipe-proxy.service',
    '/usr/local/bin/warp-pipe-proxy', '/usr/local/lib/warp-pipe-proxy',
    '/var/lib/warp-pipe-proxy', '/var/lib/warp-pipe-proxy-installer',
    '/var/log/warp-pipe-proxy-installer', '/var/lib/warp-pipe-proxy-uninstalling.json',
    '/etc/unbound/unbound.conf.d/warp-pipe-proxy.conf',
    '/etc/fail2ban/jail.d/warp-pipe-proxy.local',
    '/etc/sysctl.d/90-warp-pipe-proxy.conf', '/etc/modules-load.d/warp-pipe-proxy.conf',
    '/etc/apt/sources.list.d/warp-pipe-proxy-sagernet.sources',
)
remaining = [name for name in paths if Path(name).exists() or Path(name).is_symlink()]
if remaining:
    raise SystemExit('Unexpected project files: ' + ', '.join(remaining))
PY
}
for instance in "$name" "$other"; do
    for _ in {1..90}; do
        if lxc exec "$instance" -- true 2>/dev/null; then break; fi
        sleep 2
    done
    lxc exec "$instance" -- cloud-init status --wait
done
# The release validation currently covers this guest OS and architecture only.
guest bash -c '. /etc/os-release; [[ $ID == ubuntu && $VERSION_ID == 24.04 && $(dpkg --print-architecture) == amd64 ]]'
guest env DEBIAN_FRONTEND=noninteractive apt-get --error-on=any update
guest env DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server ufw
guest systemctl start ssh
server=$(guest ip -4 -j route get 1.1.1.1 | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["prefsrc"])')
source_ip=$(ip -4 -j route get "$server" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["prefsrc"])')

ssh-keygen -q -t ed25519 -N '' -f "$tmp/key"
guest install -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
guest tee -a /home/ubuntu/.ssh/authorized_keys < "$tmp/key.pub" >/dev/null
guest chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys
guest chmod 600 /home/ubuntu/.ssh/authorized_keys
guest cat /etc/ssh/ssh_host_ed25519_key.pub | awk -v ip="$server" '{print ip, $1, $2}' > "$tmp/known_hosts"
ssh_check() {
    ssh -i "$tmp/key" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5 \
        -o UserKnownHostsFile="$tmp/known_hosts" "ubuntu@$server" true
}
# First exercise automatic initialization on an inactive, empty firewall,
# including the DHCP client in this cloud image.
guest ufw status | grep -q '^Status: inactive'
ssh_check

guest mkdir -p /root/project
tar -cf - warp-pipe-proxy.sh runtime.sh logging.sh configure.py admin.py activity.py probe.py lifecycle.py uninstall_firewall.py \
    VERSION dependencies.lock.json release.py tests/dependency_inventory.py | guest tar -xf - -C /root/project
install_proxy() { guest bash /root/project/warp-pipe-proxy.sh install; }
# A shadowing manual binary must be rejected before APT, logs, backups, or
# configuration changes. Never replace the real system binary for this test.
assert_purged
guest bash -c '! command -v sing-box >/dev/null'
guest tee /usr/local/bin/sing-box >/dev/null <<'SH'
#!/bin/sh
touch /run/warp-unexpected-sing-box-execution
printf '%s\n' 'sing-box version 0.0.0'
SH
guest chmod 755 /usr/local/bin/sing-box
preflight_snapshot() {
    guest python3 - <<'PY'
import hashlib
import json
from pathlib import Path
import stat

paths = (
    '/etc/apt', '/etc/ufw', '/etc/default/ufw', '/etc/ssh',
    '/etc/unbound', '/etc/fail2ban', '/var/lib/dpkg/status',
    '/proc/sys/net/core/default_qdisc', '/proc/sys/net/ipv4/tcp_congestion_control',
)
result = {}
def record(path):
    if not path.exists() and not path.is_symlink():
        result[str(path)] = None
        return
    info = path.lstat()
    value = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
    if path.is_symlink():
        value['link'] = str(path.readlink())
    elif path.is_file():
        value['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    elif path.is_dir():
        for child in sorted(path.iterdir()):
            record(child)
    result[str(path)] = value
for name in paths:
    record(Path(name))
print(json.dumps(result, sort_keys=True))
PY
}
preflight_snapshot > "$tmp/preflight-before.json"
guest ufw show added > "$tmp/preflight-rules"
if install_proxy > "$tmp/preflight-refusal.log" 2>&1; then
    echo 'A shadowing sing-box binary was accepted unexpectedly' >&2
    exit 1
fi
grep -Fq 'unmanaged or manual sing-box binary' "$tmp/preflight-refusal.log"
guest test ! -e /run/warp-unexpected-sing-box-execution
assert_purged
preflight_snapshot > "$tmp/preflight-after.json"
diff "$tmp/preflight-before.json" "$tmp/preflight-after.json"
guest ufw show added | diff - "$tmp/preflight-rules"
guest rm /usr/local/bin/sing-box
install_proxy
guest python3 -B /root/project/release.py verify
[[ $(guest warp-pipe-proxy --version) == 'warp-pipe-proxy 0.1.0' ]]
install -d -m 755 artifacts
guest python3 -B /root/project/tests/dependency_inventory.py --lock /root/project/dependencies.lock.json \
    > artifacts/tested-environment.json
python3 - <<'PY'
import json
from pathlib import Path
import subprocess
path = Path('artifacts/tested-environment.json')
inventory = json.loads(path.read_text())
inventory['source_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + '\n')
PY
chmod 644 artifacts/tested-environment.json
guest cat /usr/bin/sing-box > "$tmp/sing-box"
chmod 700 "$tmp/sing-box"
export PATH="$tmp:$PATH"

ssh_restricted=no
check_ssh_access() {
    ssh_check
    lxc exec "$other" -- python3 - "$server" "$ssh_restricted" <<'PY'
import socket, sys
host, restricted = sys.argv[1:]
with socket.create_connection((host, 10443), timeout=5):
    pass
try:
    client = socket.create_connection((host, 22), timeout=3)
except OSError:
    if restricted != 'yes':
        raise
else:
    with client:
        if restricted == 'yes':
            raise SystemExit('Installer widened the source restriction on SSH')
        with client.makefile('rb') as greeting:
            if not greeting.readline(255).startswith(b'SSH-'):
                raise SystemExit('Expected SSH on a newly initialized firewall')
PY
}

export_profile() {
    guest warp-pipe-proxy client-profile --endpoint "$server" --device "$1" > "$tmp/$1.json"
}
request() {
    python3 - "$tmp/$1.json" "$2" "${3:-allow}" <<'PY'
import json, subprocess, sys
import probe
profile, url, expected = sys.argv[1:]
with open(profile) as f:
    outbound = json.load(f)['outbounds'][0]
try:
    probe.request(outbound, url)
except subprocess.CalledProcessError as error:
    if expected != 'deny' or error.cmd[0] != 'curl':
        raise
else:
    if expected != 'allow':
        sys.exit('Unexpected successful connection')
PY
}
guest warp-pipe-proxy device-list > "$tmp/initial-devices"
test ! -s "$tmp/initial-devices"
guest warp-pipe-proxy device-add --device laptop
export_profile laptop
check_ssh_access
request laptop https://example.com
# Now establish an administrator policy and verify reinstallation does not
# broaden SSH or change any existing UFW rule. The proxy allowance already exists.
guest ufw allow proto tcp from "$source_ip" to any port 22
guest ufw --force delete allow 22/tcp comment 'warp-pipe-proxy SSH preservation'
ssh_restricted=yes
guest ufw show added > "$tmp/existing-policy"
install_proxy
guest ufw show added | diff - "$tmp/existing-policy"
check_ssh_access
request laptop https://example.com
before=$(guest cat /proc/sys/kernel/random/boot_id)
lxc restart "$name"
for _ in {1..90}; do
    if ssh_check 2>/dev/null && guest systemctl is-active --quiet warp-pipe-proxy; then break; fi
    sleep 2
done
[[ $(guest cat /proc/sys/kernel/random/boot_id) != "$before" ]]
check_ssh_access
request laptop https://example.com

# Use disposable HTTP and DNS fixtures wholly inside the guest.
guest mkdir /run/warp-fixture
guest systemd-run --unit=warp-fixture4 python3 -m http.server 18080 --bind 127.0.0.1 --directory /run/warp-fixture
guest systemd-run --unit=warp-fixture6 python3 -m http.server 18081 --bind ::1 --directory /run/warp-fixture
guest tee /etc/unbound/unbound.conf.d/fixture.conf >/dev/null <<'EOF'
server:
  local-zone: "warp.test." static
  local-data: "fixture.warp.test. IN A 127.0.0.1"
EOF
guest systemctl restart unbound
guest systemctl restart warp-pipe-proxy
guest curl --noproxy '*' -fsS http://127.0.0.1:18080/ -o /dev/null
guest curl --noproxy '*' -gfsS 'http://[::1]:18081/' -o /dev/null
request laptop http://127.0.0.1:18080/ deny
request laptop http://fixture.warp.test:18080/ deny
request laptop 'http://[::1]:18081/' deny
guest python3 - <<'PY'
import json
from pathlib import Path
path = Path('/etc/warp-pipe-proxy/settings.json')
settings = json.loads(path.read_text())
settings['allowed_private_subnets'] = ['127.0.0.1/32']
path.write_text(json.dumps(settings))
PY
install_proxy
request laptop http://fixture.warp.test:18080/
request laptop 'http://[::1]:18081/' deny

guest warp-pipe-proxy device-add --device phone
export_profile phone
guest warp-pipe-proxy activity > "$tmp/activity"
grep -Eq '^laptop[[:space:]].*[[:space:]][1-9][0-9]*$' "$tmp/activity"
grep -Eq '^phone[[:space:]]+-[[:space:]]+0$' "$tmp/activity"
if grep -Eq '@probe|example[.]com' "$tmp/activity"; then exit 1; fi

guest systemd-run --unit=warp-activity-test -p StandardOutput=file:/run/phone-activity \
    /usr/local/bin/warp-pipe-proxy activity --device phone --since '1 hour ago' --follow
request phone https://example.com
phone_event=' TCP[[:space:]]+example[.]com:443$'
for _ in {1..20}; do
    if guest grep -Eq "$phone_event" /run/phone-activity; then break; fi
    sleep 1
done
guest grep -Eq "$phone_event" /run/phone-activity
# External probe failure must not restore the revoked device. Imports still
# work so argument validation itself does not abort the command.
guest cp /usr/local/lib/warp-pipe-proxy/probe.py /root/probe-cli-original.py
guest python3 - <<'PY'
from pathlib import Path
path = Path('/usr/local/lib/warp-pipe-proxy/probe.py')
source = path.read_text()
path.write_text(source.replace("    probe(Path('/etc/warp-pipe-proxy'))", "    raise SystemExit('VM test: simulated external probe outage')"))
PY
guest warp-pipe-proxy device-revoke --device phone > "$tmp/revoke.log" 2>&1
grep -Fq 'Device remains revoked' "$tmp/revoke.log"
guest mv /root/probe-cli-original.py /usr/local/lib/warp-pipe-proxy/probe.py
guest systemctl stop warp-activity-test
guest warp-pipe-proxy activity --device phone > "$tmp/revoked-activity"
grep -Eq "$phone_event" "$tmp/revoked-activity"
request phone https://example.com deny
request laptop https://example.com

# Fail the mandatory post-apply probe in the disposable checkout only.
guest ufw show added > "$tmp/rules"
guest sha256sum /etc/warp-pipe-proxy/credentials.json /etc/sing-box/config.json > "$tmp/state"
guest cp /root/project/probe.py /root/probe-original.py
guest tee /root/project/probe.py >/dev/null <<'PY'
raise SystemExit('VM test: simulated post-apply failure')
PY
if install_proxy > "$tmp/failure.log" 2>&1; then exit 1; fi
grep -Fq 'simulated post-apply failure' "$tmp/failure.log"
grep -Fq 'Managed configuration and service states restored' "$tmp/failure.log"
guest mv /root/probe-original.py /root/project/probe.py
guest ufw show added | diff - "$tmp/rules"
guest sha256sum --check < "$tmp/state"
check_ssh_access
request laptop https://example.com

# Uninstall permanently removes project data without creating another backup or
# log, while preserving administrator configuration and restricted SSH access.
old_key=$(guest python3 -c 'import json; print(json.load(open("/etc/warp-pipe-proxy/credentials.json"))["public_key"])')
guest sha256sum /etc/unbound/unbound.conf.d/fixture.conf > "$tmp/foreign-config"
guest warp-pipe-proxy uninstall
assert_purged
guest sha256sum --check < "$tmp/foreign-config"
grep -v "comment 'warp-pipe-proxy Reality'" "$tmp/rules" > "$tmp/retained-rules"
guest ufw show added | diff - "$tmp/retained-rules"
guest ufw status | grep -q '^Status: active'
ssh_check
guest bash /root/project/warp-pipe-proxy.sh uninstall
assert_purged

# Explicitly remove this test's own DNS fixture. Shared package defaults may be
# reused, but custom administrator configuration must never be adopted silently.
guest rm /etc/unbound/unbound.conf.d/fixture.conf
guest systemctl restart unbound
if guest bash /root/project/warp-pipe-proxy.sh restore; then
    echo 'The removed restore command was accepted unexpectedly' >&2
    exit 1
fi
assert_purged
# The retained active firewall is administrator-owned now; explicitly allow the
# new proxy installation as its administrator, then verify that policy is kept.
guest ufw allow 10443/tcp comment 'VM administrator proxy allowance'
guest ufw show added > "$tmp/new-policy"
install_proxy
guest ufw show added | diff - "$tmp/new-policy"
new_key=$(guest python3 -c 'import json; print(json.load(open("/etc/warp-pipe-proxy/credentials.json"))["public_key"])')
[[ $old_key != "$new_key" ]]
guest warp-pipe-proxy device-list > "$tmp/new-devices"
test ! -s "$tmp/new-devices"
check_ssh_access
request laptop https://example.com deny
request phone https://example.com deny
guest warp-pipe-proxy device-add --device fresh
export_profile fresh
request fresh https://example.com
echo 'PASS: release dependency checks, firewall initialization/preservation, external VLESS, reboot, revocation during outage, rollback, permanent uninstall and fresh reinstall'
python3 - <<'PY'
import json
from pathlib import Path
inventory = json.loads(Path('artifacts/tested-environment.json').read_text())
summary = {key: value for key, value in inventory.items() if key not in ('packages', 'lock')}
print('RELEASE_DEPENDENCY_INVENTORY=' + json.dumps(summary, sort_keys=True, separators=(',', ':')))
PY
