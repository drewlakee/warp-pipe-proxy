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
for instance in "$name" "$other"; do
    for _ in {1..90}; do
        if lxc exec "$instance" -- true 2>/dev/null; then break; fi
        sleep 2
    done
    lxc exec "$instance" -- cloud-init status --wait
done
guest env DEBIAN_FRONTEND=noninteractive apt-get update -qq
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
guest ufw allow proto tcp from "$source_ip" to any port 22
guest ufw --force enable
ssh_check

guest mkdir -p /root/project
tar -cf - warp-pipe-proxy.sh runtime.sh logging.sh configure.py admin.py probe.py | guest tar -xf - -C /root/project
install_proxy() { guest bash /root/project/warp-pipe-proxy.sh install; }
install_proxy
guest cat /usr/bin/sing-box > "$tmp/sing-box"
chmod 700 "$tmp/sing-box"
export PATH="$tmp:$PATH"

check_ssh_policy() {
    ssh_check
    lxc exec "$other" -- python3 - "$server" <<'PY'
import socket, sys
host = sys.argv[1]
with socket.create_connection((host, 10443), timeout=5):
    pass
try:
    connection = socket.create_connection((host, 22), timeout=3)
except TimeoutError:
    pass
else:
    connection.close()
    raise SystemExit('Unexpected SSH access from the second node')
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
check_ssh_policy
request laptop https://example.com
install_proxy
request laptop https://example.com
before=$(guest cat /proc/sys/kernel/random/boot_id)
lxc restart "$name"
for _ in {1..90}; do
    if ssh_check 2>/dev/null && guest systemctl is-active --quiet warp-pipe-proxy; then break; fi
    sleep 2
done
[[ $(guest cat /proc/sys/kernel/random/boot_id) != "$before" ]]
check_ssh_policy
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
request phone https://example.com
guest warp-pipe-proxy device-revoke --device phone
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
check_ssh_policy
request laptop https://example.com
echo 'PASS: external VLESS, SSH policy, reboot, local subnet policy, revocation and rollback'
