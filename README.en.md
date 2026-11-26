# Warp Pipe Proxy

> [Русский](README.md) · **English**

Run a personal VLESS Reality proxy on Ubuntu. Traffic goes through your server, so sites see its IP address. The installer configures sing-box and generates the keys.

## What the installer configures

On first install, the installer detects the public IPv4 address and selects a Reality handshake server after checking TLS 1.3 and HTTP/2. If sing-box is missing, it adds the official APT repository and installs the package.

| Component | Default setup |
| --- | --- |
| Proxy | Configures sing-box with VLESS Reality on `0.0.0.0:10443/TCP`. The `warp-pipe-proxy` service runs as a dedicated system user and starts at boot. |
| DNS | The server resolves names through Unbound on `127.0.0.1:5353`. The full client JSON profile sends DNS over HTTPS to `1.1.1.1` through the proxy. |
| Keys and access | Generates a Reality key pair, a short ID and a separate UUID for the local health check. A fresh installation starts with an empty device list. It stores credentials in `/etc/warp-pipe-proxy/credentials.json` with mode `0600`. Client access to internal addresses is blocked by default. |
| SSH and networking on a VPS | Opens the proxy port and SSH TCP ports in UFW. Fail2ban bans a source for one hour after five failed SSH logins in ten minutes. Enables TCP BBR when the kernel supports it. With `--container`, the installer skips UFW, fail2ban and BBR. |
| Checks and recovery | Checks local DNS and makes an HTTPS request through VLESS. Installer logs are in `/var/log/warp-pipe-proxy-installer/` and backups in `/var/lib/warp-pipe-proxy-installer/`. If applying changes fails, the installer attempts to restore the managed files and services. |

## Installation

The examples below show output excerpts. Timestamps, addresses and per-run paths vary. Angle brackets stand in for credentials in links and profiles.

Start with a fresh Ubuntu system running systemd and a user with root or sudo access. To connect over the internet, you need a public IPv4 address. Allow inbound **TCP 10443** in your provider’s firewall. The server needs access to APT repositories and outbound HTTPS and DNS (TCP and UDP port 53).

Clone the project on the server or inside the container.

```bash
git clone https://github.com/drewlakee/warp-pipe-proxy.git
cd warp-pipe-proxy
```

<details>
<summary>Example output</summary>

```text
Cloning into 'warp-pipe-proxy'...
```

A successful `cd` produces no output.

</details>

### VPS

Run the installer on the VPS.

```bash
sudo ./warp-pipe-proxy.sh install
```

<details>
<summary>Example output</summary>

```text
[SUCCESS] Installed command: /usr/local/bin/warp-pipe-proxy
[SUCCESS] SUCCESS: VLESS Reality configured
```

</details>

The installer reads the SSH ports from the `sshd` configuration and adds a UFW rule allowing connections from any IP to each port. It also adds these rules when UFW is already active, including when SSH was previously allowed only from your IP.

### Container

Use an Ubuntu container that runs systemd as PID 1. When creating the container, publish `-p 10443:10443/tcp` and allow that port in the host firewall. Run the installer inside the container.

```bash
sudo ./warp-pipe-proxy.sh install --container
```

<details>
<summary>Example output</summary>

```text
[SUCCESS] SUCCESS: VLESS Reality configured
[WARN] CONTAINER MODE: proxy checks passed; UFW, fail2ban and BBR were not managed
```

</details>

Pass `--container` each time you run `install` or `check`. Manage the firewall on the host.

## Connect a device

Create a profile for the phone on the server. Always pass `--device NAME` when exporting a QR code, link or JSON profile, even if there is only one device.

```bash
sudo warp-pipe-proxy device-add --device phone
```

<details>
<summary>Example output</summary>

```text
[SUCCESS] Credential change completed: device-add
```

</details>

**QR code or link.** Scan the QR code in a VLESS Reality client or import the link. Both grant access to the proxy.

```bash
sudo warp-pipe-proxy client-qr --device phone
```

<details>
<summary>Example output</summary>

```text
VLESS QR contains access credentials. Keep it private. DNS/TUN settings require the JSON profile.
```

The terminal then draws the QR code containing the phone’s credentials.

</details>

```bash
sudo warp-pipe-proxy client-config --device phone
```

<details>
<summary>Example output</summary>

```text
VLESS Reality:
vless://<UUID>@203.0.113.10:10443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=<PUBLIC_KEY>&sid=<SHORT_ID>&type=tcp#vps-reality
```

</details>

**sing-box profile.** For a system-wide tunnel (TUN) and DNS through the proxy, save the JSON, transfer the file to the device and import it into sing-box.

```bash
umask 077
sudo warp-pipe-proxy client-profile --device phone > phone.json
```

<details>
<summary>Result in phone.json</summary>

```text
      "type": "vless",
      "tag": "proxy",
      "server": "203.0.113.10",
      "server_port": 10443,
      "uuid": "<UUID>",
```

This excerpt comes from `outbounds[0]`. Both commands are silent on success. `umask` sets permissions for newly created files and `>` writes the JSON to `phone.json`.

</details>

To reach a container over Wi-Fi, add `--endpoint 192.168.1.10 --port 10443` to `client-qr` or `client-profile`, substituting the host’s LAN address and published port.

## Rotate device credentials

After a successful rotation, **every active device needs a new profile**. Restarting the proxy drops current connections. Previously issued QR codes, links and JSON profiles can no longer authenticate.

```bash
sudo warp-pipe-proxy rotate-keys
```

```text
VLESS Reality authenticated HTTPS request passed
[SUCCESS] Credential change completed: rotate-keys
[INFO] Export and import new profiles on every active device
[INFO] Previous credentials are retained in the root-only backup: /var/lib/warp-pipe-proxy-installer/<RUN>
```

Rotation replaces the shared Reality key pair and short ID, plus the UUID of every active device. Device names are preserved. For example, `phone` and `laptop` stay active and a previously revoked `old-phone` stays revoked.

After the success message, display a new QR for `phone` or export new JSON for `laptop` using the commands in [Connect a device](#connect-a-device). Pass the device’s own name with `--device`. Replace the profile in the app and reconnect. You do not need to run `device-add` again.

<details>
<summary>If the check fails after restart</summary>

```text
[WARN] Rolling back managed configuration and service states
[SUCCESS] Managed configuration and service states restored
```

After a successful rollback, the previous profiles work again. If you see `ROLLBACK INCOMPLETE`, inspect the installer log and backup.

</details>

## Management and diagnostics

| Task | Command | Example output (excerpt) |
| --- | --- | --- |
| Revoke the old phone | `sudo warp-pipe-proxy device-revoke --device old-phone` | `[SUCCESS] Credential change completed: device-revoke` |
| List devices | `sudo warp-pipe-proxy device-list` | `laptop	active`<br>`old-phone	revoked`<br>`phone	active` |
| Check services and port | `sudo warp-pipe-proxy status` | `Proxy service: PASS`<br>`DNS service: PASS`<br>`VLESS TCP port 10443: PASS` |
| Test DNS and VLESS | `sudo warp-pipe-proxy check` | `VLESS Reality authenticated HTTPS request passed` |
| Check in container mode | `sudo warp-pipe-proxy check --container` | `[WARN] Container mode: UFW and fail2ban checks skipped; host firewall must protect published ports` |
| Test a site | `sudo warp-pipe-proxy doctor --url https://example.com` | `Direct IPv4 transport: PASS`<br>`VLESS transport passed; inspect the HTTP status above` |
| Follow the service log | `sudo warp-pipe-proxy logs --follow` | `… inbound/vless[vless-reality]: [phone] inbound connection to example.com:443` |
| Show help | `warp-pipe-proxy --help` | `usage: warp-pipe-proxy.sh [-h] [--container] …` |

To remove one device, use `device-revoke`. The service restarts and the other devices can reconnect with their existing profiles. `status` checks the services and port locally. Test external reachability from a client device.

## Settings and upgrades

The server IP, ports and Reality settings are in `/etc/warp-pipe-proxy/settings.json`. To allow clients to reach a private subnet, add `"allowed_private_subnets": ["192.168.50.0/24"]` to that file, using your own CIDR range. The exception applies to all devices. Apply changes with `sudo warp-pipe-proxy install` (add `--container` in a container).

To upgrade, run `git pull --ff-only` in the project directory, then repeat the install command for your setup. When upgrading from the older single-UUID version, existing clients retain access. Export that UUID explicitly with `--device default`. Add any required private subnets before upgrading.

<details>
<summary>Example upgrade and reapply output</summary>

```text
$ git pull --ff-only
Already up to date.

$ sudo warp-pipe-proxy install
[SUCCESS] SUCCESS: VLESS Reality configured
```

This example shows a checkout that is already up to date. After downloading a new version, run the installer from the checkout as shown above. `sudo warp-pipe-proxy install` reapplies the version already installed.

</details>
