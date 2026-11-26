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
| SSH and networking on a VPS | Preserves an already active UFW policy. When no firewall policy exists, allows the proxy and SSH TCP ports, then enables UFW. Fail2ban bans a source for one hour after five failed SSH logins in ten minutes. Enables TCP BBR when the kernel supports it. With `--container`, the installer skips UFW, fail2ban and BBR. |
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

The installer inspects the firewall automatically; no additional options are needed.

- **UFW is already active:** all rules and default policies are preserved, including source restrictions on SSH. No proxy allowance is added either: allow TCP 10443 in the existing policy if needed. Local installation checks do not establish that this port is reachable externally.
- **No firewall policy exists:** the installer reads ports from `sshd`, permits SSH and the proxy, then enables UFW with other inbound traffic denied. It checks existing listeners first and recognizes system DHCP clients separately.
- **UFW is disabled but has saved user rules, or another iptables/nftables policy is detected:** installation stops before applying configuration and explains the conflict. Review the existing policy yourself; the installer neither activates it nor layers another firewall over it.

Reinstallation preserves an active UFW policy even when this project originally initialized it. If you change the proxy port, update its allowance in your policy yourself.

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
| Summarize device activity | `sudo warp-pipe-proxy activity` | `phone  12s ago  84`<br>`tablet  -  0` |
| Show recent phone requests | `sudo warp-pipe-proxy activity --device phone --since "10 minutes ago"` | `2026-11-26 14:32:08  TCP  example.com:443` |
| Follow new phone requests | `sudo warp-pipe-proxy activity --device phone --follow` | `2026-11-26 14:32:10  UDP  203.0.113.24:443` |
| Follow the service log | `sudo warp-pipe-proxy logs --follow` | `… inbound/vless[vless-reality]: [phone] inbound connection to example.com:443` |
| Show help | `warp-pipe-proxy --help` | `usage: warp-pipe-proxy.sh [-h] [--container] …` |

By default, `activity` shows the last request and the connection request count for each profile in the past hour, using the available journal. The summary includes revoked and idle profiles and excludes internal `@probe` checks. Use `--device` to see the UTC time, protocol and destination supplied by that client. One site can generate several requests. The live view starts with new events. Add `--since` to replay history first.

To remove one device, use `device-revoke`. A running service restarts and other devices can reconnect with their existing profiles. If the service is already stopped, revocation is applied without starting it. `status` checks the services and port locally. Test external reachability from a client device.

**Revocation commits after local configuration validation and application.** Failure of the subsequent external HTTPS request produces a warning, but the device stays revoked and the command succeeds. Device addition and key rotation still roll back when their mandatory checks fail.

If writing the revoked configuration or starting the service fails, the command returns an error and leaves the proxy stopped with autostart disabled. Old access is not automatically restored. The validated state without the revoked device remains in `/var/lib/warp-pipe-proxy-installer/<RUN>/revocation/`, and `/etc/warp-pipe-proxy/revocation-pending.json` records the incomplete revocation. If `credentials.json` was already replaced, reinstalling regenerates the configuration from those current revoked credentials. If writing credentials itself failed, installation refuses to start the proxy with old keys: first restore **the validated `revocation/credentials.json` from the indicated run** with mode `0600`, then reinstall. Do not use the pre-revocation backup. Further device changes, `uninstall` and `restore` are blocked until recovery completes. Inspect the failure in the log first; do not remove the pending marker manually. The uninstall recovery command below does not accept these intermediate snapshots.

## Settings and upgrades

The server's source settings are in `/etc/warp-pipe-proxy/settings.json`. Edit this file as root and apply changes with `sudo warp-pipe-proxy install` (add `--container` in a container). The installer regenerates and validates service configurations before applying them. Manual edits to generated files such as `/etc/sing-box/config.json` are overwritten when configuration is reapplied. See [File layout](#file-layout) for the other files and their roles.

| Field in `settings.json` | Meaning and constraints |
| --- | --- |
| `public_ip` | The server's public IPv4 address included in client profiles. |
| `reality_host` | The Reality handshake server's domain name. On first install it is selected after TLS 1.3 and HTTP/2 checks. |
| `vless_port` | The proxy's TCP port; defaults to `10443`. |
| `dns_port` | The local Unbound port on `127.0.0.1`; defaults to `5353`. |
| `allowed_private_subnets` | An optional list of permitted private subnets, for example `["192.168.50.0/24"]`. There are no exceptions by default; an added exception applies to all devices. |

Both ports must be distinct integers in `1024..65535`; on a VPS they must also differ from the SSH ports. After changing the proxy port, update its allowance in an already active firewall, your provider's firewall and any container port mapping. After changing the public address, proxy port or Reality server, export new client profiles. The `--endpoint` and `--port` options are supported by `client-profile` and `client-qr` and change only the exported profile, not the listening service; `client-config` does not accept them.

When `settings.json` is first created, you can pass `VPS_PUBLIC_IP` (your public IPv4 instead of automatic detection) and `VPS_REALITY_HOST` (a domain or space-separated list of candidates) through `sudo env`. For example:

```bash
sudo env VPS_REALITY_HOST=www.microsoft.com ./warp-pipe-proxy.sh install
```

Once `settings.json` exists, these variables do not override it: make subsequent changes in that file. Manage devices with `device-add`, `device-revoke` and `rotate-keys`; do not manually edit `credentials.json`. Reinstallation preserves existing UUIDs and Reality keys without rotating them automatically. Pass `--container` on every `install` and `check`; the saved installation mode is used automatically only when restoring an uninstall snapshot with `restore`.

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

## File layout

### Settings, keys and installer state

All files in the following table are under **`/etc/warp-pipe-proxy/`**. The directory is owned by root and created with mode `0700`; its files are created with mode `0600`. `settings.json` and `credentials.json` are the source data used to generate configuration. The installer creates and maintains the other files.

| File under `/etc/warp-pipe-proxy/` | Purpose |
| --- | --- |
| `settings.json` | Public IP, ports, Reality server and private subnet exceptions. Edit this file to change server parameters. |
| `credentials.json` | The Reality private/public key pair, short ID, internal check UUID, and device registry with UUIDs and revocations. Managed through device commands; contains access credentials. |
| `managed`, `installed` | Markers for a managed installation and successful completion. `uninstall` removes `installed`. |
| `summary.json`, `tls-check.txt` | Settings summary from the last successful install and output from the initial Reality server check. These are diagnostic files, not configuration inputs. |
| `ownership.json` | Hashes of owned proxy/CLI files and the container mode of the last successful installation. Used to verify safe removal. |
| `uninstalled.json` | Removal state and a reference to its latest snapshot. Allows interrupted removal to resume and determines whether `restore` is permitted. |
| `revocation-pending.json` | Marker for an incomplete revocation, with hashes of the validated intended credentials. Blocks operations that could restore old access. |
| `clients.txt`, `client-sing-box.json` | Compatibility exports for an older installation using the `default` profile; not automatically created for a fresh installation. Contain proxy access credentials. Export current device profiles with `--device`. |

Do not edit the internal markers or hashes manually. See [Management and diagnostics](#management-and-diagnostics) and [Uninstall and restore](#uninstall-and-restore) for handling snapshots and interrupted operations.

### Service configurations and installed command

| Path | Contents and management |
| --- | --- |
| `/etc/sing-box/config.json` | Generated server configuration containing the private key; `root:warp-pipe-proxy`, mode `0640`. `/etc/sing-box/` has mode `0750`. Regenerated from settings/credentials during installation and device changes. |
| `/etc/unbound/unbound.conf.d/warp-pipe-proxy.conf` | Generated local DNS configuration; root, mode `0644`. If necessary, the installer also creates the DNSSEC trust anchor `/var/lib/unbound/root.key` from `dns-root-data`, owned by `unbound` with mode `0644`. |
| `/etc/fail2ban/jail.d/warp-pipe-proxy.local` | Generated SSH jail using the detected `sshd` ports; root, mode `0644`. Not created or modified in container mode. |
| `/etc/systemd/system/warp-pipe-proxy.service` | Generated service unit; root, mode `0644`. Runs sing-box as `warp-pipe-proxy` and depends on Unbound. |
| `/usr/local/bin/warp-pipe-proxy` | Command launcher; root, mode `0755`. Uses the installed project copy, so routine management does not require the original checkout. |
| `/usr/local/lib/warp-pipe-proxy/` | Installed shell/Python modules and the `.managed` marker; directory mode `0755`, root-owned files with mode `0644`. Updated when installing from a checkout. |
| `/var/lib/warp-pipe-proxy/` | Working directory and home directory for the `warp-pipe-proxy` system user. Keys and settings are stored separately under `/etc/warp-pipe-proxy/`. |
| `/etc/apt/keyrings/sagernet.asc`, `/etc/apt/sources.list.d/warp-pipe-proxy-sagernet.sources` | Key and definition for the official sing-box APT repository; root, mode `0644`. Added when sing-box is not already installed. |
| `/etc/sysctl.d/90-warp-pipe-proxy.conf`, `/etc/modules-load.d/warp-pipe-proxy.conf` | Persistent `fq`/BBR settings and `tcp_bbr` module loading. Created when this optional optimization is successfully enabled outside a container. |
| `/etc/ufw/`, `/etc/default/ufw` | Shared UFW configuration. Initialized by the installer only when no existing firewall policy is present; an active firewall retains its own rules. |

### Logs, snapshots and temporary files

`<RUN>` is an identifier built from UTC time and the process ID, for example `20261126T120000Z-1234`. Log and backup directories are root-only (`0700`); logs and individual recovery files are created with mode `0600`. Copies of system files may retain their original permissions inside the private backup directory.

| Path | Purpose |
| --- | --- |
| `/var/log/warp-pipe-proxy-installer/<RUN>.log` | Output from installation, checking or a state-changing operation. The proxy's own log is in the systemd journal: `sudo warp-pipe-proxy logs` or `sudo journalctl -u warp-pipe-proxy`. |
| `/var/lib/warp-pipe-proxy-installer/<RUN>/` | Snapshot for a particular operation. Installation backups contain original system files with their paths, such as `etc/…`. Snapshots may contain earlier private keys and UUIDs. |
| `/var/lib/warp-pipe-proxy-installer/<RUN>/transaction/` | Files for rolling back configuration application. Sibling files `paths`, `active` and `enabled` record paths and service activity/enablement. This is not a snapshot for the `restore` command. |
| `/var/lib/warp-pipe-proxy-installer/<RUN>/revocation/` | Validated configuration without the revoked device, retained to finish revocation after a failure. Contains the intended settings/credentials and generated files. |
| `/var/lib/warp-pipe-proxy-installer/<RUN>/{settings.json,credentials.json,ownership.json,recovery.json}` | The separate uninstall snapshot format: current settings, credentials and verification metadata. `restore` accepts only the latest completed snapshot referenced by `uninstalled.json`. |
| `/var/lib/warp-pipe-proxy-installer/{stage.*,rotate.*,restore.*}` | Temporary directories for configuration preparation, credential changes and recovery validation. Removed on normal operation exit, including handled failures. |
| `/run/lock/warp-pipe-proxy.lock` | Lock preventing concurrent installation changes or exports of intermediate credential state. |

When backing up, account for both parts of the state: `/etc/warp-pipe-proxy/` and the needed snapshots under `/var/lib/warp-pipe-proxy-installer/`. The section below explains which snapshots can be used and what is retained after removal.

## Uninstall and restore

For an older installation, update the checkout and successfully reapply this installer version once before uninstalling. This creates `/etc/warp-pipe-proxy/ownership.json` with hashes of files owned by the project. Automated removal refuses to guess ownership without it. To stop the server immediately without upgrading, use `sudo systemctl disable --now warp-pipe-proxy`; the keys remain intact.

```bash
sudo warp-pipe-proxy uninstall
```

The command first verifies ownership and archives current settings and credentials in a separate root-only snapshot. It then stops and disables the proxy service and removes its unit, generated `/etc/sing-box/config.json`, installed command and supporting code. A manually edited managed file aborts removal before the service is stopped: preserve your changes and review the conflict. Output includes the recovery snapshot identifier `<RUN>`.

**Retained:** the private `/etc/warp-pipe-proxy/` directory with keys and recovery state, logs and backups, system packages and service account, Unbound and fail2ban with their configuration, BBR, and every UFW rule, including SSH and proxy allowances. Removing the proxy does not return the whole OS to its pre-install state. A retained port allowance does not create a listening service; review shared host policy separately before cleaning it up.

If removal is interrupted, resume it from the saved checkout:

```bash
sudo ./warp-pipe-proxy.sh uninstall
```

Removal resumes from its saved state. Installation and restore refuse to proceed until removal finishes. Repeating an already completed uninstall is safe and reports the same snapshot.

To restore, use a trusted checkout of the same or a compatible newer version and the exact identifier printed by uninstall, for example:

```bash
sudo ./warp-pipe-proxy.sh restore --backup 20261126T120000Z-1234
```

Only **the latest completed uninstall snapshot on this server** is accepted. The command checks hashes, file permissions, absence of a new installation, and that retained settings/credentials still match the snapshot. Older transaction backups, interrupted removal and credentials changed after uninstall are rejected. This prevents accidental revival of previously revoked devices. This snapshot supports recovery from removal on the same server; recovery after complete disk loss needs a separate backup of the server state.

Restore regenerates configuration with current code, runs normal installation checks and reuses retained keys. It does not replay archived scripts, units or firewall state. Container mode is read from the snapshot, so `restore` does not take `--container`. After success, previously active profiles work again, revoked devices remain revoked, and the consumed uninstall snapshot is no longer eligible for automatic restore. Check external reachability from a client device.
