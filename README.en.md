# Warp Pipe Proxy

> [Русский](README.md) · **English**

Run a personal VLESS Reality proxy on Ubuntu. Traffic goes through your server, so sites see its IP address. The installer configures sing-box and generates the keys.

## Installation

Start with a fresh Ubuntu system running systemd and a user with root or sudo access. To connect over the internet, you need a public IPv4 address. Allow inbound **TCP 10443** in your provider’s firewall. The server needs access to APT repositories and outbound HTTPS and DNS (TCP and UDP port 53).

Clone the project on the server or inside the container.

```bash
git clone https://github.com/drewlakee/warp-pipe-proxy.git
cd warp-pipe-proxy
```

### VPS

Run the installer from your SSH session.

```bash
sudo --preserve-env=SSH_CONNECTION ./warp-pipe-proxy.sh install
```

If UFW is active, the installer preserves its SSH rules. When enabling UFW for the first time with an empty ruleset, it allows SSH from your current session’s IP. If installing from a console, set `VPS_SSH_SOURCE` to your admin IP address or CIDR range. If UFW is inactive but already has rules, review them, enable UFW, and verify access by opening a new SSH connection.

### Container

Use an Ubuntu container that runs systemd as PID 1. When creating the container, publish `-p 10443:10443/tcp` and allow that port in the host firewall. Run the installer inside the container.

```bash
sudo ./warp-pipe-proxy.sh install --container
```

Pass `--container` each time you run `install` or `check`. Manage the firewall on the host.

## Connect a device

On the server, create a profile for your phone and display its QR code.

```bash
sudo warp-pipe-proxy device-add --device phone
sudo warp-pipe-proxy client-qr --device phone
```

Scan the code with a VLESS Reality client and connect. To get a link instead, run `sudo warp-pipe-proxy client-config --device phone`. Anyone with the QR code or link can use the proxy.

For a system-wide tunnel (TUN) with DNS routed through the proxy, export the full profile. Transfer the file to the device and import it into sing-box.

```bash
umask 077
sudo warp-pipe-proxy client-profile --device phone > phone.json
```

To reach a container over Wi-Fi, add `--endpoint 192.168.1.10 --port 10443` to `client-qr` or `client-profile`. Substitute the host’s LAN address and published port.

## Manage the proxy

After installation you can run these commands from any directory.

| Task | Command |
| --- | --- |
| List devices and their status | `sudo warp-pipe-proxy device-list` |
| Revoke the phone’s profile | `sudo warp-pipe-proxy device-revoke --device phone` |
| Check services and the listening port | `sudo warp-pipe-proxy status` |
| Check the configuration, DNS and VLESS | `sudo warp-pipe-proxy check` |
| Check connectivity to a specific site | `sudo warp-pipe-proxy doctor --url https://example.com` |
| Follow the connection log | `sudo warp-pipe-proxy logs --follow` |

Adding or revoking a device restarts the service. Other devices can reconnect with their existing profiles. To rotate keys for all devices, run `sudo warp-pipe-proxy rotate-keys` and import the new profiles.

## Settings and upgrades

The server IP, ports and Reality settings are in `/etc/warp-pipe-proxy/settings.json`. To allow clients to reach a private subnet, add `"allowed_private_subnets": ["192.168.50.0/24"]` to that file, using your own CIDR range. The exception applies to all devices. Apply changes with `sudo warp-pipe-proxy install` (add `--container` in a container).

To upgrade, run `git pull --ff-only` in the project directory, then repeat the install command for your setup. The existing UUID is preserved in the `default` profile. Add any required private subnets before upgrading. If the old `warp-pipe-proxy SSH preservation` UFW rule is still present, open a new SSH session from an allowed IP before removing it.
