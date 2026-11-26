# Changelog

## v0.1.0 — 2026-11-26

First tagged release of Warp Pipe Proxy, a personal VLESS Reality proxy installer for Ubuntu. This release supports **Ubuntu 24.04 LTS on amd64** with **sing-box 1.14.4**. See the [release notes](docs/releases/v0.1.0.md) for installation, dependency versions and validation scope.

### Release and dependency contract

- Added `VERSION` and `--version` for both the source checkout and the installed command.
- Added `dependencies.lock.json` with exact versions of all 12 direct APT dependencies used in VPS mode; container mode omits UFW and fail2ban. Versions come from the validated Ubuntu 24.04 amd64 VM.
- Installation requests exact package versions and checks the resulting environment before generating or applying service configuration. `check` also verifies the release lock.
- Missing system packages may be installed and older system packages upgraded to the lock. Newer installed versions are rejected before APT or configuration changes; the installer never automatically downgrades them.
- Existing sing-box must already be the expected package and runtime version. A different engine version, a manual binary, or a shadowing executable on `PATH` is rejected before APT or configuration changes.
- No permanent APT holds or global preferences are installed. The lock covers direct dependencies; the complete VM package inventory is published by CI for the transitive OS environment. Release selection and installation remain manual.

### Proxy and device management

- VLESS Reality on TCP 10443 by default, with public IPv4 detection and TLS 1.3/HTTP/2 validation of the selected Reality handshake server.
- A dedicated unprivileged systemd service, local Unbound DNS, SSH fail2ban protection and optional BBR on the VPS path.
- An initially empty device registry with a separate UUID for each device, explicit device selection for QR/link/JSON exports, and a separate internal health-check credential.
- Key rotation preserves device names and revocation status while replacing the Reality key pair, short ID and active device UUIDs.
- Private destination access is blocked by default, including addresses resolved from names. Explicit `allowed_private_subnets` exceptions are available in server settings.
- Commands for status, end-to-end checks, direct/proxy diagnosis, logs and per-device activity.

### Firewall policy

- Automatically inspects the existing firewall without an extra option.
- Preserves all rules and policies of an active UFW, including source-restricted SSH access. Administrators add any required proxy allowance to that policy themselves.
- Initializes UFW only when no existing policy is detected, allowing the detected SSH ports and the proxy port before enabling it.
- Refuses disabled UFW with saved user rules and competing iptables/nftables policy. Checks listeners and supported DHCP clients before enabling an inbound deny policy.
- Configuration rollback leaves an untouched firewall alone.

### Revocation and removal

- Device revocation commits after local validation and application. A later external HTTPS probe failure is diagnostic and cannot reinstate revoked access.
- Revocation can be applied while the proxy is stopped without starting it. A failed local application leaves the proxy stopped with autostart disabled, preserves validated revocation data for completion and blocks applying obsolete credentials.
- Complete `uninstall` is permitted during incomplete revocation and permanently deletes project settings, keys, profiles, installed code, service files, old backups and installer logs. It creates no new removal backup or log.
- Removal verifies ownership before deleting project-specific Unbound, fail2ban, BBR and APT source files. It removes only identifiable original proxy UFW allowances, preserving administrator policy and SSH access.
- Shared packages, the service account, shared repository key and system journal remain. A temporary marker without secrets supports retrying interrupted removal and is deleted after success.
- A fresh installation after removal generates new keys and an empty device registry. Previously issued profiles no longer work.

### Validation and documentation

- Python unit tests, Bash syntax checks and an Ubuntu 24.04 amd64 VM scenario cover installation, external VLESS traffic, firewall preservation, reboot, private-address restrictions, revocation, rollback, complete removal and installation again.
- Release metadata checks and VM package inventory make the tested direct dependency set explicit. The VM result does not establish support for other Ubuntu versions, architectures or container mode.
- Russian and English READMEs document tagged installation, exact dependencies, device management, file ownership and paths, interrupted revocation, and permanent removal.
