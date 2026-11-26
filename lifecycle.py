"""Track owned files, preserve revocation intent, and completely remove the proxy."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import tempfile

import configure


CONFIG = '/etc/sing-box/config.json'
UNIT = '/etc/systemd/system/warp-pipe-proxy.service'
LAUNCHER = '/usr/local/bin/warp-pipe-proxy'
BUNDLE = '/usr/local/lib/warp-pipe-proxy'
BUNDLE_FILES = ('warp-pipe-proxy.sh', 'runtime.sh', 'logging.sh', 'configure.py',
                'probe.py', 'admin.py', 'activity.py', 'lifecycle.py', 'uninstall_firewall.py',
                'release.py', 'VERSION', 'dependencies.lock.json', '.managed')
OWNED_FILES = (CONFIG, UNIT, LAUNCHER, *(BUNDLE + '/' + name for name in BUNDLE_FILES))
V2_FILES = tuple(name for name in OWNED_FILES if Path(name).name not in ('release.py', 'VERSION', 'dependencies.lock.json'))
LEGACY_FILES = tuple(name for name in V2_FILES if not name.endswith('/uninstall_firewall.py'))
UNBOUND = '/etc/unbound/unbound.conf.d/warp-pipe-proxy.conf'
FAIL2BAN = '/etc/fail2ban/jail.d/warp-pipe-proxy.local'
BBR_FILES = ('/etc/sysctl.d/90-warp-pipe-proxy.conf', '/etc/modules-load.d/warp-pipe-proxy.conf')
APT_SOURCE = '/etc/apt/sources.list.d/warp-pipe-proxy-sagernet.sources'
HOST_FILES = (UNBOUND, FAIL2BAN, *BBR_FILES, APT_SOURCE)
ALL_FILES = (*OWNED_FILES, *HOST_FILES)
PURGE_MARKER = '/var/lib/warp-pipe-proxy-uninstalling.json'
LOG_DIRECTORY = '/var/log/warp-pipe-proxy-installer'
STATE_DIRECTORY = '/var/lib/warp-pipe-proxy'
STATE_FILES = ('settings.json', 'credentials.json')
PURGE_FORMAT = 'warp-pipe-proxy-uninstall-v1'
REVOCATION_FORMAT = 'warp-pipe-proxy-revocation-v1'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_private(path, data):
    """Publish complete root-only metadata and persist the rename."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix='.' + path.name + '.', dir=path.parent, delete=False) as output:
            temporary = Path(output.name)
            os.fchmod(output.fileno(), 0o600)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        sync_directory(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_json(path, data):
    write_private(path, (json.dumps(data, indent=2) + '\n').encode())


class Lifecycle:
    def __init__(self, root=Path('/etc/warp-pipe-proxy'),
                 backup_root=Path('/var/lib/warp-pipe-proxy-installer'),
                 system_root=Path('/'), run=subprocess.run, owner_uid=None,
                 firewall_cleanup=None, service_uid=None):
        self.root = Path(root)
        self.backup_root = Path(backup_root)
        self.system_root = Path(system_root)
        self.run = run
        self.owner_uid = os.geteuid() if owner_uid is None else owner_uid
        self.firewall_cleanup = firewall_cleanup
        if service_uid is None:
            try:
                service_uid = pwd.getpwnam('warp-pipe-proxy').pw_uid
            except KeyError:
                pass
        self.service_uid = service_uid

    @staticmethod
    def present(path):
        return path.exists() or path.is_symlink()

    def check_parents(self, path):
        for parent in path.parents:
            if parent.is_symlink():
                raise ValueError(f'Refusing a symlink in managed path: {parent}')
            if parent == self.system_root:
                break

    def path(self, name):
        path = self.system_root / name.lstrip('/')
        self.check_parents(path)
        return path

    def private_directory(self, path, create=False):
        if create:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner_uid or info.st_mode & 0o077:
            raise ValueError(f'Expected an owner-only directory: {path}')

    def read_file(self, path, private=False):
        info = path.lstat()
        forbidden = 0o077 if private else 0o022
        if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid or info.st_mode & forbidden:
            raise ValueError(f'Refusing an unsafe or unowned file: {path}')
        return path.read_bytes()

    def target(self, name):
        if name not in ALL_FILES:
            raise ValueError(f'Not an installer-owned path: {name}')
        return self.path(name)

    def bundle_cache(self):
        """Only interpreter-generated caches of our own modules may accompany the bundle."""
        bundle = self.system_root / BUNDLE.lstrip('/')
        if not bundle.exists() and not bundle.is_symlink():
            return []
        info = bundle.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner_uid or info.st_mode & 0o022:
            raise ValueError(f'Unsafe managed bundle directory: {bundle}')
        allowed = set(BUNDLE_FILES) | {'__pycache__'}
        for child in bundle.iterdir():
            if child.name not in allowed:
                raise ValueError(f'Unknown bundle entry; preserve it and review manually before uninstall: {child}')
        cache = bundle / '__pycache__'
        if not cache.exists() and not cache.is_symlink():
            return []
        info = cache.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner_uid or info.st_mode & 0o022:
            raise ValueError(f'Unsafe Python cache directory: {cache}')
        modules = '|'.join(re.escape(Path(name).stem) for name in BUNDLE_FILES if name.endswith('.py'))
        pattern = rf'(?:{modules})\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc'
        paths = []
        for path in cache.iterdir():
            if not re.fullmatch(pattern, path.name):
                raise ValueError(f'Unknown Python cache entry; preserve it and review manually: {path}')
            self.read_file(path)
            paths.append(path)
        return paths

    def validate_manifest(self, value, require_core=True):
        files = value.get('files') if isinstance(value, dict) else None
        version = value.get('version') if isinstance(value, dict) else None
        required = OWNED_FILES if version == 3 else V2_FILES if version == 2 else LEGACY_FILES
        if (not isinstance(value, dict) or version not in (1, 2, 3) or type(value.get('container')) is not bool
                or not isinstance(files, dict) or not set(files).issubset(ALL_FILES)
                or (require_core and not set(required).issubset(files))
                or not all(isinstance(h, str) and re.fullmatch(r'[0-9a-f]{64}', h) for h in files.values())):
            raise ValueError('Invalid ownership manifest; reapply the current installer first')
        return value

    def read_manifest(self):
        return self.validate_manifest(json.loads(self.read_file(self.root / 'ownership.json', private=True)))

    def state(self):
        values = {name: self.read_file(self.root / name, private=True) for name in STATE_FILES}
        configure.validate(json.loads(values['settings.json']), json.loads(values['credentials.json']))
        return values

    def verify_owned(self, manifest, revoked_config=False):
        for name, expected in manifest['files'].items():
            path = self.target(name)
            if not self.present(path):
                continue
            contents = self.read_file(path)
            if digest(contents) != expected and not (name == CONFIG and revoked_config):
                raise ValueError(f'Managed file was changed; preserve it and review manually before uninstall: {path}')

    def record(self, container=False, apt_source_created=False):
        self.private_directory(self.root)
        self.check_install()
        self.state()
        self.read_file(self.root / 'installed', private=True)
        self.bundle_cache()
        previous = self.read_manifest()['files'] if self.present(self.root / 'ownership.json') else {}
        manifest = {'version': 3, 'container': bool(container), 'files': {
            name: digest(self.read_file(self.target(name))) for name in OWNED_FILES}}
        # Shared package files are never recorded; these paths are specific to this project.
        for name in HOST_FILES:
            if name in previous:
                manifest['files'][name] = previous[name]
        generated = (UNBOUND, *((FAIL2BAN,) if not container else ()))
        for name in generated:
            if self.present(self.target(name)):
                manifest['files'][name] = digest(self.read_file(self.target(name)))
        if apt_source_created:
            manifest['files'][APT_SOURCE] = digest(self.read_file(self.target(APT_SOURCE)))
        write_json(self.root / 'ownership.json', manifest)
        self.clear_revocation()
        sync_directory(self.root)

    def record_host_files(self, applied=False):
        """Record BBR files only after this run successfully wrote both of them."""
        if not applied:
            return
        self.private_directory(self.root)
        manifest = self.read_manifest()
        if manifest['container']:
            return
        for name in BBR_FILES:
            path = self.target(name)
            manifest['files'][name] = digest(self.read_file(path))
        write_json(self.root / 'ownership.json', manifest)

    def record_config(self):
        """Older installations may revoke access before adopting lifecycle metadata."""
        self.check_revocation_committed()
        path = self.root / 'ownership.json'
        if not path.exists() and not path.is_symlink():
            self.clear_revocation()
            return
        self.private_directory(self.root)
        manifest = self.read_manifest()
        manifest['files'][CONFIG] = digest(self.read_file(self.target(CONFIG)))
        write_json(path, manifest)
        self.clear_revocation()

    def clear_revocation(self):
        path = self.root / 'revocation-pending.json'
        if path.exists() or path.is_symlink():
            self.check_revocation_committed()
            # The shell publishes credentials/config with rename. Flush both
            # live files and those renames before making the durable intent
            # disappear; a failed flush must leave recovery required.
            live_files = ((self.root / 'credentials.json', True), (self.target(CONFIG), False))
            for live, private in live_files:
                self.read_file(live, private=private)
                with live.open('rb') as source:
                    os.fsync(source.fileno())
            for parent in dict.fromkeys(live.parent for live, _ in live_files):
                sync_directory(parent)
            path.unlink()
            sync_directory(self.root)

    def prepare_revoke(self, run_id):
        self.private_directory(self.root)
        self.refuse_pending_revocation()
        if not self.valid_run(run_id):
            raise ValueError('Invalid revocation recovery identifier')
        self.private_directory(self.backup_root)
        self.private_directory(self.backup_root / run_id)
        directory = self.backup_root / run_id / 'revocation'
        self.private_directory(directory)
        values = {name: self.read_file(directory / name, private=True) for name in STATE_FILES}
        configure.validate(json.loads(values['settings.json']), json.loads(values['credentials.json']))
        # Candidate files were copied by the shell; make them durable before publishing intent.
        for name in STATE_FILES:
            with (directory / name).open('rb') as source:
                os.fsync(source.fileno())
        sync_directory(directory)
        sync_directory(directory.parent)
        marker = {'format': REVOCATION_FORMAT, 'run': run_id,
                  'credentials_sha256': digest(values['credentials.json']),
                  'settings_sha256': digest(values['settings.json'])}
        write_json(self.root / 'revocation-pending.json', marker)

    def refuse_pending_revocation(self):
        path = self.root / 'revocation-pending.json'
        if path.exists() or path.is_symlink():
            raise ValueError('A revocation is unfinished; recover it before another credential change')

    def check_revocation_committed(self):
        path = self.root / 'revocation-pending.json'
        if not path.exists() and not path.is_symlink():
            return
        self.private_directory(self.root)
        marker = json.loads(self.read_file(path, private=True))
        if (not isinstance(marker, dict) or marker.get('format') != REVOCATION_FORMAT
                or not self.valid_run(marker.get('run'))):
            raise ValueError('Invalid pending-revocation marker; keep the proxy stopped and inspect its recovery copy')
        self.private_directory(self.backup_root)
        self.private_directory(self.backup_root / marker['run'])
        directory = self.backup_root / marker['run'] / 'revocation'
        self.private_directory(directory)
        values = {name: self.read_file(directory / name, private=True) for name in STATE_FILES}
        for name, key in (('credentials.json', 'credentials_sha256'), ('settings.json', 'settings_sha256')):
            if digest(values[name]) != marker.get(key):
                raise ValueError(f'Pending revocation recovery file was changed or corrupted: {directory / name}')
        configure.validate(json.loads(values['settings.json']), json.loads(values['credentials.json']))
        if self.read_file(self.root / 'credentials.json', private=True) != values['credentials.json']:
            raise ValueError(f'Unfinished revocation: keep the proxy stopped and recover credentials only from '
                             f'{directory / "credentials.json"} to {self.root / "credentials.json"}, then rerun install. '
                             'Do not restore pre-revocation credentials')

    def check_install(self):
        """A new install cannot race or conceal an interrupted destructive uninstall."""
        if self.present(self.path(PURGE_MARKER)):
            raise ValueError('Uninstall was interrupted; rerun uninstall from a trusted checkout before installing')
        self.check_revocation_committed()

    @staticmethod
    def valid_run(value):
        return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', value) is not None

    def service_state(self, service='warp-pipe-proxy'):
        result = self.run(['systemctl', 'show', '-p', 'LoadState', '-p', 'ActiveState', service],
                          capture_output=True, text=True, timeout=30, check=True)
        lines = result.stdout.strip().splitlines()
        if len(lines) != 2 or any('=' not in line for line in lines):
            raise ValueError(f'Cannot determine the {service} service state safely')
        values = dict(line.split('=', 1) for line in lines)
        if (set(values) != {'LoadState', 'ActiveState'}
                or values['LoadState'] not in ('loaded', 'not-found', 'masked')
                or values['ActiveState'] not in ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading')):
            raise ValueError(f'Cannot determine the {service} service state safely')
        return values

    def project_directories(self):
        return (self.root, self.backup_root, self.path(LOG_DIRECTORY), self.path(STATE_DIRECTORY))

    def mountpoints(self):
        # mountinfo includes bind mounts on the same filesystem, which ismount()
        # cannot reliably distinguish from ordinary subdirectories.
        result = []
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            fields = line.split()
            if len(fields) < 6 or ' - ' not in line or not fields[4].startswith('/'):
                raise ValueError('Cannot inspect mount points safely before uninstall')
            name = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), fields[4])
            result.append(Path(name))
        if not result:
            raise ValueError('No mount information is available for safe uninstall')
        return result

    def verify_project_directories(self):
        # Only these fixed project directories are recursively deleted. Nested links
        # are unlinked by fd-based rmtree, never followed outside the directory.
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError('Safe directory removal is unavailable on this platform')
        mounts = self.mountpoints()
        for directory in self.project_directories():
            self.check_parents(directory)
            if not self.present(directory):
                continue
            info = directory.lstat()
            owners = {self.owner_uid}
            if directory == self.path(STATE_DIRECTORY) and self.service_uid is not None:
                owners.add(self.service_uid)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners:
                raise ValueError(f'Refusing an unowned or symlinked project directory: {directory}')
            if any(directory == mount or directory in mount.parents for mount in mounts):
                raise ValueError(f'Unmount project data and nested bind mounts before uninstall: {directory}')
            for current, names, _ in os.walk(directory, followlinks=False):
                if os.path.ismount(current):
                    raise ValueError(f'Unmount the project data directory before uninstall: {current}')
                names[:] = [name for name in names if not (Path(current) / name).is_symlink()]

    def read_purge_marker(self):
        value = json.loads(self.read_file(self.path(PURGE_MARKER), private=True))
        if (not isinstance(value, dict) or value.get('format') != PURGE_FORMAT
                or type(value.get('revoked_config')) is not bool
                or not isinstance(value.get('reload'), list)
                or any(service not in ('unbound', 'fail2ban') for service in value['reload'])):
            raise ValueError('Invalid unfinished-uninstall marker; inspect it before continuing')
        self.validate_manifest(value.get('ownership'), require_core=False)
        return value

    def cleanup_firewall(self):
        if self.firewall_cleanup is not None:
            return self.firewall_cleanup(run=self.run)
        import uninstall_firewall
        return uninstall_firewall.remove_proxy_rules(run=self.run)

    def uninstall(self):
        """Delete owned components and all project data without making any backup."""
        marker_path = self.path(PURGE_MARKER)
        self.verify_project_directories()
        if self.present(marker_path):
            marker = self.read_purge_marker()
            manifest = marker['ownership']
        else:
            manifest_path = self.root / 'ownership.json'
            if self.present(manifest_path):
                self.private_directory(self.root)
                manifest = self.read_manifest()
            else:
                # No ownership means no permission to remove shared-location files.
                for name in OWNED_FILES:
                    if self.present(self.target(name)):
                        raise ValueError(f'No ownership manifest for {name}; review the file before uninstall')
                if not any(self.present(directory) for directory in self.project_directories()):
                    return False
                manifest = {'version': 3, 'container': False, 'files': {}}
            pending = self.root / 'revocation-pending.json'
            revoked_config = self.present(pending)
            if revoked_config:
                # Purge must work even when intended credentials or JSON are corrupt.
                # Presence of the private root-owned intent permits deleting a
                # server config committed before ownership recording could finish.
                self.read_file(pending, private=True)
            marker = {'format': PURGE_FORMAT, 'ownership': manifest,
                      'revoked_config': revoked_config, 'reload': []}

        self.verify_owned(manifest, revoked_config=marker['revoked_config'])
        self.bundle_cache()
        for name in OWNED_FILES:
            if name not in manifest['files'] and self.present(self.target(name)):
                raise ValueError(f'File is not recorded as owned; review it before uninstall: {name}')
        for name in HOST_FILES:
            if name not in manifest['files'] and self.present(self.target(name)):
                print(f'WARN: retaining an unrecorded host file: {name}')
        if not self.present(marker_path):
            for name, service in ((UNBOUND, 'unbound'), (FAIL2BAN, 'fail2ban')):
                if name in manifest['files'] and self.service_state(service)['ActiveState'] == 'active':
                    marker['reload'].append(service)
            # Contains only hashes, paths and service names, never copied user data.
            write_json(marker_path, marker)

        unit = self.target(UNIT)
        if self.present(unit):
            self.run(['systemctl', 'disable', '--now', 'warp-pipe-proxy'], check=True, timeout=30)
        else:
            self.run(['systemctl', 'daemon-reload'], check=True, timeout=30)
        state = self.service_state()
        if state['ActiveState'] != 'inactive':
            raise ValueError('Proxy is not stopped; refusing to delete its files or data')
        if not self.present(unit) and state['LoadState'] != 'not-found':
            raise ValueError('Unexpected replacement proxy unit; review it before continuing uninstall')
        if not manifest['container'] and any(name in manifest['files'] for name in LEGACY_FILES):
            self.cleanup_firewall()
        for name in manifest['files']:
            self.target(name).unlink(missing_ok=True)
        for path in self.bundle_cache():
            path.unlink()
        bundle = self.path(BUNDLE)
        cache = bundle / '__pycache__'
        if cache.exists():
            cache.rmdir()
        for directory in (bundle, self.target(CONFIG).parent):
            if directory.exists() and not any(directory.iterdir()):
                directory.rmdir()
                sync_directory(directory.parent)
        for parent in {self.target(name).parent for name in manifest['files']}:
            if parent.exists():
                sync_directory(parent)
        # Remove all retained keys, old snapshots, pending intents, logs and state.
        # This also happens before any final service reload that might fail.
        for directory in self.project_directories():
            if directory.exists():
                shutil.rmtree(directory)
                sync_directory(directory.parent)
        self.run(['systemctl', 'daemon-reload'], check=True, timeout=30)
        for service in marker['reload']:
            # try-restart never starts a service that has since become inactive.
            self.run(['systemctl', 'try-restart', service], check=True, timeout=30)
        marker_path.unlink()
        sync_directory(marker_path.parent)
        return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check-install', 'prepare-revoke', 'record', 'record-host-files', 'record-config', 'uninstall'))
    parser.add_argument('--container', action='store_true')
    parser.add_argument('--apt-source-created', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--applied', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--run')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run lifecycle operations with sudo/root')
    lifecycle = Lifecycle()
    if args.action == 'check-install':
        lifecycle.check_install()
    elif args.action == 'prepare-revoke':
        if not args.run:
            parser.error('prepare-revoke requires --run')
        lifecycle.prepare_revoke(args.run)
    elif args.action == 'record':
        lifecycle.record(args.container, apt_source_created=args.apt_source_created)
    elif args.action == 'record-host-files':
        lifecycle.record_host_files(applied=args.applied)
    elif args.action == 'record-config':
        lifecycle.record_config()
    elif args.action == 'uninstall':
        changed = lifecycle.uninstall()
        print('Proxy and project data deleted; no backup was created.' if changed else 'No installed proxy or project data remains.')
        print('Shared packages, service account, APT key, SSH/firewall policy and system journal are retained.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(f'ERROR: {error}. If uninstall was interrupted, rerun it from a trusted checkout.')
