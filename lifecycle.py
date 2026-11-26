"""Conservative proxy removal and recovery; host-wide configuration is retained."""

import argparse
import hashlib
import json
import os
from pathlib import Path
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
                'probe.py', 'admin.py', 'activity.py', 'lifecycle.py', '.managed')
OWNED_FILES = (CONFIG, UNIT, LAUNCHER, *(BUNDLE + '/' + name for name in BUNDLE_FILES))
STATE_FILES = ('settings.json', 'credentials.json')
FORMAT = 'warp-pipe-proxy-recovery-v1'
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
    """Publish a complete root-only file before a recovery marker can reference it."""
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
                 system_root=Path('/'), run=subprocess.run, owner_uid=None):
        self.root = Path(root)
        self.backup_root = Path(backup_root)
        self.system_root = Path(system_root)
        self.run = run
        self.owner_uid = os.geteuid() if owner_uid is None else owner_uid

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
        if name not in OWNED_FILES:
            raise ValueError(f'Not an installer-owned path: {name}')
        path = self.system_root / name.lstrip('/')
        for parent in path.parents:
            if parent == self.system_root.parent:
                break
            if parent.is_symlink():
                raise ValueError(f'Refusing a symlink in managed path: {parent}')
            if parent == self.system_root:
                break
        return path

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

    def read_manifest(self, path=None):
        value = json.loads(self.read_file(path or self.root / 'ownership.json', private=True))
        files = value.get('files') if isinstance(value, dict) else None
        if (not isinstance(value, dict) or value.get('version') != 1 or type(value.get('container')) is not bool
                or not isinstance(files, dict) or set(files) != set(OWNED_FILES)
                or not all(isinstance(h, str) and re.fullmatch(r'[0-9a-f]{64}', h) for h in files.values())):
            raise ValueError('Invalid ownership manifest; reapply the current installer first')
        return value

    def state(self):
        values = {name: self.read_file(self.root / name, private=True) for name in STATE_FILES}
        configure.validate(json.loads(values['settings.json']), json.loads(values['credentials.json']))
        return values

    def verify_owned(self, manifest, allow_missing=False):
        for name, expected in manifest['files'].items():
            path = self.target(name)
            if not path.exists() and not path.is_symlink() and allow_missing:
                continue
            if digest(self.read_file(path)) != expected:
                raise ValueError(f'Managed file was changed; preserve it and review manually before uninstall: {path}')

    def record(self, container=False):
        self.private_directory(self.root)
        self.check_revocation_committed()
        self.state()
        self.read_file(self.root / 'installed', private=True)
        self.bundle_cache()
        manifest = {'version': 1, 'container': bool(container), 'files': {
            name: digest(self.read_file(self.target(name))) for name in OWNED_FILES}}
        write_json(self.root / 'ownership.json', manifest)
        (self.root / 'uninstalled.json').unlink(missing_ok=True)
        self.clear_revocation()
        sync_directory(self.root)

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
            raise ValueError('A revocation is unfinished; recover it before uninstall, restore or another credential change')

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

    def marker(self):
        value = json.loads(self.read_file(self.root / 'uninstalled.json', private=True))
        if (not isinstance(value, dict) or value.get('format') != FORMAT or value.get('phase') not in ('pending', 'complete')
                or not self.valid_run(value.get('run'))
                or not re.fullmatch(r'[0-9a-f]{64}', str(value.get('metadata_sha256', '')))):
            raise ValueError('Invalid uninstall recovery marker')
        return value

    def check_install(self):
        """A new installation may not conceal interrupted removal of the old one."""
        self.check_revocation_committed()
        path = self.root / 'uninstalled.json'
        if not path.exists() and not path.is_symlink():
            return
        self.private_directory(self.root)
        if self.marker()['phase'] == 'pending':
            raise ValueError('Uninstall was interrupted; rerun uninstall from a trusted checkout before installing')

    @staticmethod
    def valid_run(value):
        return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', value) is not None

    def snapshot(self, run_id, manifest):
        if not self.valid_run(run_id):
            raise ValueError('Invalid recovery identifier')
        self.private_directory(self.backup_root, create=True)
        destination = self.backup_root / run_id
        if destination.exists() or destination.is_symlink():
            raise ValueError(f'Recovery path already exists: {destination}')
        values = self.state()
        metadata = {'format': FORMAT, 'run': run_id, 'container': manifest['container'],
                    'state_sha256': {name: digest(data) for name, data in values.items()}}
        ownership = (json.dumps(manifest, indent=2) + '\n').encode()
        metadata['ownership_sha256'] = digest(ownership)
        temporary = Path(tempfile.mkdtemp(prefix='.uninstall-', dir=self.backup_root))
        try:
            for name, data in values.items():
                write_private(temporary / name, data)
            write_private(temporary / 'ownership.json', ownership)
            write_json(temporary / 'recovery.json', metadata)
            metadata_hash = digest((temporary / 'recovery.json').read_bytes())
            temporary.rename(destination)
            sync_directory(self.backup_root)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        marker = {'format': FORMAT, 'run': run_id, 'phase': 'pending', 'metadata_sha256': metadata_hash}
        write_json(self.root / 'uninstalled.json', marker)
        return marker

    def recovery(self, marker):
        self.private_directory(self.backup_root)
        directory = self.backup_root / marker['run']
        self.private_directory(directory)
        raw = self.read_file(directory / 'recovery.json', private=True)
        if digest(raw) != marker['metadata_sha256']:
            raise ValueError('Recovery metadata was changed or corrupted')
        metadata = json.loads(raw)
        if (not isinstance(metadata, dict) or metadata.get('format') != FORMAT or metadata.get('run') != marker['run']
                or type(metadata.get('container')) is not bool
                or not isinstance(metadata.get('state_sha256'), dict)
                or set(metadata['state_sha256']) != set(STATE_FILES)):
            raise ValueError('Invalid recovery metadata')
        raw_manifest = self.read_file(directory / 'ownership.json', private=True)
        if digest(raw_manifest) != metadata.get('ownership_sha256'):
            raise ValueError('Recovery ownership manifest was changed or corrupted')
        manifest = self.read_manifest(directory / 'ownership.json')
        if manifest['container'] != metadata['container']:
            raise ValueError('Recovery mode does not match its ownership manifest')
        current = self.state()
        for name in STATE_FILES:
            archived = self.read_file(directory / name, private=True)
            if digest(archived) != metadata['state_sha256'][name] or current[name] != archived:
                raise ValueError(f'Retained {name} differs from the uninstall snapshot; refusing to overwrite newer state')
        if self.read_manifest() != manifest:
            raise ValueError('Current ownership differs from the uninstall snapshot')
        return metadata, manifest, current

    def service_state(self):
        result = self.run(['systemctl', 'show', '-p', 'LoadState', '-p', 'ActiveState', 'warp-pipe-proxy'],
                          capture_output=True, text=True, timeout=30, check=True)
        lines = result.stdout.strip().splitlines()
        if len(lines) != 2 or any('=' not in line for line in lines):
            raise ValueError('Cannot determine the proxy service state safely')
        values = dict(line.split('=', 1) for line in lines)
        if (set(values) != {'LoadState', 'ActiveState'}
                or values['LoadState'] not in ('loaded', 'not-found')
                or values['ActiveState'] not in ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading')):
            raise ValueError('Cannot determine the proxy service state safely')
        return values

    def uninstall(self, run_id):
        self.refuse_pending_revocation()
        self.private_directory(self.root)
        installed = self.root / 'installed'
        if installed.exists() or installed.is_symlink():
            self.read_file(installed, private=True)
        marker_path = self.root / 'uninstalled.json'
        if marker_path.exists() or marker_path.is_symlink():
            marker = self.marker()
            _, manifest, _ = self.recovery(marker)
            self.verify_owned(manifest, allow_missing=True)
            self.bundle_cache()
            if marker['phase'] == 'complete':
                if (self.root / 'installed').exists() or any(self.target(name).exists() for name in OWNED_FILES):
                    raise ValueError('Files appeared after uninstall; refusing to remove a newer installation')
                self.require_stopped(require_missing=True)
                return marker['run']
        else:
            self.read_file(self.root / 'managed', private=True)
            self.read_file(self.root / 'installed', private=True)
            try:
                manifest = self.read_manifest()
            except FileNotFoundError:
                raise ValueError('No ownership manifest; reapply this installer version before uninstall') from None
            self.verify_owned(manifest)
            self.bundle_cache()
            marker = self.snapshot(run_id, manifest)

        # The durable pending marker permits a later invocation to resume after interruption.
        if self.target(UNIT).exists():
            self.run(['systemctl', 'disable', '--now', 'warp-pipe-proxy'], check=True, timeout=30)
        elif self.service_state()['ActiveState'] != 'inactive':
            self.run(['systemctl', 'stop', 'warp-pipe-proxy'], check=True, timeout=30)
        self.require_stopped()
        for name in OWNED_FILES:
            self.target(name).unlink(missing_ok=True)
        for path in self.bundle_cache():
            path.unlink()
        bundle = self.system_root / BUNDLE.lstrip('/')
        cache = bundle / '__pycache__'
        if cache.exists():
            cache.rmdir()
        # Make all removals durable before publishing a completed recovery marker.
        for parent in {self.target(name).parent for name in OWNED_FILES}:
            if parent.exists():
                sync_directory(parent)
        if bundle.exists() and not any(bundle.iterdir()):
            bundle.rmdir()
            sync_directory(bundle.parent)
        (self.root / 'installed').unlink(missing_ok=True)
        sync_directory(self.root)
        self.run(['systemctl', 'daemon-reload'], check=True, timeout=30)
        marker['phase'] = 'complete'
        write_json(marker_path, marker)
        return marker['run']

    def require_stopped(self, require_missing=False):
        state = self.service_state()
        if state['ActiveState'] != 'inactive':
            raise ValueError('Proxy service is not stopped; recovery/removal cannot continue')
        if require_missing and state['LoadState'] != 'not-found':
            raise ValueError('Another proxy unit is loaded after uninstall; review it before restoring')

    def prepare_restore(self, run_id, out):
        self.refuse_pending_revocation()
        self.private_directory(self.root)
        if (self.root / 'installed').exists() or (self.root / 'installed').is_symlink():
            raise ValueError('An installation already exists; historical credentials will not replace it')
        marker = self.marker()
        if marker['phase'] != 'complete':
            raise ValueError('Uninstall was interrupted; rerun uninstall before restoring')
        if run_id != marker['run']:
            raise ValueError('Only the latest completed uninstall snapshot can be restored')
        metadata, _, values = self.recovery(marker)
        for name in OWNED_FILES:
            target = self.target(name)
            if target.exists() or target.is_symlink():
                raise ValueError(f'Path appeared after uninstall; review it before restoring: {target}')
        bundle = self.system_root / BUNDLE.lstrip('/')
        if bundle.exists() or bundle.is_symlink():
            raise ValueError(f'Bundle appeared after uninstall; review it before restoring: {bundle}')
        self.require_stopped(require_missing=True)
        self.private_directory(out, create=True)
        for name, data in values.items():
            write_private(out / name, data)
        return metadata['container']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check-install', 'prepare-revoke', 'record', 'record-config', 'uninstall', 'prepare-restore'))
    parser.add_argument('--container', action='store_true')
    parser.add_argument('--run')
    parser.add_argument('--backup')
    parser.add_argument('--out', type=Path)
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
        lifecycle.record(args.container)
    elif args.action == 'record-config':
        lifecycle.record_config()
    elif args.action == 'uninstall':
        if not args.run:
            parser.error('uninstall requires --run')
        run_id = lifecycle.uninstall(args.run)
        print(f'Proxy removed. Recovery snapshot: {lifecycle.backup_root / run_id}')
        print('Retained: private settings/credentials, UFW/SSH rules (including proxy allowances),')
        print('Unbound, fail2ban, BBR settings, packages, service account, logs and backups.')
        print(f'Restore from a trusted checkout: sudo ./warp-pipe-proxy.sh restore --backup {run_id}')
    else:
        if not args.backup or args.out is None:
            parser.error('prepare-restore requires --backup and --out')
        print(int(lifecycle.prepare_restore(args.backup, args.out)))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(f'ERROR: {error}. Inspect the retained recovery data before retrying.')
