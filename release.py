"""Read release metadata and check the exact supported package versions without writes."""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess


BASE = Path(__file__).resolve().parent
VERSION_PATTERN = r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?'
PACKAGE_PATTERN = r'[a-z0-9][a-z0-9+.-]+'
DEB_VERSION_PATTERN = r'[0-9][0-9A-Za-z.+:~\-]*'
GROUPS = ('common', 'host', 'engine')


def release_version(base=BASE):
    version = (Path(base) / 'VERSION').read_text().strip()
    if not re.fullmatch(VERSION_PATTERN, version):
        raise ValueError('Invalid project VERSION')
    return version


class Release:
    def __init__(self, base=BASE, system_root=Path('/'), run=subprocess.run, which=shutil.which):
        self.base = Path(base)
        self.system_root = Path(system_root)
        self.run = run
        self.which = which
        self.version = release_version(self.base)
        self.lock = json.loads((self.base / 'dependencies.lock.json').read_text())
        self.validate_metadata()

    def validate_metadata(self):
        data = self.lock
        if (not isinstance(data, dict) or type(data.get('schema')) is not int or data['schema'] != 1
                or data.get('release') != self.version):
            raise ValueError('Invalid dependency lock schema or release version')
        platform = data.get('os')
        if (not isinstance(platform, dict) or set(platform) != {'id', 'version_id'}
                or not all(isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]*', value)
                           for value in platform.values())):
            raise ValueError('Invalid operating system in dependency lock')
        architectures = data.get('architectures')
        if (not isinstance(architectures, list) or not architectures
                or not all(isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9-]*', value)
                           for value in architectures) or len(set(architectures)) != len(architectures)):
            raise ValueError('Invalid architectures in dependency lock')
        groups = data.get('packages')
        if not isinstance(groups, dict) or set(groups) != set(GROUPS):
            raise ValueError('Invalid package groups in dependency lock')
        seen = set()
        for group in GROUPS:
            packages = groups[group]
            if not isinstance(packages, dict) or not packages:
                raise ValueError(f'Empty or invalid {group} package group')
            for name, version in packages.items():
                if (not re.fullmatch(PACKAGE_PATTERN, name) or name in seen
                        or not isinstance(version, str) or not re.fullmatch(DEB_VERSION_PATTERN, version)):
                    raise ValueError(f'Invalid or duplicate exact package pin: {name}')
                seen.add(name)
        if set(groups['engine']) != {'sing-box'}:
            raise ValueError('The engine package group must contain only sing-box')
        engine_version = data.get('engine_version')
        if not isinstance(engine_version, str) or not re.fullmatch(VERSION_PATTERN, engine_version):
            raise ValueError('Invalid sing-box runtime version in dependency lock')
        if not isinstance(data.get('provenance'), (str, dict)) or not data['provenance']:
            raise ValueError('Dependency lock must identify its provenance')

    def command(self, arguments):
        return self.run(arguments, capture_output=True, text=True, check=False, timeout=30,
                        env={**os.environ, 'LC_ALL': 'C'})

    def selected(self, container=False, engine=True):
        packages = dict(self.lock['packages']['common'])
        if not container:
            packages.update(self.lock['packages']['host'])
        if engine:
            packages.update(self.lock['packages']['engine'])
        return packages

    def specs(self, container=False):
        return [f'{name}={version}' for name, version in self.selected(container, engine=False).items()]

    def package(self, name):
        for group in GROUPS:
            if name in self.lock['packages'][group]:
                return f'{name}={self.lock["packages"][group][name]}'
        raise ValueError(f'Package is not pinned by this release: {name}')

    def platform(self):
        values = {}
        for line in (self.system_root / 'etc/os-release').read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            key, separator, value = line.partition('=')
            if key not in ('ID', 'VERSION_ID'):
                continue
            parsed = shlex.split(value, comments=True)
            if not separator or len(parsed) != 1 or key in values:
                raise ValueError('Cannot determine operating system from /etc/os-release')
            values[key] = parsed[0]
        expected = self.lock['os']
        if values != {'ID': expected['id'], 'VERSION_ID': expected['version_id']}:
            raise ValueError(f'Release {self.version} supports {expected["id"]} {expected["version_id"]}; '
                             'this operating system is not in the dependency lock')
        result = self.command(['dpkg', '--print-architecture'])
        architecture = result.stdout.strip()
        if result.returncode != 0 or architecture not in self.lock['architectures']:
            raise ValueError(f'Unsupported or unknown architecture: {architecture or "unknown"}; '
                             f'expected {", ".join(self.lock["architectures"])}')
        return architecture

    def installed_version(self, name):
        result = self.command(['dpkg-query', '--show', '--showformat=${db:Status-Status}\t${Version}\n', name])
        if result.returncode == 1 and not result.stdout.strip():
            return None
        if result.returncode != 0:
            raise ValueError(f'Cannot inspect installed package: {name}')
        lines = result.stdout.splitlines()
        fields = lines[0].split('\t') if len(lines) == 1 else []
        if len(fields) != 2:
            raise ValueError(f'Invalid package status for {name}')
        status, version = fields
        if status in ('not-installed', 'config-files'):
            return None
        if status != 'installed' or not re.fullmatch(DEB_VERSION_PATTERN, version):
            raise ValueError(f'Package {name} is not fully installed: {status}; repair it before installing')
        return version

    def compare(self, actual, operator, expected):
        result = self.command(['dpkg', '--compare-versions', actual, operator, expected])
        if result.returncode not in (0, 1):
            raise ValueError(f'Cannot compare package versions {actual} and {expected}')
        return result.returncode == 0

    def verify_engine(self, architecture, allow_missing):
        expected_version = self.lock['packages']['engine']['sing-box']
        actual_version = self.installed_version('sing-box')
        executable = self.which('sing-box')
        expected_path = self.system_root / 'usr/bin/sing-box'
        if actual_version is None:
            if executable is not None or expected_path.exists() or expected_path.is_symlink():
                raise ValueError('An unmanaged or manual sing-box binary exists; refusing to replace it')
            if allow_missing:
                return
            raise ValueError(f'Required package sing-box={expected_version} is not installed')
        if actual_version != expected_version:
            raise ValueError(f'Installed sing-box {actual_version} differs from required {expected_version}; '
                             'no automatic engine upgrade or downgrade is permitted')
        if executable is None:
            raise ValueError('The installed sing-box package has no executable on PATH')
        if (Path(executable).resolve(strict=True) != expected_path
                or not stat.S_ISREG(expected_path.lstat().st_mode)):
            raise ValueError('sing-box on PATH is shadowed or not the packaged /usr/bin/sing-box; '
                             'refusing to use a manual binary')
        ownership = self.command(['dpkg-query', '--search', '/usr/bin/sing-box'])
        owners = ownership.stdout.splitlines()
        valid_owners = {f'sing-box: /usr/bin/sing-box', f'sing-box:{architecture}: /usr/bin/sing-box'}
        if ownership.returncode != 0 or len(owners) != 1 or owners[0] not in valid_owners:
            raise ValueError('Cannot verify that /usr/bin/sing-box belongs to the sing-box package')
        runtime = self.command([str(expected_path), 'version'])
        lines = runtime.stdout.splitlines()
        expected_line = f'sing-box version {self.lock["engine_version"]}'
        if runtime.returncode != 0 or not lines or lines[0] != expected_line:
            raise ValueError(f'The packaged sing-box binary does not report {expected_line}')

    def preflight(self, container=False):
        architecture = self.platform()
        self.verify_engine(architecture, allow_missing=True)
        for name, expected in self.selected(container, engine=False).items():
            actual = self.installed_version(name)
            if actual is None or actual == expected or self.compare(actual, 'lt', expected):
                continue
            if self.compare(actual, 'gt', expected):
                raise ValueError(f'Installed {name} {actual} is newer than required {expected}; '
                                 'refusing an automatic downgrade')
            raise ValueError(f'Installed {name} {actual} differs from the exact required version {expected}')

    def verify(self, container=False):
        architecture = self.platform()
        self.verify_engine(architecture, allow_missing=False)
        for name, expected in self.selected(container, engine=False).items():
            actual = self.installed_version(name)
            if actual != expected:
                raise ValueError(f'Required {name}={expected}; installed version is {actual or "missing"}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('version')
    for action in ('preflight', 'specs', 'verify'):
        commands.add_parser(action).add_argument('--container', action='store_true')
    commands.add_parser('package').add_argument('name')
    args = parser.parse_args()
    if args.action == 'version':
        print(release_version())
        return
    release = Release()
    if args.action == 'package':
        print(release.package(args.name))
    elif args.action == 'specs':
        print('\n'.join(release.specs(args.container)))
    elif args.action == 'preflight':
        release.preflight(args.container)
    elif args.action == 'verify':
        release.verify(args.container)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(f'ERROR: {error}')
