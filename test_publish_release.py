import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


BASE = Path(__file__).parent
COMMIT = 'a' * 40


class PublishReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for directory in ('tests', 'docs/releases', 'artifacts', 'bin'):
            (self.root / directory).mkdir(parents=True)
        for name in ('VERSION', 'dependencies.lock.json', 'release.py', 'tests/publish_release.sh'):
            shutil.copyfile(BASE / name, self.root / name)
        self.lock_bytes = (self.root / 'dependencies.lock.json').read_bytes()
        self.lock = json.loads(self.lock_bytes)
        self.version = self.lock['release']
        (self.root / f'docs/releases/v{self.version}.md').write_text('# Test release\n')
        self.inventory = {
            'schema': 1, 'release': self.version, 'source_commit': COMMIT,
            'scope': 'ubuntu-24.04-amd64-vm', 'architecture': 'amd64',
            'os_release': {'ID': 'ubuntu', 'VERSION_ID': '24.04'},
            'lock_sha256': hashlib.sha256(self.lock_bytes).hexdigest(), 'lock': self.lock,
            'direct_packages': {name: {'version': version, 'architecture': 'amd64'}
                                for group in self.lock['packages'].values()
                                for name, version in group.items()},
            'packages': [{'name': 'sing-box', 'version': '1.14.4', 'architecture': 'amd64'}],
            'sing_box_sha256': 'b' * 64,
        }
        (self.root / 'bin/git').write_text('''#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
if args == ['rev-parse', 'HEAD']:
    print(os.environ.get('FAKE_HEAD', os.environ['GITHUB_SHA']))
elif args[:4] == ['ls-remote', '--exit-code', '--tags', 'origin']:
    if os.environ.get('FAKE_REMOTE_ERROR'):
        sys.exit(1)
    if not os.environ.get('FAKE_TAG_SHA'):
        sys.exit(2)
    print(os.environ['FAKE_TAG_SHA'] + '\\t' + args[4])
    if os.environ.get('FAKE_PEELED_SHA'):
        print(os.environ['FAKE_PEELED_SHA'] + '\\t' + args[5])
else:
    raise SystemExit('Unexpected git command')
''')
        (self.root / 'bin/gh').write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALL_LOG'], 'a') as stream:
    stream.write(json.dumps(args) + '\\n')
if args[0] == 'api':
    if os.environ.get('FAKE_API_ERROR'):
        raise SystemExit('API access failed')
    print(os.environ.get('FAKE_RELEASES', ''))
elif args[:2] == ['release', 'create']:
    assets = {Path(value).name: Path(value).read_text()
              for value in args[3:args.index('--repo')]}
    notes = Path(args[args.index('--notes-file') + 1]).read_text()
    Path(os.environ['PUBLISH_CAPTURE']).write_text(json.dumps({
        'args': args, 'assets': assets, 'notes': notes}))
else:
    raise SystemExit('Unexpected gh mutation')
''')
        for name in ('git', 'gh'):
            (self.root / 'bin' / name).chmod(0o755)
        self.environment = {
            **os.environ, 'PATH': str(self.root / 'bin') + ':' + os.environ['PATH'],
            'TMPDIR': str(self.root),
            'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main',
            'GITHUB_SHA': COMMIT, 'GITHUB_REPOSITORY': 'example/project', 'GITHUB_RUN_ID': '123',
            'GITHUB_SERVER_URL': 'https://github.com', 'GH_TOKEN': 'unused-test-token',
            'CALL_LOG': str(self.root / 'calls.jsonl'), 'PUBLISH_CAPTURE': str(self.root / 'published.json'),
        }

    def invoke(self, **environment):
        (self.root / 'artifacts/tested-environment.json').write_text(json.dumps(self.inventory))
        return subprocess.run(['bash', 'tests/publish_release.sh'], cwd=self.root,
                              env={**self.environment, **environment}, capture_output=True, text=True)

    def assert_not_published(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.root / 'published.json').exists())

    def test_publication_uses_exact_commit_verified_assets_and_current_run_link(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        captured = json.loads((self.root / 'published.json').read_text())
        self.assertEqual(captured['args'][2], f'v{self.version}')
        self.assertEqual(captured['args'][captured['args'].index('--target') + 1], COMMIT)
        self.assertEqual(set(captured['assets']),
                         {'VERSION', 'dependencies.lock.json', 'tested-environment.json', 'SHA256SUMS'})
        for line in captured['assets']['SHA256SUMS'].splitlines():
            checksum, name = line.split(maxsplit=1)
            self.assertEqual(checksum, hashlib.sha256(captured['assets'][name].encode()).hexdigest())
        self.assertIn('https://github.com/example/project/actions/runs/123', captured['notes'])
        self.assertIn(COMMIT, captured['notes'])
        self.assertEqual((self.root / f'docs/releases/v{self.version}.md').read_text(), '# Test release\n')

    def test_pull_request_and_manual_run_cannot_publish(self):
        for event in ('pull_request', 'workflow_dispatch'):
            with self.subTest(event=event):
                self.assert_not_published(self.invoke(GITHUB_EVENT_NAME=event))
        self.assertFalse((self.root / 'calls.jsonl').exists())

    def test_inventory_mismatch_blocks_all_api_calls(self):
        for key, wrong in (('source_commit', 'c' * 40), ('lock_sha256', '0' * 64),
                           ('release', '9.9.9'), ('scope', 'container')):
            with self.subTest(key=key):
                original = self.inventory[key]
                self.inventory[key] = wrong
                self.assert_not_published(self.invoke())
                self.inventory[key] = original
        self.assertFalse((self.root / 'calls.jsonl').exists())

    def test_existing_release_is_left_unchanged(self):
        result = self.invoke(FAKE_RELEASES=f'v{self.version}', FAKE_TAG_SHA='c' * 40)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('leaving it unchanged', result.stdout)
        self.assertFalse((self.root / 'published.json').exists())

    def test_existing_wrong_tag_is_never_moved_or_published(self):
        result = self.invoke(FAKE_TAG_SHA='c' * 40)
        self.assert_not_published(result)
        self.assertIn('does not point to the tested commit', result.stderr)

    def test_annotated_tag_is_checked_using_its_peeled_commit(self):
        result = self.invoke(FAKE_TAG_SHA='c' * 40, FAKE_PEELED_SHA=COMMIT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'published.json').is_file())

    def test_remote_lookup_errors_cannot_be_treated_as_absent_release_or_tag(self):
        for key in ('FAKE_API_ERROR', 'FAKE_REMOTE_ERROR'):
            with self.subTest(error=key):
                self.assert_not_published(self.invoke(**{key: 'yes'}))


if __name__ == '__main__':
    unittest.main()
