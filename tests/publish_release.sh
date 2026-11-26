#!/usr/bin/env bash
# Only the main-push job with successful unit and VM dependencies invokes this.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
[[ ${GITHUB_ACTIONS:-} == true && ${GITHUB_EVENT_NAME:-} == push && ${GITHUB_REF:-} == refs/heads/main ]] || {
    echo 'Release publication requires a main-branch push in GitHub Actions' >&2
    exit 1
}
: "${GH_TOKEN:?The release job requires its GitHub token}"
: "${GITHUB_REPOSITORY:?Missing repository}"
: "${GITHUB_RUN_ID:?Missing workflow run}"
: "${GITHUB_SHA:?Missing tested commit}"
[[ $GITHUB_SHA =~ ^[0-9a-f]{40}$ && $GITHUB_RUN_ID =~ ^[0-9]+$ ]]
[[ $(git rev-parse HEAD) == "$GITHUB_SHA" ]] || {
    echo 'The release checkout is not the tested commit' >&2
    exit 1
}

version=$(python3 -B - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
from release import Release

release = Release()
inventory = json.loads(Path('artifacts/tested-environment.json').read_text())
lock_bytes = Path('dependencies.lock.json').read_bytes()
expected = release.selected()
actual = {name: value['version'] for name, value in inventory['direct_packages'].items()}
checks = (
    inventory.get('schema') == 1,
    inventory.get('release') == release.version,
    inventory.get('source_commit') == os.environ['GITHUB_SHA'],
    inventory.get('scope') == 'ubuntu-24.04-amd64-vm',
    inventory.get('architecture') == 'amd64',
    inventory.get('architecture') in release.lock['architectures'],
    inventory['os_release'].get('ID') == release.lock['os']['id'] == 'ubuntu',
    inventory['os_release'].get('VERSION_ID') == release.lock['os']['version_id'] == '24.04',
    inventory.get('lock_sha256') == hashlib.sha256(lock_bytes).hexdigest(),
    inventory.get('lock') == release.lock,
    actual == expected,
    isinstance(inventory.get('packages'), list) and bool(inventory['packages']),
    re.fullmatch(r'[0-9a-f]{64}', inventory.get('sing_box_sha256', '')) is not None,
)
if not all(checks):
    raise SystemExit('Release metadata and the verified VM inventory disagree')
if not Path(f'docs/releases/v{release.version}.md').is_file():
    raise SystemExit('Release notes are missing')
print(release.version)
PY
)
tag=v$version
publication_dir=$(mktemp -d)
trap 'rm -rf -- "$publication_dir"' EXIT

# API failures are fatal; only a successful listing can establish absence.
gh api --paginate "repos/$GITHUB_REPOSITORY/releases" --jq '.[].tag_name' > "$publication_dir/releases"
if grep -Fxq "$tag" "$publication_dir/releases"; then
    echo "Release $tag already exists; leaving it unchanged"
    exit 0
fi

# Annotated tags are compared using their peeled commit. Never move a tag.
if git ls-remote --exit-code --tags origin "refs/tags/$tag" "refs/tags/$tag^{}" > "$publication_dir/tag"; then
    tag_commit=$(awk -v ref="refs/tags/$tag" '
        $2 == ref { direct = $1 }
        $2 == ref "^{}" { peeled = $1 }
        END { print (peeled ? peeled : direct) }
    ' "$publication_dir/tag")
    [[ $tag_commit == "$GITHUB_SHA" ]] || {
        echo "Existing tag $tag does not point to the tested commit; refusing publication" >&2
        exit 1
    }
else
    status=$?
    (( status == 2 )) || exit "$status"
fi

cp VERSION dependencies.lock.json artifacts/tested-environment.json "$publication_dir/"
cp "docs/releases/$tag.md" "$publication_dir/notes.md"
printf '\n## Release verification\n\nVerified commit: `%s`.\n\n[Successful unit and Ubuntu VM checks](%s/%s/actions/runs/%s).\n' \
    "$GITHUB_SHA" "${GITHUB_SERVER_URL:-https://github.com}" "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID" \
    >> "$publication_dir/notes.md"
(
    cd "$publication_dir"
    sha256sum VERSION dependencies.lock.json tested-environment.json > SHA256SUMS
)
gh release create "$tag" \
    "$publication_dir/VERSION" "$publication_dir/dependencies.lock.json" \
    "$publication_dir/tested-environment.json" "$publication_dir/SHA256SUMS" \
    --repo "$GITHUB_REPOSITORY" --target "$GITHUB_SHA" --title "$tag" \
    --notes-file "$publication_dir/notes.md"
