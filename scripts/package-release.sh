#!/bin/sh
# Build the installed bundle outside the checkout: the executable, the confined
# helper beside it, and the manifest that binds their digests. No data-resource
# artifact is shipped (TD-03); the exact inventory is rivect, the helper and
# rivect.manifest.json. An existing destination is refused so a previous
# release is never overwritten by a failed or partial packaging attempt.

set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s DESTINATION\n' "$0" >&2
    exit 2
fi

destination=$1
case $destination in
    /*) ;;
    *)
        printf 'destination must be an absolute path: %s\n' "$destination" >&2
        exit 2
        ;;
esac
if [ -e "$destination" ]; then
    printf 'destination already exists: %s\n' "$destination" >&2
    exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target_dir=${CARGO_TARGET_DIR:-"$repo_root/target"}
case $target_dir in
    /*) ;;
    *) target_dir=$repo_root/$target_dir ;;
esac
cargo=${CARGO:-cargo}

mkdir -p "$(dirname -- "$destination")"
staging=$(mktemp -d "$destination.staging.XXXXXX")
cleanup() {
    if [ -d "$staging" ]; then
        rm -rf -- "$staging"
    fi
}
trap cleanup EXIT HUP INT TERM

(
    cd "$repo_root"
    "$cargo" build --locked --release --workspace --bins --target-dir "$target_dir"
)

cp "$target_dir/release/rivect" "$staging/rivect"
cp "$target_dir/release/rivect-sandbox-helper" "$staging/rivect-sandbox-helper"
chmod 0755 "$staging/rivect" "$staging/rivect-sandbox-helper"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        shasum -a 256 "$1" | cut -d ' ' -f 1
    fi
}

build=$("$staging/rivect" --version)
executable_sha256=$(sha256_of "$staging/rivect")
helper_sha256=$(sha256_of "$staging/rivect-sandbox-helper")

cat > "$staging/rivect.manifest.json" <<EOF
{
  "schema_version": 1,
  "build": "$build",
  "executable": {
    "name": "rivect",
    "sha256": "$executable_sha256"
  },
  "helper": {
    "name": "rivect-sandbox-helper",
    "sha256": "$helper_sha256"
  }
}
EOF

manifest_sha256=$(sha256_of "$staging/rivect.manifest.json")

mv -- "$staging" "$destination"
printf 'rivect.manifest.json sha256 %s\n' "$manifest_sha256"
printf 'bundle %s\n' "$destination"
