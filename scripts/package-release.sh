#!/bin/sh
# Package the engine, sandbox helper and paired native terminal client.

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
while [ "$destination" != / ] && [ "${destination%/}" != "$destination" ]; do destination=${destination%/}; done
receipt=$destination.manifest.sha256
sbom=$destination.cdx.json
if [ -e "$destination" ] || [ -L "$destination" ]; then
    printf 'destination already exists: %s\n' "$destination" >&2
    exit 2
fi
for sidecar in "$receipt" "$sbom"; do
    if [ -e "$sidecar" ] || [ -L "$sidecar" ]; then
        printf 'sidecar already exists: %s\n' "$sidecar" >&2
        exit 2
    fi
done

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
target_dir=${CARGO_TARGET_DIR:-"$repo_root/target"}
case $target_dir in
    /*) ;;
    *) target_dir=$repo_root/$target_dir ;;
esac
cargo=${CARGO:-cargo}

mkdir -p "$(dirname -- "$destination")"
work=$(mktemp -d "$destination.staging.XXXXXX")
staging=$work/bundle
cleanup() {
    if [ -d "$staging" ]; then
        python3 -I - "$work" "$receipt" "$sbom" <<'PY'
import os
import sys

work, receipt, sbom = sys.argv[1:]
for name, destination in (("receipt", receipt), ("sbom", sbom)):
    try:
        source = os.lstat(os.path.join(work, name))
        if os.path.samestat(source, os.lstat(destination)):
            os.unlink(destination)
    except FileNotFoundError:
        pass  # This sidecar was not linked, or has already disappeared.
PY
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir -m 0755 "$staging"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        digest=$(sha256sum < "$1") || return 1
    else
        digest=$(shasum -a 256 < "$1") || return 1
    fi
    printf '%s\n' "${digest%% *}"
}
(
    cd "$repo_root"
    unset RIVECT_BUNDLED_UI_SHA256 RIVECT_BUNDLED_UI_REQUIREMENT
    RIVECT_BUNDLED_UI_SHA256=$(sha256_of "$repo_root/tui/build/rivect-tui")
    export RIVECT_BUNDLED_UI_SHA256
    if [ "$(uname -s)" = Darwin ]; then
        # Read Bun's existing ad-hoc identity; no signing or distribution assessment.
        /usr/bin/codesign -d --verbose=4 "$repo_root/tui/build/rivect-tui" 2>"$work/code-directory"
        cdhash=$(awk -F= '$1 == "CDHash" && length($2) == 40 && $2 ~ /^[0-9a-f]+$/ {print $2}' "$work/code-directory")
        [ "${#cdhash}" = 40 ] || { printf 'invalid terminal client code directory\n' >&2; exit 1; }
        RIVECT_BUNDLED_UI_REQUIREMENT=$(printf 'cdhash H"%s"' "$cdhash")
        export RIVECT_BUNDLED_UI_REQUIREMENT
    fi
    "$cargo" build --locked --release --workspace --bins --target-dir "$target_dir" \
        --message-format=json-render-diagnostics > "$work/artifacts"
    host=$(rustc -vV | awk '/^host:/ { print $2 }')
    "$cargo" metadata --locked --offline --format-version 1 --filter-platform "$host" > "$work/metadata"
)

cp "$target_dir/release/rivect" "$staging/rivect"
cp "$target_dir/release/rivect-sandbox-helper" "$staging/rivect-sandbox-helper"
chmod 0755 "$staging/rivect" "$staging/rivect-sandbox-helper"


build=$("$staging/rivect" --version)
executable_sha256=$(sha256_of "$staging/rivect")
helper_sha256=$(sha256_of "$staging/rivect-sandbox-helper")

case $(uname -s) in
    Darwin) library=libopentui.dylib ;;
    Linux) library=libopentui.so ;;
    *) printf 'unsupported native UI host\n' >&2; exit 2 ;;
esac
mkdir "$staging/libexec"
cp "$repo_root/tui/build/rivect-tui" "$repo_root/tui/build/$library" "$staging/libexec/"
chmod 0755 "$staging/libexec/rivect-tui"
chmod 0644 "$staging/libexec/$library"
ui_sha256=$(sha256_of "$staging/libexec/rivect-tui")
library_sha256=$(sha256_of "$staging/libexec/$library")
ui_entries=$(cat <<EOF
,
  "ui": { "name": "libexec/rivect-tui", "sha256": "$ui_sha256" },
  "library": { "name": "libexec/$library", "sha256": "$library_sha256" }
EOF
)

cat > "$staging/rivect.manifest.json" <<EOF
{
  "schema_version": 2,
  "build": "$build",
  "executable": {
    "name": "rivect",
    "sha256": "$executable_sha256"
  },
  "helper": {
    "name": "rivect-sandbox-helper",
    "sha256": "$helper_sha256"
  }$ui_entries
}
EOF

manifest_sha256=$(sha256_of "$staging/rivect.manifest.json")

python3 "$repo_root/scripts/release-sbom.py" "$staging" "$work/artifacts" "$work/metadata" \
    "$repo_root/tui/build/ui-inventory.json" > "$work/sbom"
printf '%s\n' "$manifest_sha256" > "$work/receipt"
python3 -I -c 'import os,sys; os.link(sys.argv[1],sys.argv[2]); os.link(sys.argv[3],sys.argv[4])' \
    "$work/sbom" "$sbom" "$work/receipt" "$receipt"
mv -- "$staging" "$destination"
printf 'rivect.manifest.json sha256 %s\n' "$manifest_sha256"
printf 'bundle %s\n' "$destination"
