#!/bin/sh
# Run the offline evidence producers on one packaged bundle, evaluate the
# release conjunction in release mode, and map its machine verdict to an
# exit: 0 release_ready, 5 not ready, 2 bad arguments, 1 producer/test
# failure.

set -eu

usage() {
    printf 'usage: %s --bundle DIR\n' "$0" >&2
}

bundle=
while [ "$#" -gt 0 ]; do
    case $1 in
        --bundle)
            [ "$#" -ge 2 ] || {
                usage
                exit 2
            }
            bundle=$2
            shift 2
            ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            usage
            exit 2
            ;;
    esac
done
if [ -z "$bundle" ]; then
    usage
    exit 2
fi
if [ ! -d "$bundle" ]; then
    printf 'bundle is not a directory: %s\n' "$bundle" >&2
    exit 2
fi
if [ ! -f "$bundle/rivect.manifest.json" ]; then
    printf 'bundle carries no rivect.manifest.json: %s\n' "$bundle" >&2
    exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd -- "$repo_root"
cargo=${CARGO:-cargo}

command -v jq >/dev/null 2>&1 || {
    printf 'release-gate: jq is required\n' >&2
    exit 1
}

run_producer() {
    manifest=$1
    receipt=$2
    printf 'RELEASE_GATE producer manifest=%s receipt=%s\n' "$manifest" "$receipt"
    sh scripts/offline-evidence.sh --manifest "$manifest" --receipt "$receipt" --bundle "$bundle" ||
        exit 1
}

run_producer tests/fixtures/provider-trials.json target/provider-trials.json
for group in a01-a12 a13-a24 a25-a36 sections; do
    run_producer "tests/fixtures/acceptance-rows-$group.json" "target/acceptance-rows-$group.json"
done
run_producer tests/fixtures/search-trials.json target/search-trials.json

printf 'RELEASE_GATE conjunction\n'
RIVECT_OFFLINE_EVIDENCE=release "$cargo" test --locked --test final_acceptance -- --nocapture ||
    exit 1

verdict=target/final-acceptance.json
if [ ! -f "$verdict" ]; then
    printf 'release-gate: the conjunction wrote no %s\n' "$verdict" >&2
    exit 1
fi
ready=$(jq -r '.release_ready' "$verdict") || exit 1
case $ready in
    true)
        printf 'RELEASE_GATE release_ready=true exit=0\n'
        exit 0
        ;;
    false)
        printf 'RELEASE_GATE release_ready=false exit=5\n'
        exit 5
        ;;
    *)
        printf 'release-gate: %s carries release_ready=%s\n' "$verdict" "$ready" >&2
        exit 1
        ;;
esac
