#!/bin/sh
# Run the offline evidence producers on one packaged bundle, evaluate the
# release conjunction in release mode, and map its machine verdict to an
# exit: 0 release_ready, 5 not ready, 2 bad arguments, 1 producer/test
# failure.

set -eu

usage() {
    printf 'usage: %s --bundle DIR [--receipts-only]\n' "$0" >&2
}

bundle=
receipts_only=false
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
        --receipts-only)
            receipts_only=true
            shift
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

bundle=$(CDPATH='' cd -- "$bundle" && pwd)
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
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

export RIVECT_TEST_BUNDLE="$bundle"
if [ "$receipts_only" = false ]; then
    run_producer tests/fixtures/provider-trials.json target/provider-trials.json
    for group in a01-a12 a13-a24 a25-a36 sections; do
        run_producer "tests/fixtures/acceptance-rows-$group.json" "target/acceptance-rows-$group.json"
    done
    run_producer tests/fixtures/search-trials.json target/search-trials.json
    "$cargo" test --locked --test installed installed_ordinary_request_completes_with_one_settlement -- --exact --show-output ||
        exit 1
    "$cargo" test --locked --test installed_tui installed_19_state_matrix_runs_on_the_packaged_artifact -- --exact --show-output ||
        exit 1
fi

printf 'RELEASE_GATE conjunction\n'
# The conjunction asserts the full release criteria and fails when they are
# unmet, but it still writes the verdict; the release answer is that verdict
# (ready -> exit 0, not ready -> exit 5 prerelease), not the test's pass/fail.
# Drop any stale verdict first so a crash before the write cannot reuse one.
rm -f target/final-acceptance.json
conjunction_exit=0
RIVECT_OFFLINE_EVIDENCE=release "$cargo" test --locked --test final_acceptance \
    final_acceptance_passes_the_installed_rows_and_prints_the_verdict \
    -- --exact --show-output || conjunction_exit=$?
case $conjunction_exit in
    0|101) ;; # libtest reports unmet assertions as 101
    *)
        printf 'release-gate: abnormal conjunction exit %s\n' "$conjunction_exit" >&2
        exit 1
        ;;
esac

verdict=target/final-acceptance.json
if [ ! -f "$verdict" ]; then
    printf 'release-gate: the conjunction wrote no %s (exit %s)\n' "$verdict" "$conjunction_exit" >&2
    exit 1
fi
candidate=$(shasum -a 256 "$bundle/rivect.manifest.json" | awk '{print $1}')
jq -e --arg candidate "$candidate" '
    .schema_version == 1 and .candidate_manifest_sha256 == $candidate and
    (.required | type == "number" and . > 0) and
    (.release_ready | type == "boolean") and
    (.blockers.retained_legs | type == "number" and . >= 0 and . == floor)
' "$verdict" >/dev/null || {
    printf 'release-gate: invalid or stale conjunction verdict\n' >&2
    exit 1
}
ready=$(jq -r '.release_ready' "$verdict") || exit 1
retained=$(jq -r '.blockers.retained_legs' "$verdict") || exit 1
# A real release needs the row plane ready AND no retained leg left after the
# cross-host fold; anything less is a recorded prerelease, never a silent pass.
# A green verdict never overrides an unexpected assertion/runtime failure.
if [ "$ready" = true ] && [ "$retained" = 0 ] && [ "$conjunction_exit" -ne 0 ]; then
    printf 'release-gate: conjunction failed despite a ready verdict\n' >&2
    exit 1
fi
if [ "$ready" = "true" ] && [ "$retained" = "0" ]; then
    printf 'RELEASE_GATE release_ready=true retained_legs=0 exit=0\n'
    exit 0
fi
printf 'RELEASE_GATE release_ready=%s retained_legs=%s exit=5\n' "$ready" "$retained"
exit 5
