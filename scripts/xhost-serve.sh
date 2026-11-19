#!/bin/sh
# Attest platform legs from this run's verified logs; never execute tests here.
# usage: xhost-serve.sh <linux|macos> <commit> <bundle-dir> <logs-dir>
set -eu
[ "$#" -eq 4 ] || { echo "usage: $0 linux|macos commit bundle logs" >&2; exit 2; }
platform=$1
commit=$2
bundle=$3
logs=$4
candidate=$(shasum -a 256 "$bundle/rivect.manifest.json" | awk '{print $1}')
sbom=$(shasum -a 256 "$bundle.cdx.json" | awk '{print $1}')
case $platform in
    linux)
        legs='["auth.secret_service"]'
        oracles='auth:secret_service_leg_records_not_run_when_the_headless_store_is_absent'
        ;;
    macos)
        legs='["auth.keychain"]'
        oracles='auth:keychain_rivect_test_namespaced_entries_are_created_and_deleted_by_the_test'
        ;;
    *) echo "unknown platform: $platform" >&2; exit 2 ;;
esac
printf '%s\n' "$oracles" | while IFS=: read -r target oracle; do
    output=$(shasum -a 256 "$logs/$target.log" | awk '{print $1}')
    jq -e --arg c "$candidate" --arg o "$output" \
        '.exit == 0 and .candidate_manifest_sha256 == $c and .output_sha256 == $o' \
        "$logs/$target.json" >/dev/null
    grep -Fx "test $oracle ... ok" "$logs/$target.log" >/dev/null
done
for leg in $(printf '%s' "$legs" | jq -r '.[]'); do
    if [ -f "target/rivect-not-run/$leg.jsonl" ]; then
        echo "NOT_RUN: $leg" >&2
        cat "target/rivect-not-run/$leg.jsonl" >&2
        exit 1
    fi
done
jq -n --arg commit "$commit" --arg platform "$platform" \
    --arg candidate "$candidate" --arg sbom "$sbom" --arg run "${GITHUB_RUN_ID:-local}" \
    --argjson legs "$legs" \
    '{schema_version:2, commit:$commit, run_id:$run, platform:$platform,
      candidate_manifest_sha256:$candidate, sbom_sha256:$sbom, served_legs:$legs}' > xhost-receipt.json