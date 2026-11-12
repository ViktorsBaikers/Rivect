#!/bin/sh
# Run the exact integration oracles a checked-in offline-evidence manifest
# names and write one candidate-bound receipt. The producer refuses a
# malformed manifest, a non-integration target, an absent/ignored oracle or a
# missing marker; it deletes any prior receipt first and writes the new one
# atomically only after every target passes.
#
# usage: offline-evidence.sh --manifest PATH --receipt PATH --bundle DIR

set -eu

usage() {
    cat <<'EOF'
usage: offline-evidence.sh --manifest PATH --receipt PATH --bundle DIR

  --manifest PATH   checked-in family manifest (schema_version 1)
  --receipt PATH    candidate-bound receipt to write atomically
  --bundle DIR      installed candidate bundle holding rivect.manifest.json
  --help            print this usage

exit: 0 receipt written, 1 manifest/oracle/producer failure, 2 bad arguments
EOF
}

manifest=
receipt=
bundle=
while [ "$#" -gt 0 ]; do
    case $1 in
        --help | -h)
            usage
            exit 0
            ;;
        --manifest)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            manifest=$2
            shift 2
            ;;
        --receipt)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            receipt=$2
            shift 2
            ;;
        --bundle)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            bundle=$2
            shift 2
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done
if [ -z "$manifest" ] || [ -z "$receipt" ] || [ -z "$bundle" ]; then
    usage >&2
    exit 2
fi

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        shasum -a 256 "$1" | cut -d ' ' -f 1
    fi
}

is_hex64() {
    case $1 in
        *[!0-9a-f]* | '') return 1 ;;
    esac
    [ "${#1}" -eq 64 ]
}

[ -f "$manifest" ] || {
    printf 'manifest is not a regular file: %s\n' "$manifest" >&2
    exit 2
}
[ -d "$bundle" ] || {
    printf 'bundle is not a directory: %s\n' "$bundle" >&2
    exit 2
}
bundle_manifest=$bundle/rivect.manifest.json
[ -f "$bundle_manifest" ] || {
    printf 'bundle manifest is not a regular file: %s\n' "$bundle_manifest" >&2
    exit 2
}
bundle_digest=$(sha256_of "$bundle_manifest") || {
    printf 'bundle manifest digest failed\n' >&2
    exit 2
}
is_hex64 "$bundle_digest" || {
    printf 'bundle manifest digest is not 64 hex characters\n' >&2
    exit 2
}

manifest_size=$(wc -c <"$manifest" | tr -d ' ')
[ "$manifest_size" -le 4194304 ] || {
    printf 'manifest exceeds the 4 MiB bound\n' >&2
    exit 2
}
manifest_digest=$(sha256_of "$manifest")

command -v jq >/dev/null 2>&1 || {
    printf 'jq is required to read the manifest\n' >&2
    exit 1
}

schema=$(jq -r '.schema_version // empty' "$manifest") || exit 2
family=$(jq -r '.family // empty' "$manifest") || exit 2
row_count=$(jq -r '.rows | length' "$manifest") || exit 2
[ "$schema" = "1" ] || {
    printf 'manifest schema_version is not 1\n' >&2
    exit 2
}
case $family in
    provider) denominator=222 ;;
    acceptance) denominator=40 ;;
    search) denominator=20 ;;
    *)
        printf 'unknown offline evidence family: %s\n' "$family" >&2
        exit 2
        ;;
esac
[ "$row_count" = "$denominator" ] || {
    printf 'family %s declares %s rows, not %s\n' "$family" "$row_count" "$denominator" >&2
    exit 2
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/rivect-offline-evidence.XXXXXX") || exit 1
cleanup() {
    rm -rf -- "$tmp"
}
trap cleanup EXIT HUP INT TERM

jq -e '
    (.rows | type == "array") and
    ([.rows[].case_id] | length == (unique | length)) and
    all(.rows[];
        (.case_id | type == "string" and length > 0) and
        (.provider | type == "string" and length > 0) and
        (.marker | type == "string" and length > 0) and
        (.observation | type == "string" and length > 0 and (contains("\n") | not)) and
        (.expected == "pass" or .expected == "unserved") and
        (.oracle | type == "array" and length > 0) and
        all(.oracle[];
            (type == "string") and
            (split("::") as $parts |
                ($parts | length) >= 2 and
                ($parts[0] | length > 0) and
                ($parts[0] != "lib") and
                ($parts[0] != "bin") and
                (($parts[1:] | join("::")) | length > 0))
        )
    )
' "$manifest" >/dev/null || {
    printf 'manifest rows are malformed\n' >&2
    exit 2
}

jq -r '.rows[] | [.case_id, .provider, .marker, .expected, (.oracle | join("\u001f")), .observation] | @tsv' "$manifest" >"$tmp/rows.tsv" || exit 2

# Delete the prior receipt before any target runs so a failed run leaves no
# stale evidence behind.
rm -f -- "$receipt"

: >"$tmp/oracles.tsv"
: >"$tmp/targets.raw"
unit_separator=$(printf '\037')
while IFS='	' read -r case_id provider marker expected oracles observation; do
    [ -n "$case_id" ] && [ -n "$provider" ] && [ -n "$marker" ] && [ -n "$observation" ] || {
        printf 'manifest row is missing a required field\n' >&2
        exit 2
    }
    case $expected in
        pass) ;;
        unserved)
            case $case_id in
                TP-PROVIDER-AUTH::cursor | TP-PROVIDER-WIRE::cursor | TP-PROVIDER-RECOVERY::cursor | TP-PROVIDER-AUTH::devin | TP-PROVIDER-WIRE::devin | TP-PROVIDER-RECOVERY::devin) ;;
                *)
                    printf 'unserved is recorded only for the six cursor/devin rows: %s\n' "$case_id" >&2
                    exit 2
                    ;;
            esac
            ;;
        *)
            printf 'unknown expected outcome for %s: %s\n' "$case_id" "$expected" >&2
            exit 2
            ;;
    esac
    first_oracle=
    old_ifs=$IFS
    IFS=$unit_separator
    for oracle in $oracles; do
        target=${oracle%%::*}
        test_name=${oracle#*::}
        [ -n "$target" ] && [ -n "$test_name" ] || {
            printf 'malformed oracle for %s: %s\n' "$case_id" "$oracle" >&2
            exit 2
        }
        [ "$target" != "lib" ] && [ "$target" != "bin" ] || {
            printf 'oracle target must be an integration target: %s\n' "$oracle" >&2
            exit 2
        }
        [ -f "$(dirname -- "$0")/../tests/$target.rs" ] || {
            printf 'oracle target is not an integration target: %s\n' "$target" >&2
            exit 2
        }
        if [ -z "$first_oracle" ]; then
            first_oracle=$oracle
        fi
        printf '%s\n' "$target" >>"$tmp/targets.raw"
    done
    IFS=$old_ifs
    printf '%s\t%s\t%s\t%s\n' "$case_id" "$first_oracle" "$marker" "$expected" >>"$tmp/oracles.tsv"
done <"$tmp/rows.tsv"

sort -u "$tmp/targets.raw" >"$tmp/targets.txt"
target_count=$(wc -l <"$tmp/targets.txt" | tr -d ' ')
[ "$target_count" -gt 0 ] || {
    printf 'manifest names no integration target\n' >&2
    exit 2
}

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cargo=${CARGO:-cargo}
: >"$tmp/receipt_rows.jsonl"
: >"$tmp/receipt_targets.jsonl"

while IFS= read -r target; do
    [ -n "$target" ] || continue
    command="cargo test --locked --test $target -- --nocapture"
    output=$tmp/$target.log
    set +e
    (
        cd "$repo_root" &&
            "$cargo" test --locked --test "$target" -- --nocapture
    ) >"$output" 2>&1
    status=$?
    set -e
    if [ "$status" -ne 0 ]; then
        printf 'target %s failed with exit %s; output: %s\n' "$target" "$status" "$output" >&2
        tail -n 40 "$output" >&2 || true
        exit 1
    fi

    cases=0
    while IFS='	' read -r case_id oracle marker expected; do
        case $oracle in
            "$target::"*) test_name=${oracle#*::} ;;
            *) continue ;;
        esac
        if grep -Fqx "test $test_name ... ignored" "$output"; then
            printf 'oracle %s is ignored\n' "$oracle" >&2
            exit 1
        fi
        if ! grep -Fqx "test $test_name ... ok" "$output"; then
            printf 'oracle did not run or did not pass: %s\n' "$oracle" >&2
            grep -F "$test_name" "$output" >&2 || true
            exit 1
        fi
        if ! grep -Fqx -- "$marker" "$output"; then
            printf 'marker is absent from target %s output: %s\n' "$target" "$marker" >&2
            exit 1
        fi
        cases=$((cases + 1))
        jq -cRn --arg case_id "$case_id" --arg evidence "$oracle" --arg marker "$marker" --arg outcome "$expected" \
            '{case_id: $case_id, evidence: $evidence, marker: $marker, outcome: $outcome}' >>"$tmp/receipt_rows.jsonl"
    done <"$tmp/oracles.tsv"
    [ "$cases" -gt 0 ] || {
        printf 'target %s served no manifest oracle\n' "$target" >&2
        exit 1
    }
    output_digest=$(sha256_of "$output")
    jq -cRn --arg target "$target" --arg command "$command" --arg output_sha256 "$output_digest" --argjson cases "$cases" \
        '{target: $target, command: $command, exit: 0, output_sha256: $output_sha256, cases: $cases}' >>"$tmp/receipt_targets.jsonl"
    printf 'OFFLINE_EVIDENCE target=%s exit=0 cases=%s\n' "$target" "$cases"
done <"$tmp/targets.txt"

row_total=$(wc -l <"$tmp/receipt_rows.jsonl" | tr -d ' ')
[ "$row_total" = "$denominator" ] || {
    printf 'receipt covers %s rows, not %s\n' "$row_total" "$denominator" >&2
    exit 1
}

receipt_dir=$(dirname -- "$receipt")
mkdir -p -- "$receipt_dir"
tmp_receipt=$receipt.tmp.$$
trap 'rm -rf -- "$tmp"; rm -f -- "$tmp_receipt"' EXIT HUP INT TERM
jq -n \
    --arg family "$family" \
    --arg candidate_manifest_sha256 "$bundle_digest" \
    --arg manifest_sha256 "$manifest_digest" \
    --slurpfile rows "$tmp/receipt_rows.jsonl" \
    --slurpfile targets "$tmp/receipt_targets.jsonl" \
    '{
        schema_version: 1,
        producer_version: "1",
        family: $family,
        candidate_manifest_sha256: $candidate_manifest_sha256,
        manifest_sha256: $manifest_sha256,
        targets: $targets,
        rows: $rows,
        counts: {
            rows: ($rows | length),
            pass: ($rows | map(select(.outcome == "pass")) | length),
            unserved: ($rows | map(select(.outcome == "unserved")) | length)
        }
    }' >"$tmp_receipt" || {
    printf 'receipt assembly failed\n' >&2
    exit 1
}
mv -f -- "$tmp_receipt" "$receipt"

pass_count=$(jq -r '.counts.pass' "$receipt")
unserved_count=$(jq -r '.counts.unserved' "$receipt")
printf 'OFFLINE_EVIDENCE family=%s rows=%s pass=%s unserved=%s targets=%s\n' \
    "$family" "$row_total" "$pass_count" "$unserved_count" "$target_count"
