#!/bin/sh
# Cross-host bind (DEC-027): fold the genuinely-served platform legs from both
# hosts into one candidate-bound served.json for the acting bundle. The
# conjunction's fold rescues exactly these legs; a receipt that does not name
# the acting commit is refused, never folded.
#
# usage: xhost-bind.sh <bundle-dir> <commit>
set -eu

bundle=$1
commit=$2

candidate=$( (sha256sum "$bundle/rivect.manifest.json" 2>/dev/null \
    || shasum -a 256 "$bundle/rivect.manifest.json") | awk '{print $1}')
[ -n "$candidate" ] || { echo "NO_CANDIDATE"; exit 1; }

linux_receipt=xhost/xhost-linux/xhost-receipt.json
macos_receipt=xhost/xhost-macos/xhost-receipt.json
for r in "$linux_receipt" "$macos_receipt"; do
    got=$(jq -r '.commit' "$r")
    if [ "$got" != "$commit" ]; then
        echo "xhost commit mismatch in $r: $got != $commit" >&2
        exit 1
    fi
done

legs=$(jq -s '[.[].served_legs[]] | unique' "$linux_receipt" "$macos_receipt")
mkdir -p target/rivect-not-run-xhost
jq -n --arg c "$candidate" --argjson legs "$legs" \
    '{schema_version:1, candidate_sha256:$c, host:"ci-cross-host", served_legs:$legs}' \
    > target/rivect-not-run-xhost/served.json
cat target/rivect-not-run-xhost/served.json