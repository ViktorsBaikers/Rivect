#!/bin/sh
# Linux's disposable D-Bus session is owned by dbus-run-session in the workflow.
set -eu
jq -e '.schema_version == 2' "$RIVECT_TEST_BUNDLE/rivect.manifest.json" >/dev/null
if [ "$PLATFORM" = linux ]; then
    RIVECT_TEST_DBUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:?expected a disposable D-Bus session}
    export RIVECT_TEST_DBUS_ADDRESS
    mkdir -p "$HOME/.local/share/keyrings"
    printf rivect-test-password | gnome-keyring-daemon --unlock --components=secrets
fi
python3 scripts/ci-test.py --jobs 2
sh scripts/xhost-serve.sh "$PLATFORM" "$GITHUB_SHA" "$RIVECT_TEST_BUNDLE" target/ci-logs
