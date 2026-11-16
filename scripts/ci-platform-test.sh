#!/bin/sh
# Linux's disposable D-Bus session is owned by dbus-run-session in the workflow.
set -eu
if [ "$PLATFORM" = linux ]; then
    mkdir -p "$HOME/.local/share/keyrings"
    printf rivect-test-password | gnome-keyring-daemon --unlock --components=secrets
fi
python3 scripts/ci-test.py
sh scripts/xhost-serve.sh "$PLATFORM" "$GITHUB_SHA" "$RIVECT_TEST_BUNDLE" target/ci-logs
