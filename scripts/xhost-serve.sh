#!/bin/sh
# Cross-host serve (DEC-027): genuinely serve this host's platform-exclusive
# release legs, then write a commit-bound receipt the package job folds into
# the acting candidate. A leg that stays NOT_RUN refuses the receipt — the
# serve is real or it is nothing; no fabricated evidence.
#
# usage: xhost-serve.sh <linux|macos> <commit>
set -eu

platform=$1
commit=$2

serve_linux() {
    export DEBIAN_FRONTEND=noninteractive
    sudo apt-get update -qq
    sudo apt-get install -y -qq gnome-keyring dbus dbus-x11 \
        libsecret-tools pkg-config >/dev/null
    # Persistent session bus; unlock the login keyring headlessly so the
    # Secret Service can enroll (the same daemon must own org.freedesktop.secrets).
    eval "$(dbus-launch --sh-syntax)"
    export DBUS_SESSION_BUS_ADDRESS
    mkdir -p "$HOME/.local/share/keyrings"
    printf 'rivect-test-password' \
        | gnome-keyring-daemon --unlock --components=secrets
    for _ in $(seq 1 20); do
        if dbus-send --session --dest=org.freedesktop.DBus \
            --type=method_call --print-reply /org/freedesktop/DBus \
            org.freedesktop.DBus.ListNames 2>/dev/null \
            | grep -q org.freedesktop.secrets; then
            break
        fi
        sleep 0.5
    done
    cargo test --locked --test auth \
        secret_service_leg_records_not_run_when_the_headless_store_is_absent \
        -- --exact --nocapture
    cargo test --locked --test measurement \
        offline_corpus_measures_the_installed_candidate_against_the_frozen_limits \
        -- --exact --nocapture
}

case $platform in
    linux)
        serve_linux
        legs='["auth.secret_service","measurement.offline_corpus"]'
        for leg in auth.secret_service measurement.offline_corpus; do
            if [ -f "target/rivect-not-run/$leg.jsonl" ]; then
                echo "NOT_RUN: $leg"
                cat "target/rivect-not-run/$leg.jsonl"
                exit 1
            fi
        done
        ;;
    macos)
        cargo test --locked --test auth \
            keychain_rivect_test_namespaced_entries_are_created_and_deleted_by_the_test \
            -- --exact --nocapture
        legs='["auth.keychain"]'
        if [ -f target/rivect-not-run/auth.keychain.jsonl ]; then
            echo "NOT_RUN: auth.keychain"
            cat target/rivect-not-run/auth.keychain.jsonl
            exit 1
        fi
        ;;
    *)
        echo "unknown platform: $platform" >&2
        exit 2
        ;;
esac

printf '{"schema_version":1,"commit":"%s","platform":"%s","served_legs":%s}\n' \
    "$commit" "$platform" "$legs" > xhost-receipt.json
cat xhost-receipt.json