#!/bin/sh
# Keep each verified bundle intact; only the final symlink switch changes PATH.
set -eu
umask 077
LC_ALL=C
export LC_ALL

fail() {
    printf 'rivect installer: %s\n' "$*" >&2
    exit 1
}

os=$(uname -s) || fail 'cannot detect operating system'
arch=$(uname -m) || fail 'cannot detect architecture'
case $os:$arch in
    Darwin:arm64|Darwin:aarch64) target=aarch64-apple-darwin ;;
    Linux:x86_64) target=x86_64-unknown-linux-gnu ;;
    *) fail "unsupported platform: $os $arch (supported: macOS arm64, Linux x86_64)" ;;
esac
case ${HOME:-} in
    /*) ;;
    *) fail 'HOME must be an absolute path' ;;
esac
for command in curl tar awk sort cmp mktemp mkdir mv ln chmod grep rm rmdir; do
    command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done
if command -v sha256sum >/dev/null 2>&1; then
    hash_command=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    hash_command=shasum
else
    fail 'sha256sum or shasum is required'
fi

root=$HOME/.local/share/rivect
mkdir -p "$root/releases" || fail 'cannot create installation directory'
mkdir "$root/.install-lock" 2>/dev/null || fail "installation locked: $root/.install-lock (remove only if no installer is running)"
work=
staging=
cleanup() {
    if [ -n "$work" ]; then rm -rf -- "$work"; fi
    if [ -n "$staging" ]; then rm -rf -- "$staging"; fi
    rmdir "$root/.install-lock"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
work=$(mktemp -d "$root/.download.XXXXXX") || fail 'cannot create download directory'

releases=https://github.com/ViktorsBaikers/Rivect/releases
resolved=$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 -fsSL -o /dev/null -w '%{url_effective}' "$releases/latest") || fail 'cannot resolve latest release'
case $resolved in
    "$releases/tag/"*) tag=${resolved#"$releases/tag/"} ;;
    *) fail 'latest release did not resolve to a repository release tag' ;;
esac
printf '%s\n' "$tag" | awk '/^v[0-9]+[.][0-9]+[.][0-9]+$/ {valid=1} END {exit (!valid || NR != 1)}' || fail 'invalid release tag'
archive=rivect-$tag-$target.tar.gz
url=$releases/download/$tag
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 -fsSL -o "$work/$archive" "$url/$archive" || fail 'archive download failed'
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 -fsSL -o "$work/checksum" "$url/$target.sha256" || fail 'checksum download failed'
expected=$(awk -v name="$archive" 'NF == 2 && ($2 == name || $2 == "./" name) && length($1) == 64 && $1 !~ /[^0-9a-f]/ {hash=$1; valid++} END {if (NR != 1 || valid != 1) exit 1; print hash}' "$work/checksum") || fail 'invalid checksum file'
if [ "$hash_command" = sha256sum ]; then
    sha256sum < "$work/$archive" > "$work/hash" || fail 'cannot hash archive'
else
    shasum -a 256 < "$work/$archive" > "$work/hash" || fail 'cannot hash archive'
fi
read -r actual _remainder < "$work/hash" || fail 'cannot read archive hash'
[ "$actual" = "$expected" ] || fail 'archive checksum mismatch'

# Validate names, duplicates and entry types before tar can write anything.
tar -tzf "$work/$archive" > "$work/names" || fail 'cannot list archive'
printf '%s\n' rivect rivect-sandbox-helper rivect.manifest.json > "$work/expected"
sort "$work/names" > "$work/sorted" || fail 'cannot sort archive inventory'
cmp -s "$work/expected" "$work/sorted" || fail 'archive must contain exactly rivect, rivect-sandbox-helper and rivect.manifest.json'
tar -tvzf "$work/$archive" > "$work/types" || fail 'cannot inspect archive types'
awk 'substr($0, 1, 1) != "-" {bad=1} END {exit (bad || NR != 3)}' "$work/types" || fail 'archive entries must be regular files, not links or directories'
staging=$(mktemp -d "$root/releases/.staging.XXXXXX") || fail 'cannot stage installation'
tar -xzf "$work/$archive" --no-same-owner --no-same-permissions -C "$staging" || fail 'archive extraction failed'
for name in rivect rivect-sandbox-helper rivect.manifest.json; do
    [ -f "$staging/$name" ] && [ ! -L "$staging/$name" ] || fail 'extracted bundle is not regular files'
done
chmod 0755 "$staging" "$staging/rivect" "$staging/rivect-sandbox-helper" || fail 'cannot set executable permissions'
chmod 0644 "$staging/rivect.manifest.json" || fail 'cannot set manifest permissions'
env -i HOME="$HOME" PATH="$PATH" "$staging/rivect" --version >/dev/null || fail 'release binary cannot run on this system'
release=$root/releases/$expected
if [ -e "$release" ] || [ -L "$release" ]; then
    [ -d "$release" ] && [ ! -L "$release" ] || fail 'existing bundle path is not a directory'
    for name in rivect rivect-sandbox-helper rivect.manifest.json; do
        if [ ! -f "$release/$name" ] || [ -L "$release/$name" ] || ! cmp -s "$staging/$name" "$release/$name"; then
            fail 'existing bundle differs from verified archive'
        fi
    done
else
    mv "$staging" "$release" || fail 'cannot publish verified bundle'
    staging=
fi

IFS= read -r path_line <<'PROFILE'
case ":$PATH:" in *":$HOME/.local/share/rivect/bin:"*) ;; *) export PATH="$HOME/.local/share/rivect/bin:$PATH" ;; esac
PROFILE
add_profile() {
    profile=$1
    if [ -e "$profile" ] && [ ! -f "$profile" ]; then fail "shell profile is not a regular file: $profile"; fi
    if [ -f "$profile" ]; then
        if grep -Fqx "$path_line" "$profile"; then return; else
            status=$?
            [ "$status" -eq 1 ] || fail "cannot read shell profile: $profile"
        fi
    fi
    printf '\n# Rivect user-local installation\n%s\n' "$path_line" >> "$profile" || fail "cannot update shell profile: $profile"
}
shell=${SHELL:-sh}
case ${shell##*/} in
    zsh)
        profile_root=${ZDOTDIR:-$HOME}
        mkdir -p "$profile_root" || fail 'cannot create zsh profile directory'
        add_profile "$profile_root/.zshrc"
        ;;
    bash)
        add_profile "$HOME/.bashrc"
        if [ -f "$HOME/.bash_profile" ]; then add_profile "$HOME/.bash_profile"
        elif [ -f "$HOME/.bash_login" ]; then add_profile "$HOME/.bash_login"
        elif [ -f "$HOME/.profile" ]; then add_profile "$HOME/.profile"
        else add_profile "$HOME/.bash_profile"
        fi
        ;;
    fish)
        profile_root=${XDG_CONFIG_HOME:-$HOME/.config}/fish
        mkdir -p "$profile_root" || fail 'cannot create fish profile directory'
        IFS= read -r path_line <<'PROFILE'
if not contains -- "$HOME/.local/share/rivect/bin" $PATH; set -gx PATH "$HOME/.local/share/rivect/bin" $PATH; end
PROFILE
        add_profile "$profile_root/config.fish"
        ;;
    *) add_profile "$HOME/.profile" ;;
esac

[ ! -e "$root/bin" ] || [ -L "$root/bin" ] || fail 'installation bin path is not a symlink'
ln -s "$release" "$work/bin" || fail 'cannot stage bundle selection'
# GNU and BSD mv need different flags to replace, not follow, directory symlinks.
if mv -fT "$work/bin" "$root/bin" 2>/dev/null; then :
else mv -fh "$work/bin" "$root/bin" || fail 'cannot activate verified bundle'
fi
printf 'Installed Rivect %s for %s in %s\n' "$tag" "$target" "$root/bin" >&2
printf '%s\n' 'Open a new terminal, or source your shell profile, then run rivect.' 'A piped installer cannot change PATH in its parent shell.' >&2
