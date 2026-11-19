#!/bin/sh
# Keep the Ubuntu 24.04 artifact ABI; its packaged setpriv predates Landlock.
set -eu
case "$#:${1-}" in
    0:) set -- libcap-ng-dev pkg-config ;;
    1:--keyring) set -- libcap-ng-dev pkg-config gnome-keyring dbus-daemon ;;
    *) printf 'usage: %s [--keyring]\n' "$0" >&2; exit 2 ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM
# The runner's HTTP mirror can return 503 or silently keep stale indexes.
for pocket in noble noble-updates noble-security; do
    printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] %s %s main universe\n' \
        'https://azure.archive.ubuntu.com/ubuntu' "$pocket"
done > "$tmp/noble.list"
apt_noble() {
    sudo apt-get -o Dir::Etc::sourcelist="$tmp/noble.list" \
        -o Dir::Etc::sourceparts=- -o Acquire::Retries=2 \
        -o Acquire::https::Timeout=15 "$@"
}
apt_noble update -q --error-on=any
apt_noble install -y -q --no-install-recommends "$@"
sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0
curl --fail --location --silent --show-error --connect-timeout 10 --max-time 60 \
    https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.41/util-linux-2.41.5.tar.xz \
    -o "$tmp/util-linux.tar.xz"
printf 'f586e35d320ff537aab3ffeca37e9ecd482ccbe013590db4429a414d8aa6a728  %s/util-linux.tar.xz\n' "$tmp" | sha256sum -c -
tar -xJf "$tmp/util-linux.tar.xz" -C "$tmp"
(
    cd "$tmp/util-linux-2.41.5"
    ./configure --disable-all-programs --enable-setpriv --disable-nls --disable-shared
    make -j2 setpriv
    sudo install -m 0755 setpriv /usr/bin/setpriv
)
/usr/bin/setpriv --help | grep -- --landlock-access
