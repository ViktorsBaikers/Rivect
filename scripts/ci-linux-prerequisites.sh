#!/bin/sh
# Keep the Ubuntu 24.04 artifact ABI; its packaged setpriv predates Landlock.
set -eu
sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0
sudo apt-get update -qq
sudo apt-get install -y -qq libcap-ng-dev pkg-config
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM
curl --fail --location --silent --show-error \
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
