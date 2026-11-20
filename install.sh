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
for command in curl python3 awk cmp mktemp mkdir ln grep rm rmdir; do
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
for dir in "$HOME/.local" "$HOME/.local/share" "$root" "$root/releases"; do
    [ ! -L "$dir" ] || fail "installation directory is a symlink: $dir"
done
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
if [ "$#" -eq 0 ]; then
    resolved=$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 -fsSL -o /dev/null -w '%{url_effective}' "$releases/latest") || fail 'cannot resolve latest release'
    case $resolved in
        "$releases/tag/"*) tag=${resolved#"$releases/tag/"} ;;
        *) fail 'latest release did not resolve to a repository release tag' ;;
    esac
elif [ "$#" -eq 2 ] && [ "$1" = --rollback ]; then
    tag=$2
else
    fail 'usage: install.sh [--rollback vMAJOR.MINOR.PATCH]'
fi
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

staging=$(mktemp -d "$root/releases/.staging.XXXXXX") || fail 'cannot stage installation'
release=$root/releases/$expected
if [ "$#" -ne 0 ] && [ ! -d "$release" ]; then
    fail 'archive was not previously installed'
fi
python3 -I - "$work/$archive" "$staging" "$release" "$work/receipt" "$target" <<'PY' || fail 'bundle verification failed'
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile

archive, stage, release, receipt = map(Path, sys.argv[1:5])
library = "libexec/libopentui." + ("dylib" if sys.argv[5].endswith("darwin") else "so")
names = {"executable": "rivect", "helper": "rivect-sandbox-helper",
         "ui": "libexec/rivect-tui", "library": library}
manifest = "rivect.manifest.json"
allowed = {manifest, *names.values()}

def unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        sys.exit("duplicate manifest key")
    return result

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

# Never extract archive-controlled paths or apply archive modes, links or ownership.
seen = set()
libexec_dir = False
with tarfile.open(archive, "r|gz") as tar:
    for entry in tar:
        if entry.name == "libexec" and entry.isdir() and not libexec_dir:
            libexec_dir = True
            continue
        if entry.name == manifest and entry.size > 64 * 1024:
            sys.exit("release manifest exceeds the size limit")
        if entry.name not in allowed or entry.name in seen or entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
            sys.exit("invalid archive entry")
        seen.add(entry.name)
        dest = stage / entry.name
        dest.parent.mkdir(exist_ok=True)
        with tar.extractfile(entry) as src, dest.open("xb") as out:
            shutil.copyfileobj(src, out)
        dest.chmod(0o644 if entry.name in (manifest, library) else 0o755)

raw = (stage / manifest).read_bytes()
data = json.loads(raw, object_pairs_hook=unique)
if type(data["schema_version"]) is not int or data["schema_version"] != 2:
    sys.exit("unsupported manifest version; Rivect requires a v2 package")
if (set(data) != {"schema_version", "build", *names} or not isinstance(data["build"], str)
        or not data["build"] or seen != {manifest, *names.values()}):
    sys.exit("invalid bundle inventory")
for role, name in names.items():
    if data[role] != {"name": name, "sha256": digest(stage / name)}:
        sys.exit("manifest entry mismatch: " + role)

if os.path.lexists(release):
    for directory in ("", "libexec"):
        current = release / directory
        if current.is_symlink() or not current.is_dir() or set(os.listdir(current)) != set(os.listdir(stage / directory)):
            sys.exit("existing bundle inventory differs")
    for name in seen:
        path = release / name
        if (path.is_symlink() or not path.is_file() or digest(path) != digest(stage / name)
                or (name not in (manifest, library) and not os.access(path, os.X_OK))):
            sys.exit("existing bundle differs from verified archive")
receipt.write_text(hashlib.sha256(raw).hexdigest() + "\n", encoding="ascii")
PY
receipt=$release.manifest.sha256
if [ -e "$receipt" ] || [ -L "$receipt" ]; then
    if [ ! -f "$receipt" ] || [ -L "$receipt" ] || ! cmp -s "$work/receipt" "$receipt"; then
        fail 'existing manifest receipt differs'
    fi
elif [ "$#" -ne 0 ]; then
    fail 'previous manifest receipt missing'
fi

IFS= read -r path_line <<'PROFILE'
case ":$PATH:" in *":$HOME/.local/share/rivect/bin:"*) ;; *) export PATH="$HOME/.local/share/rivect/bin:$PATH" ;; esac
PROFILE
add_profile() {
    profile=$1
    [ ! -L "$profile" ] || fail "shell profile is a symlink: $profile"
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
# Publish immutable objects first; only the final rename changes the active bundle.
python3 -I - "$staging" "$release" "$work/receipt" "$receipt" "$work/bin" "$root/bin" "$tag" "$target" "$#" <<'PY' || fail 'cannot activate verified bundle'
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

stage, release, candidate, receipt, link, active = map(Path, sys.argv[1:7])
tag, target, argc = sys.argv[7:]
rollback = argc != "0"
commands = release.with_suffix(".commands")
published = received = created_commands = False
key = f"{tag}-{target}-"
binding = key + release.name + "-" + candidate.read_text(encoding="ascii").strip()

# Only records reached through the active link are history. An interrupted publication is not.
history = None
if active.is_symlink():
    selected = Path(os.readlink(active))
    if selected.parent.parent == active.parent and selected.parent.name.startswith(".activation."):
        history = selected.parent
        if history.is_symlink() or not history.is_dir() or not selected.is_symlink():
            sys.exit("invalid active selection")
bound = history is not None and (history / binding).is_symlink() and os.readlink(history / binding) == str(commands)
if rollback and not bound:
    sys.exit("release was not previously activated for this tag and target")

def require_library_mapping(pid, env, deadline):
    library = release / "libexec" / ("libopentui.dylib" if target.endswith("darwin") else "libopentui.so")
    if sys.platform == "darwin":
        subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-d", "txt", "-p", str(pid), "--", library],
                       env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       timeout=max(0, deadline - time.monotonic()), check=True)
    else:
        st = library.stat()
        device = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}".encode()
        inode = str(st.st_ino).encode()
        with open(f"/proc/{pid}/maps", "rb") as maps:
            for line in maps:
                _, perms, _, dev, ino, *_ = line.split(maxsplit=5)
                if b"x" in perms and dev == device and ino == inode:
                    return
        raise ValueError("renderer did not map the installed library")

def probe_renderer(work, env):
    master, slave = pty.openpty()
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        deadline = time.monotonic() + 8
        with subprocess.Popen([release / "libexec/rivect-tui"], cwd=work,
                              env=dict(env, TERM="xterm-256color", TMPDIR=str(work)),
                              stdin=slave, stdout=slave, stderr=slave, start_new_session=True) as ui:
            def wait_for(marker):
                tail = b""
                while time.monotonic() < deadline:
                    if select.select([master], [], [], .1)[0]:
                        tail += os.read(master, 65536)
                        if marker in tail:
                            return
                        tail = tail[-len(marker):]
                    elif ui.poll() is not None:
                        break
                raise ValueError("renderer did not complete terminal startup and shutdown")
            try:
                wait_for(b"Message")
                require_library_mapping(ui.pid, env, deadline)
                os.write(master, b"\x03")
                wait_for(b"\x1b[?1049l")
                # Terminal restoration can still fill the PTY after the alt-screen marker.
                while ui.poll() is None and time.monotonic() < deadline:
                    if select.select([master], [], [], .05)[0]:
                        os.read(master, 65536)
                if ui.wait(timeout=max(0, deadline - time.monotonic())) not in (0, 130):
                    raise ValueError("renderer exited unsuccessfully")
            except BaseException:
                try:
                    os.killpg(ui.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # The process group already exited.
                raise
    finally:
        os.close(slave)
        os.close(master)

def probe_bundle():
    work = link.parent
    env = {"HOME": str(work), "PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    doctor = subprocess.run([release / "rivect", "doctor", "--data-root", work / "fresh"],
                            env=env, cwd=work, capture_output=True, timeout=30)
    report = json.loads(doctor.stdout)
    fresh = {"exe": "ready", "release": "ready", "config": "ready",
             "runtime_dir": "missing", "owner_lock": "missing", "state_db": "missing"}
    if (doctor.returncode != 3 or report.get("kind") != "doctor"
            or {c["name"]: c["state"] for c in report["checks"]} != fresh):
        raise ValueError("candidate doctor refused fresh installation")

    # Establish that this fresh path is writable without the sandbox.
    target = work / "forbidden-write"
    target.touch(exist_ok=False)
    target.unlink()
    platform, policy = (("macos", "(version 1)(allow default)(deny file-write*)")
                        if (release / "libexec/libopentui.dylib").exists() else ("linux", ""))
    probe = subprocess.run([release / "rivect-sandbox-helper", "probe-write", platform, policy, target],
                           env=env, cwd=work, capture_output=True, timeout=30)
    if (probe.returncode != 20 or os.path.lexists(target)
            or not probe.stderr.startswith(b"rivect-sandbox-helper: probe-write open denied:")
            or not any(errno in probe.stderr for errno in (b"(os error 1)", b"(os error 13)"))):
        raise ValueError("sandbox did not deny the forbidden write")
    probe_renderer(work, env)

try:
    subprocess.run([stage / "rivect", "--version"], env={"HOME": str(link.parent), "PATH": "/usr/bin:/bin"},
                   cwd=link.parent, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True, timeout=10)
    if not release.exists():
        stage.rename(release)
        published = True
    if not rollback and not receipt.exists():
        os.link(candidate, receipt)
        received = True
    probe_bundle()
    if not rollback and not os.path.lexists(commands):
        commands.mkdir()
        created_commands = True
        (commands / "rivect").symlink_to(release / "rivect")
    if (commands.is_symlink() or not commands.is_dir() or os.listdir(commands) != ["rivect"]
            or os.readlink(commands / "rivect") != str(release / "rivect")):
        raise ValueError("invalid release command directory")
    if not bound:
        # Build a private snapshot. The same rename commits both selection and its receipt history.
        snapshot = Path(tempfile.mkdtemp(prefix=".activation.", dir=link.parent))
        if history is not None:
            for record in history.iterdir():
                historical = Path(os.readlink(record))
                if not record.name.startswith(key) and historical.suffix == ".commands":
                    (snapshot / record.name).symlink_to(historical)
        (snapshot / binding).symlink_to(commands)
        history = active.parent / snapshot.name
        snapshot.rename(history)
    link.symlink_to(history / binding)
    os.replace(link, active)
except BaseException:
    # A signal can arrive after rename already committed. Never remove the active selection.
    if history is not None and active.is_symlink() and os.readlink(active) == str(history / binding):
        raise
    if created_commands:
        shutil.rmtree(commands)
    if received:
        receipt.unlink()
    if published:
        shutil.rmtree(release)
    raise
PY
printf 'Installed Rivect %s for %s in %s\n' "$tag" "$target" "$root/bin" >&2
printf '%s\n' 'Open a new terminal, or source your shell profile, then run rivect.' 'A piped installer cannot change PATH in its parent shell.' >&2
