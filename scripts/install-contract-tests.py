#!/usr/bin/env python3
"""Offline installer contracts: real shell/filesystem, simulated HTTPS only."""
import _ctypes
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import pty
import shlex
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tui.installed_test import dismiss_pending, wait_terminal_exit, wait_text

RELEASES = "https://github.com/ViktorsBaikers/Rivect/releases"
TARGET = "aarch64-apple-darwin"


class InstallerContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rivect-install-contract-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.log = self.root / "requests"
        self.env = {"HOME": str(self.home), "PATH": f"{self.tools}:/usr/bin:/bin",
                    "SHELL": "/bin/zsh", "LC_ALL": "C",
                    "FIXTURES": str(self.assets), "REQUESTS": str(self.log),
                    "FAKE_OS": "Darwin", "FAKE_ARCH": "arm64"}
        self.tool("uname", "#!/bin/sh\ncase $1 in -s) printf '%s\\n' \"$FAKE_OS\";; -m) printf '%s\\n' \"$FAKE_ARCH\";; *) exit 2;; esac\n")
        self.tool("curl", f"#!{sys.executable}\n" + """import os, pathlib, shutil, sys
args = sys.argv[1:]
for flag in ['--proto', '--proto-redir']:
    if flag not in args or args[args.index(flag) + 1] != '=https':
        sys.exit(2)
if '--tlsv1.2' not in args or '-fsSL' not in args:
    sys.exit(2)
url = next((arg for arg in args if arg.startswith('https://')), '')
with open(os.environ['REQUESTS'], 'a') as log:
    log.write(url + '\\n')
base = 'https://github.com/ViktorsBaikers/Rivect/releases'
if url == base + '/latest':
    if os.environ.get('FAIL_LATEST') == '1':
        sys.exit(22)
    sys.stdout.write(os.environ.get('LATEST_URL', base + '/tag/v0.1.1'))
    sys.exit(0)
if not url.startswith(tuple(base + '/download/v0.1.' + n + '/' for n in ('0', '1', '2'))):
    sys.exit(22)
source = pathlib.Path(os.environ['FIXTURES']) / url.removeprefix(base + '/download/')
if not source.is_file():
    sys.exit(22)
if '-o' in args:
    shutil.copyfile(source, args[args.index('-o') + 1])
else:
    sys.stdout.buffer.write(source.read_bytes())
""")
        self.make_release()

    def tool(self, name, content):
        path = self.tools / name
        path.write_text(content)
        path.chmod(0o755)

    def make_release(self, target=TARGET, executable=None, version=2, helper=None, tag="v0.1.1",
                     ui=None, library=None):
        (self.root / "candidate-ran").unlink(missing_ok=True)
        self.files = {"rivect": b"#!/bin/sh\nprintf 'rivect 0.1.1\\n'\n",
                      "rivect-sandbox-helper": b"#!/bin/sh\nprintf 'helper 0.1.1\\n'\n"}
        if version == 2:
            self.files["rivect"] = b"""#!/bin/sh
case $1 in
  --version) echo 'rivect VERSION' ;;
  doctor) echo '{"kind":"doctor","checks":[{"name":"exe","state":"ready"},{"name":"release","state":"ready"},{"name":"config","state":"ready"},{"name":"runtime_dir","state":"missing"},{"name":"owner_lock","state":"missing"},{"name":"state_db","state":"missing"}]}' ; exit 3 ;;
  *) exit 1 ;;
esac
""".replace(b"VERSION", tag[1:].encode())
            self.files["rivect-sandbox-helper"] = b"""#!/bin/sh
[ "$1" = probe-write ] || exit 11
echo 'rivect-sandbox-helper: probe-write open denied: Operation not permitted (os error 1)' >&2
exit 20
"""
        if helper is not None:
            self.files["rivect-sandbox-helper"] = helper
        if executable is not None:
            self.files["rivect"] = executable
        if version == 2:
            marker = shlex.quote(str(self.root / "candidate-ran")).encode()
            self.files["rivect"] = self.files["rivect"].replace(b"#!/bin/sh\n", b"#!/bin/sh\n: > " + marker + b"\n", 1)
        manifest = {"schema_version": version, "build": f"rivect {tag[1:]}"}
        entries = {"executable": "rivect", "helper": "rivect-sandbox-helper"}
        if version == 2:
            ext = "dylib" if target == TARGET else "so"
            entries.update(ui="libexec/rivect-tui", library=f"libexec/libopentui.{ext}")
            # Exercise a real dlopen and raw PTY exchange; only the renderer ABI is a fixture.
            self.files[entries["library"]] = Path(_ctypes.__file__).read_bytes() if library is None else library
            self.files[entries["ui"]] = ui if ui is not None else (f"#!{sys.executable}\n" + f"""import ctypes, os, termios, tty
from pathlib import Path
renderer_abi = ctypes.CDLL(str(Path(__file__).with_name('libopentui.{ext}'))).PyInit__ctypes
saved = termios.tcgetattr(0)
try:
    tty.setraw(0)
    os.write(1, b'\\x1b[?1049hMessage')
    if os.read(0, 1) != b'\\x03':
        raise SystemExit(1)
finally:
    termios.tcsetattr(0, termios.TCSANOW, saved)
    os.write(1, b'\\x1b[?1049l')
""").encode()
        for key, name in entries.items():
            manifest[key] = {"name": name, "sha256": hashlib.sha256(self.files[name]).hexdigest()}
        self.files["rivect.manifest.json"] = json.dumps(manifest).encode()
        assets = self.assets / tag
        assets.mkdir(exist_ok=True)
        self.archive = assets / f"rivect-{tag}-{target}.tar.gz"
        with tarfile.open(self.archive, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for name, content in self.files.items():
                info = tarfile.TarInfo(name)
                info.mode = 0o755 if name != "rivect.manifest.json" else 0o644
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        self.checksum = assets / f"{target}.sha256"
        self.checksum.write_text(hashlib.sha256(self.archive.read_bytes()).hexdigest() +
                                 f"  ./{self.archive.name}\n")

    def install(self, *args):
        return subprocess.run(["sh", str(ROOT / "install.sh"), *args], env=self.env,
                              capture_output=True, text=True, timeout=20)

    def test_v2_receipt(self):
        self.make_release(version=2)
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([p.name for p in self.selected_bundle().iterdir()], ["rivect"])
        release = (self.selected_bundle() / "rivect").resolve().parent
        receipt = release.with_suffix(".manifest.sha256")
        digest = hashlib.sha256(self.files["rivect.manifest.json"]).hexdigest()
        self.assertEqual(receipt.read_bytes(), (digest + "\n").encode())
        for name, content in self.files.items():
            self.assertEqual((release / name).read_bytes(), content)
        receipt.unlink()
        decoy = self.home / "decoy"
        decoy.write_text("unchanged")
        receipt.symlink_to(decoy)
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(decoy.read_text(), "unchanged")

    def test_rollback_reverifies_previous_v2_without_following_latest(self):
        self.make_release(version=2)
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        command = self.selected_bundle() / "rivect"
        previous = command.resolve().parent
        old_ui = previous / "libexec/rivect-tui"
        verified_ui = old_ui.read_bytes()

        self.make_release(version=2, tag="v0.1.2")
        self.env["LATEST_URL"] = RELEASES + "/tag/v0.1.2"
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        current = command.resolve().parent
        self.assertNotEqual(current, previous)

        old_ui.write_bytes(b"corrupt")
        rejected = self.install("--rollback", "v0.1.1")
        self.assertNotEqual(rejected.returncode, 0, rejected.stderr)
        self.assertIn("existing bundle differs from verified archive", rejected.stderr)
        self.assertEqual(command.resolve().parent, current)

        old_ui.write_bytes(verified_ui)
        self.log.unlink()
        result = self.install("--rollback", "v0.1.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(command.resolve().parent, previous)
        restored = subprocess.check_output([command, "--version"], env=self.env, text=True, timeout=5)
        self.assertEqual(restored, "rivect 0.1.1\n")
        self.assertEqual(self.log.read_text().splitlines(), [
            f"{RELEASES}/download/v0.1.1/rivect-v0.1.1-{TARGET}.tar.gz",
            f"{RELEASES}/download/v0.1.1/{TARGET}.sha256"])

    def test_rollback_refuses_republished_archive(self):
        self.make_release(version=2)
        installed = self.install()
        self.assertEqual(installed.returncode, 0, installed.stderr)
        previous = self.selected_bundle().resolve()
        self.make_release(version=2, helper=self.files["rivect-sandbox-helper"] + b"\n")
        refused = self.install("--rollback", "v0.1.1")
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("archive was not previously installed", refused.stderr)
        self.assertEqual(self.selected_bundle().resolve(), previous)

    def assert_rollback_refused_before_execution(self, tag):
        active = self.selected_bundle()
        before = (active.readlink(), active.lstat().st_ino, (active / "rivect").read_bytes())
        marker = self.root / "candidate-ran"
        marker.unlink(missing_ok=True)
        refused = self.install("--rollback", tag)
        self.assertFalse(marker.exists(), "rollback executed an unbound candidate")
        self.assertNotEqual(refused.returncode, 0, refused.stderr)
        self.assertEqual((active.readlink(), active.lstat().st_ino, (active / "rivect").read_bytes()), before)

    def test_rollback_refuses_cached_wrong_tag_without_execution(self):
        self.make_release(version=2)
        old_archive, old_checksum = self.archive, self.checksum
        self.assertEqual(self.install().returncode, 0)
        self.make_release(version=2, tag="v0.1.2")
        self.env["LATEST_URL"] = RELEASES + "/tag/v0.1.2"
        self.assertEqual(self.install().returncode, 0)
        self.assertEqual(self.install("--rollback", "v0.1.1").returncode, 0)
        shutil.copyfile(self.archive, old_archive)
        self.archive, self.checksum = old_archive, old_checksum
        self.rewrite_checksum()
        self.assert_rollback_refused_before_execution("v0.1.1")

    def test_rollback_refuses_another_platform_archive(self):
        self.assertEqual(self.install().returncode, 0)
        original = self.archive
        self.make_release(target="x86_64-unknown-linux-gnu")
        shutil.copyfile(original, self.archive)
        self.rewrite_checksum()
        self.env.update(FAKE_OS="Linux", FAKE_ARCH="x86_64")
        self.assert_rollback_refused_before_execution("v0.1.1")

    def test_rollback_refuses_missing_activation_record_without_execution(self):
        self.make_release(version=2)
        self.assertEqual(self.install().returncode, 0)
        active = self.selected_bundle()
        first = active.readlink().name
        self.make_release(version=2, tag="v0.1.2")
        self.env["LATEST_URL"] = RELEASES + "/tag/v0.1.2"
        self.assertEqual(self.install().returncode, 0)
        record = active.readlink().with_name(first)
        record.unlink()
        self.assert_rollback_refused_before_execution("v0.1.1")
        self.assertFalse(os.path.lexists(record), "rollback minted an activation record")

    def test_rollback_refuses_interrupted_activation_without_execution(self):
        self.assertEqual(self.install().returncode, 0)
        self.make_release(version=2, tag="v0.1.2")
        pause = self.root / "pause-doctor"
        entered = self.root / "doctor-entered"
        gate = f'if [ "$1" = doctor ] && [ -f {shlex.quote(str(pause))} ]; then : > {shlex.quote(str(entered))}; exec sleep 60; fi\n'
        cli = self.files["rivect"].replace(b"case $1 in", gate.encode() + b"case $1 in")
        self.make_release(version=2, tag="v0.1.2", executable=cli)
        self.env["LATEST_URL"] = RELEASES + "/tag/v0.1.2"
        pause.touch()
        with subprocess.Popen(["sh", ROOT / "install.sh"], env=self.env, start_new_session=True) as installer:
            try:
                deadline = time.monotonic() + 10
                while not entered.exists():
                    if installer.poll() is not None or time.monotonic() >= deadline:
                        self.fail("doctor did not reach interrupted activation boundary")
                    time.sleep(.01)
            finally:
                if installer.poll() is None:
                    os.killpg(installer.pid, signal.SIGKILL)
        pause.unlink()
        (self.selected_bundle().parent / ".install-lock").rmdir()
        self.assert_rollback_refused_before_execution("v0.1.2")

    def test_rollback_refuses_missing_manifest_receipt_without_execution(self):
        self.make_release(version=2)
        self.assertEqual(self.install().returncode, 0)
        receipt = (self.selected_bundle() / "rivect").resolve().parent.with_suffix(".manifest.sha256")
        receipt.unlink()
        self.assert_rollback_refused_before_execution("v0.1.1")
        self.assertFalse(receipt.exists(), "rollback minted a receipt")

    def test_checksum_mismatch_prevents_execution_and_preserves_active_bundle(self):
        self.assertEqual(self.install().returncode, 0)
        before = self.selected_bundle().readlink()
        self.make_release(version=2, tag="v0.1.2")
        self.env["LATEST_URL"] = RELEASES + "/tag/v0.1.2"
        self.checksum.write_text(f"{'0' * 64}  ./{self.archive.name}\n")
        refused = self.install()
        self.assertIn("archive checksum mismatch", refused.stderr)
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse((self.root / "candidate-ran").exists())
        self.assertEqual(self.selected_bundle().readlink(), before)

    def test_renderer_must_load_candidate_library_not_only_draw_frame(self):
        self.assertEqual(self.install().returncode, 0)
        before = self.selected_bundle().readlink()
        self.make_release(version=2)
        without_library = b"\n".join(line for line in self.files["libexec/rivect-tui"].split(b"\n")
                                     if not line.startswith(b"renderer_abi ="))
        self.make_release(version=2, ui=without_library)
        refused = self.install()
        self.assertNotEqual(refused.returncode, 0, refused.stderr)
        self.assertEqual(self.selected_bundle().readlink(), before)

    def test_v2_renderer_startup_and_exit_required_before_switch(self):
        self.assertEqual(self.install().returncode, 0)
        before = self.selected_bundle().readlink()
        self.env["LATEST_URL"] = RELEASES + "/tag/v0.1.2"
        self.make_release(version=2)
        pid_file = self.root / "hung-renderer"
        hung = self.files["libexec/rivect-tui"] + f"Path({str(pid_file)!r}).write_text(str(os.getpid()))\nimport time; time.sleep(60)\n".encode()
        for name, ui, library in [("no frame", b"#!/bin/sh\nexit 0\n", None),
                                  ("incompatible library", None, b"not a shared library"),
                                  ("hang after frame", hung, None)]:
            with self.subTest(name=name):
                self.make_release(version=2, tag="v0.1.2", ui=ui, library=library)
                refused = self.install()
                self.assertNotEqual(refused.returncode, 0, refused.stderr)
                self.assertEqual(self.selected_bundle().readlink(), before)
                if name == "hang after frame":
                    with self.assertRaises(ProcessLookupError):
                        os.kill(int(pid_file.read_text()), 0)

    def test_invalid_rollback_selection_never_downloads_or_activates(self):
        for args in [("--rollback",), ("--rollback", "v0.1.1/../../other"),
                     ("--rollback", ""), ("--other", "v0.1.1"), ("--rollback", "v0.1.1", "extra")]:
            with self.subTest(args=args):
                self.assertNotEqual(self.install(*args).returncode, 0)
                self.assertFalse(self.log.exists())
                self.assertFalse(self.selected_bundle().exists())

    def test_v2_activation_probes_preserve_previous(self):
        self.assertEqual(self.install().returncode, 0)
        before = self.selected_bundle().resolve()
        for executable, helper in ((b"#!/bin/sh\n[ \"$1\" = --version ]\n", None),
                                   (None, b"#!/bin/sh\nexit 0\n"),
                                   (None, b"#!/bin/sh\nexit 20\n")):
            with self.subTest(executable=executable, helper=helper):
                self.make_release(version=2, executable=executable, helper=helper)
                self.assertNotEqual(self.install().returncode, 0)
                self.assertEqual(self.selected_bundle().resolve(), before)

    def test_retired_manifest_is_rejected_before_execution(self):
        marker = shlex.quote(str(self.root / "candidate-ran"))
        executable = f"#!/bin/sh\n: > {marker}\necho rivect\n".encode()
        self.make_release(version=1, executable=executable)
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("unsupported manifest version", result.stderr)
        self.assertFalse((self.root / "candidate-ran").exists())
        self.assertFalse(os.path.lexists(self.selected_bundle()))

        self.make_release()
        installed = self.install()
        self.assertEqual(installed.returncode, 0, installed.stderr)
        active = self.selected_bundle().readlink()
        self.make_release(version=1, executable=executable, tag="v0.1.2")
        self.env["LATEST_URL"] = RELEASES + "/tag/v0.1.2"
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("unsupported manifest version", result.stderr)
        self.assertFalse((self.root / "candidate-ran").exists())
        self.assertEqual(self.selected_bundle().readlink(), active)

    def test_payload_mismatch_preserves_previous_bundle(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        previous = self.selected_bundle().resolve()
        self.make_release(version=2)
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, content in self.files.items():
                if name == "libexec/rivect-tui":
                    content += b"changed"
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        self.rewrite_checksum()
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest entry mismatch: ui", result.stderr)
        self.assertEqual(self.selected_bundle().resolve(), previous)
        release = previous.with_suffix("")
        self.assertEqual(set(previous.parent.iterdir()), {previous, release, release.with_suffix(".manifest.sha256")})

    def test_unrunnable_release_preserves_previous_bundle(self):
        initial = self.install()
        self.assertEqual(initial.returncode, 0, initial.stderr)
        previous = self.selected_bundle().resolve()
        expected = dict(self.files)
        self.make_release(executable=b"#!/bin/sh\nexit 126\n")
        failed = self.install()
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(self.selected_bundle().resolve(), previous)
        self.assert_bundle(expected)

    def test_installs_runnable_complete_bundle_from_pinned_release(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        profile = self.home / ".zshrc"
        self.assertTrue(profile.is_file())
        run = subprocess.run(["sh", "-c", '. "$HOME/.zshrc"; command -v rivect; rivect --version'],
                             env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        binary, version = run.stdout.splitlines()
        self.assertEqual(version, "rivect 0.1.1")
        bundle = Path(binary).resolve().parent
        for name, content in self.files.items():
            self.assertEqual((bundle / name).read_bytes(), content)
        self.assertEqual(self.log.read_text().splitlines(), [RELEASES + "/latest",
                         RELEASES + f"/download/v0.1.1/{self.archive.name}",
                         RELEASES + f"/download/v0.1.1/{TARGET}.sha256"])

    def selected_bundle(self):
        return self.home / ".local/share/rivect/bin"

    def assert_bundle(self, expected):
        active = self.selected_bundle()
        self.assertTrue(active.is_symlink())
        self.assertEqual([path.name for path in active.iterdir()], ["rivect"])
        bundle = (active / "rivect").resolve().parent
        self.assertEqual({path.relative_to(bundle).as_posix() for path in bundle.rglob("*")
                          if path.is_file()}, set(expected))
        for name, content in expected.items():
            self.assertEqual((bundle / name).read_bytes(), content)
        run = subprocess.run([str(active / "rivect"), "--version"], env=self.env,
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse((active.parent / ".install-lock").exists())
        self.assertEqual(list(active.parent.glob(".download.*")), [])
        self.assertEqual(list((active.parent / "releases").glob(".staging.*")), [])

    def rewrite_checksum(self):
        self.checksum.write_text(hashlib.sha256(self.archive.read_bytes()).hexdigest() +
                                 f"  {self.archive.name}\n")

    def test_reinstall_keeps_one_bundle_and_one_path_entry_without_losing_profile(self):
        profile = self.home / ".zshrc"
        profile.write_text("# existing preferences\nexport KEPT=yes\n")
        for _ in range(2):
            result = self.install()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("cannot change PATH in its parent shell", result.stderr)
            self.assert_bundle(self.files)
        release = (self.selected_bundle() / "rivect").resolve().parent
        receipt = release.with_suffix(".manifest.sha256")
        self.assertEqual(set(release.parent.iterdir()), {release, receipt, release.with_suffix(".commands")})
        self.assertEqual(receipt.read_text(), hashlib.sha256(self.files["rivect.manifest.json"]).hexdigest() + "\n")
        text = profile.read_text()
        self.assertTrue(text.startswith("# existing preferences\nexport KEPT=yes\n"))
        self.assertEqual(text.count("# Rivect user-local installation"), 1)
        run = subprocess.run(["sh", "-c", '. "$HOME/.zshrc"; . "$HOME/.zshrc"; printf "%s\\n%s\\n" "$PATH" "$KEPT"'],
                             env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        path, kept = run.stdout.splitlines()
        self.assertEqual(path.split(":").count(str(self.selected_bundle())), 1)
        self.assertEqual(kept, "yes")

    def test_linux_x86_64_selects_linux_assets(self):
        target = "x86_64-unknown-linux-gnu"
        self.make_release(target)
        self.env.update(FAKE_OS="Linux", FAKE_ARCH="x86_64")
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_bundle(self.files)
        self.assertIn(f"/download/v0.1.1/{target}.sha256", self.log.read_text())

    def test_unsupported_platform_fails_before_network_or_filesystem_changes(self):
        for os_name, arch in [("Darwin", "x86_64"), ("Linux", "aarch64"), ("Windows_NT", "AMD64")]:
            with self.subTest(platform=(os_name, arch)):
                self.env.update(FAKE_OS=os_name, FAKE_ARCH=arch)
                result = self.install()
                self.assertEqual(result.returncode, 1)
                self.assertIn("unsupported platform", result.stderr)
                self.assertFalse(self.log.exists())
                self.assertEqual(list(self.home.iterdir()), [])

    def test_home_spaces_and_shell_quotes_are_literal(self):
        self.home = self.root / "home with 'single' and \"double\" $dollar \\ backslash"
        self.home.mkdir()
        self.env["HOME"] = str(self.home)
        self.test_installs_runnable_complete_bundle_from_pinned_release()
        self.assert_bundle(self.files)

    def test_bash_updates_interactive_and_existing_login_profiles_idempotently(self):
        self.env["SHELL"] = "/bin/bash"
        (self.home / ".bash_login").write_text("# existing login\n")
        for _ in range(2):
            result = self.install()
            self.assertEqual(result.returncode, 0, result.stderr)
        for name in [".bashrc", ".bash_login"]:
            text = (self.home / name).read_text()
            self.assertEqual(text.count("# Rivect user-local installation"), 1)
            run = subprocess.run(["bash", "-c", '. "$1"; rivect --version', "bash", str(self.home / name)],
                                 env=self.env, capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout, "rivect 0.1.1\n")
        self.assertFalse((self.home / ".bash_profile").exists())

    def test_zdotdir_and_fish_config_location(self):
        zdotdir = self.home / "zsh preferences"
        self.env["ZDOTDIR"] = str(zdotdir)
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((zdotdir / ".zshrc").is_file())
        self.assertFalse((self.home / ".zshrc").exists())
        self.env["SHELL"] = "/usr/bin/fish"
        self.env["XDG_CONFIG_HOME"] = str(self.home / "config preferences")
        for _ in range(2):
            result = self.install()
            self.assertEqual(result.returncode, 0, result.stderr)
        text = (Path(self.env["XDG_CONFIG_HOME"]) / "fish/config.fish").read_text()
        self.assertEqual(text.count("# Rivect user-local installation"), 1)
        self.assertIn('set -gx PATH "$HOME/.local/share/rivect/bin" $PATH', text)

    def test_empty_shell_uses_posix_profile(self):
        self.env["SHELL"] = ""
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        run = subprocess.run(["sh", "-c", '. "$HOME/.profile"; rivect --version'],
                             env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, "rivect 0.1.1\n")

    def test_failed_download_or_checksum_preserves_working_install(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = dict(self.files)
        previous = self.selected_bundle().resolve()
        archive_bytes = self.archive.read_bytes()
        checksum_text = self.checksum.read_text()
        for failure in ["archive missing", "checksum missing", "checksum wrong", "checksum extra", "archive corrupt"]:
            with self.subTest(failure=failure):
                self.archive.write_bytes(archive_bytes)
                self.checksum.write_text(checksum_text)
                if failure == "archive missing":
                    self.archive.unlink()
                elif failure == "checksum missing":
                    self.checksum.unlink()
                elif failure == "checksum wrong":
                    self.checksum.write_text("0" * 64 + f"  {self.archive.name}\n")
                elif failure == "checksum extra":
                    self.checksum.write_text(checksum_text + checksum_text)
                else:
                    self.archive.write_bytes(b"not a gzip archive")
                result = self.install()
                self.assertEqual(result.returncode, 1, result.stderr)
                if failure == "archive corrupt":
                    self.assertIn("archive checksum mismatch", result.stderr)
                self.assertEqual(self.selected_bundle().resolve(), previous)
                self.assert_bundle(expected)

    def test_failed_profile_install_preserves_previous_selection(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        previous = self.selected_bundle().resolve()
        expected = dict(self.files)
        (self.home / ".zshrc").unlink()
        (self.home / ".zshrc").mkdir()
        # A different valid bundle must not activate before all install steps succeed.
        self.make_release(executable=self.files["rivect"] + b"\n")
        result = self.install()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("shell profile is not a regular file", result.stderr)
        self.assertEqual(self.selected_bundle().resolve(), previous)
        self.assert_bundle(expected)

    def test_malicious_tar_inventory_never_extracts_or_replaces_previous_bundle(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = dict(self.files)
        previous = self.selected_bundle().resolve()
        escaped = self.root / "escaped"
        for attack in ["traversal", "absolute", "symlink", "hardlink", "directory", "duplicate", "extra", "missing", "pax traversal"]:
            with self.subTest(attack=attack):
                with tarfile.open(self.archive, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                    for name, content in self.files.items():
                        if attack == "missing" and name == "rivect.manifest.json":
                            continue
                        info = tarfile.TarInfo(name)
                        info.size = len(content)
                        if name == "rivect":
                            if attack == "traversal": info.name = "../escaped"
                            elif attack == "absolute": info.name = str(escaped)
                            elif attack == "pax traversal": info.pax_headers = {"path": "../escaped"}
                            elif attack in ["symlink", "hardlink", "directory"]:
                                info.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                                             "directory": tarfile.DIRTYPE}[attack]
                                info.linkname = str(escaped)
                                info.size = 0
                        archive.addfile(info, io.BytesIO(content) if info.isreg() else None)
                    if attack in ["duplicate", "extra"]:
                        info = tarfile.TarInfo("rivect" if attack == "duplicate" else "extra")
                        archive.addfile(info, io.BytesIO(b""))
                self.rewrite_checksum()
                result = self.install()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse(escaped.exists())
                self.assertFalse((previous.parent / "escaped").exists())
                self.assertEqual(self.selected_bundle().resolve(), previous)
                self.assert_bundle(expected)

    @unittest.skipUnless(os.environ.get("RIVECT_V2_TEST_BUNDLE"), "requires a native v2 candidate")
    def test_native_v2_activation(self):
        bundle = Path(os.environ["RIVECT_V2_TEST_BUNDLE"]).resolve(strict=True)
        (self.tools / "uname").unlink()  # use the real host, not the installer fixture target
        target = {("Darwin", "arm64"): TARGET, ("Linux", "x86_64"): "x86_64-unknown-linux-gnu"}[
            (os.uname().sysname, os.uname().machine)]
        self.make_release(target=target, version=2, tag="v0.1.0")
        self.env["LATEST_URL"] = RELEASES + "/tag/v0.1.0"
        installed = self.install()
        self.assertEqual(installed.returncode, 0, installed.stderr)
        oldest = (self.selected_bundle() / "rivect").resolve().parent
        del self.env["LATEST_URL"]
        self.make_release(target=target)
        with tarfile.open(self.archive, "w:gz", format=tarfile.USTAR_FORMAT, compresslevel=1) as archive:
            for part in bundle.rglob("*"):
                if not part.is_dir():
                    archive.add(part, arcname=str(part.relative_to(bundle)), recursive=False)
        self.rewrite_checksum()
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        command = self.selected_bundle() / "rivect"
        self.assertEqual(os.listdir(command.parent), ["rivect"])
        ui = command.resolve().parent / "libexec/rivect-tui"
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        env = {"TERM": "xterm-256color", "PATH": "/usr/bin:/bin", "HOME": str(self.home),
               "TMPDIR": str(self.home)}
        with subprocess.Popen([command], cwd=self.home, env=env, stdin=slave, stdout=slave, stderr=slave) as child:
            try:
                wait_text(master, b"Message")
                os.write(master, b"before-switch\r")
                dismiss_pending(master)
                db = self.home / ".rivect/runtime/rivect.db"
                with sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True) as store:
                    [(session, goal)] = store.execute("SELECT session_id, goal_bytes FROM tasks").fetchall()
                    self.assertEqual(goal, b"before-switch")

                # Neither control's CLI speaks the wire protocol. Reconnect must reopen the pinned owner.
                self.make_release(target=target, version=2, tag="v0.1.2")
                self.env["LATEST_URL"] = RELEASES + "/tag/v0.1.2"
                for switch in ((), ("--rollback", "v0.1.0")):
                    result = self.install(*switch)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotEqual(command.resolve().parent, ui.parent.parent)
                    if switch:
                        self.assertEqual(command.resolve().parent, oldest)
                    os.write(master, b"/resume\r")
                    wait_text(master, session.encode())

                    # Force a late component open; keeping the original owner alive would not test pinning.
                    [pid] = subprocess.check_output(["pgrep", "-P", str(child.pid)], env=env, timeout=5).split()
                    owner = int(pid)
                    args = subprocess.check_output(["ps", "-ww", "-p", str(owner), "-o", "args="],
                                                   env=env, text=True, timeout=5).strip()
                    self.assertTrue(args.endswith(" --ui-terminal-wire-v1"), args)
                    os.kill(owner, signal.SIGKILL)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        try:
                            os.kill(owner, 0)
                        except ProcessLookupError:
                            break
                        time.sleep(.01)
                    else:
                        self.fail("previous wire owner was not reaped")
                    os.write(master, f"/resume {session}\r".encode())
                    dismiss_pending(master)
                    with sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True) as store:
                        self.assertEqual(store.execute("SELECT session_id, goal_bytes FROM tasks").fetchall(),
                                         [(session, b"before-switch")])
                os.write(master, b"\x03")
                self.assertEqual(wait_terminal_exit(master, child), 130)
            finally:
                if child.poll() is None:
                    child.kill()

        rolled_back = self.install("--rollback", "v0.1.1")
        self.assertEqual(rolled_back.returncode, 0, rolled_back.stderr)
        self.assertEqual(command.resolve().parent, ui.parent.parent)
        for proof in ("installed_test.py", "session_test.py"):
            subprocess.run([sys.executable, str(ROOT / "tui" / proof), str(ui)],
                           env=env, check=True, timeout=60)

    def test_latest_resolution_failure_or_unsafe_tag_preserves_working_install(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        previous = self.selected_bundle().resolve()
        for url in ["http://github.com/ViktorsBaikers/Rivect/releases/tag/v0.1.1",
                    "https://example.invalid/releases/tag/v0.1.1",
                    RELEASES + "/tag/v0.1.1/../../payload",
                    RELEASES + "/tag/v0.1.1\nextra"]:
            with self.subTest(url=url):
                self.env["LATEST_URL"] = url
                result = self.install()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(self.selected_bundle().resolve(), previous)
                self.assert_bundle(self.files)
        del self.env["LATEST_URL"]
        self.env["FAIL_LATEST"] = "1"
        self.assertEqual(self.install().returncode, 1)
        self.assert_bundle(self.files)


if __name__ == "__main__":
    unittest.main()
