#!/usr/bin/env python3
"""Offline installer contracts: real shell/filesystem, simulated HTTPS only."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
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
if not url.startswith(base + '/download/v0.1.1/'):
    sys.exit(22)
source = pathlib.Path(os.environ['FIXTURES']) / url.rsplit('/', 1)[-1]
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

    def make_release(self, target=TARGET, executable=None):
        self.files = {"rivect": b"#!/bin/sh\nprintf 'rivect 0.1.1\\n'\n",
                      "rivect-sandbox-helper": b"#!/bin/sh\nprintf 'helper 0.1.1\\n'\n"}
        if executable is not None:
            self.files["rivect"] = executable
        manifest = {"schema_version": 1, "build": "rivect 0.1.1"}
        for key, name in [("executable", "rivect"), ("helper", "rivect-sandbox-helper")]:
            manifest[key] = {"name": name, "sha256": hashlib.sha256(self.files[name]).hexdigest()}
        self.files["rivect.manifest.json"] = json.dumps(manifest).encode()
        self.archive = self.assets / f"rivect-v0.1.1-{target}.tar.gz"
        with tarfile.open(self.archive, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for name, content in self.files.items():
                info = tarfile.TarInfo(name)
                info.mode = 0o755 if name != "rivect.manifest.json" else 0o644
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        self.checksum = self.assets / f"{target}.sha256"
        self.checksum.write_text(hashlib.sha256(self.archive.read_bytes()).hexdigest() +
                                 f"  ./{self.archive.name}\n")

    def install(self):
        return subprocess.run(["sh", str(ROOT / "install.sh")], env=self.env,
                              capture_output=True, text=True, timeout=20)

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
        bundle = self.selected_bundle()
        self.assertTrue(bundle.is_symlink())
        self.assertEqual(set(path.name for path in bundle.iterdir()), set(expected))
        for name, content in expected.items():
            self.assertEqual((bundle / name).read_bytes(), content)
        for name in ["rivect", "rivect-sandbox-helper"]:
            run = subprocess.run([str(bundle / name), "--version"], env=self.env,
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse((bundle.parent / ".install-lock").exists())
        self.assertEqual(list(bundle.parent.glob(".download.*")), [])
        self.assertEqual(list((bundle.parent / "releases").glob(".staging.*")), [])

    def rewrite_checksum(self):
        self.checksum.write_text(hashlib.sha256(self.archive.read_bytes()).hexdigest() +
                                 f"  {self.archive.name}\n")

    def test_reinstall_keeps_one_bundle_and_one_path_entry_without_losing_profile(self):
        profile = self.home / ".zshrc"
        profile.write_text("# existing preferences\nexport KEPT=yes\n")
        for _ in range(2):
            result = self.install()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_bundle(self.files)
        self.assertEqual(len(list((self.selected_bundle().parent / "releases").iterdir())), 1)
        text = profile.read_text()
        self.assertTrue(text.startswith("# existing preferences\nexport KEPT=yes\n"))
        self.assertEqual(text.count("# Rivect user-local installation"), 1)
        run = subprocess.run(["sh", "-c", '. "$HOME/.zshrc"; . "$HOME/.zshrc"; printf "%s\\n%s\\n" "$PATH" "$KEPT"'],
                             env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        path, kept = run.stdout.splitlines()
        self.assertEqual(path.split(":").count(str(self.selected_bundle())), 1)
        self.assertEqual(kept, "yes")
        self.assertIn("cannot change PATH in its parent shell", result.stderr)

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
        with tarfile.open(self.archive, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for name, content in self.files.items():
                info = tarfile.TarInfo(name)
                content += b"\n"
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        self.rewrite_checksum()
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
