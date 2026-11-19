#!/usr/bin/env python3
"""Offline checks for evidence reuse and release failure boundaries."""
from contextlib import ExitStack, suppress
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import tarfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseTag(unittest.TestCase):
    def test_tag_must_match_current_package_version(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        step = workflow.split("- name: verify release tag matches package version", 1)[1]
        script = textwrap.dedent(step.split("run: |\n", 1)[1].split("      - ", 1)[0])
        cargo = r'''cargo() {
    test "$*" = 'metadata --locked --no-deps --format-version 1' || return 2
    printf '%s\n' '{"packages":[{"name":"rivect","version":"0.2.0"}]}'
}
'''
        for ref, tag, expected in [("refs/heads/main", "main", 0),
                                   ("refs/tags/v0.2.0", "v0.2.0", 0),
                                   ("refs/tags/v0.1.0", "v0.1.0", 1)]:
            with self.subTest(ref=ref):
                result = subprocess.run(["bash", "-euo", "pipefail", "-c", cargo + script],
                    env={"PATH": os.environ["PATH"], "GITHUB_REF": ref, "GITHUB_REF_NAME": tag},
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stderr)


class LinuxPrerequisites(unittest.TestCase):
    def test_transport_failure_tries_secondary_but_rejects_its_corrupt_archive(self):
        with tempfile.TemporaryDirectory(prefix="rivect-ci-download-") as directory:
            root = Path(directory)
            (root / "sudo").write_text("#!/bin/sh\nexit 0\n")
            (root / "curl").write_text(textwrap.dedent('''\
                #!/bin/sh
                while [ "$#" -gt 0 ]; do
                    case "$1" in
                        https://*) url=$1 ;;
                        -o) output=$2; shift ;;
                    esac
                    shift
                done
                printf '%s\\n' "$url" >> "$TMPDIR/requests"
                case "$url" in
                    https://mirrors.edge.kernel.org/*) exit 28 ;;
                    https://cdn.kernel.org/*) printf 'corrupt archive' > "$output" ;;
                    *) exit 2 ;;
                esac
                '''))
            for name in ("sudo", "curl"):
                (root / name).chmod(0o700)
            result = subprocess.run(["sh", ROOT / "scripts/ci-linux-prerequisites.sh"],
                env={"PATH": f"{root}:{os.environ['PATH']}", "TMPDIR": directory, "LC_ALL": "C"},
                capture_output=True, text=True, timeout=10)
            hosts = [line.split("/")[2] for line in (root / "requests").read_text().splitlines()]
            self.assertEqual(hosts, ["mirrors.edge.kernel.org", "cdn.kernel.org"])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FAILED", result.stdout)


class EvidenceReuse(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rivect-ci-contract-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        (self.bundle / "rivect.manifest.json").write_text("{}\n")
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.manifest = self.root / "search.json"
        self.manifest.write_text(json.dumps({
            "schema_version": 1, "family": "search", "rows": [
                {"case_id": f"case-{i}", "provider": "offline",
                 "marker": f"ROW case-{i} ok", "expected": "pass",
                 "observation": "independent fixture", "oracle": ["search_text::probe"]}
                for i in range(20)
            ]
        }))
        self.log = self.logs / "search_text.log"
        self.log.write_text("test probe ... ok\n" + "\n".join(
            f"ROW case-{i} ok" for i in range(20)) +
            "\ntest result: ok. 1 passed; 0 failed; 0 ignored\n")
        self.status = self.logs / "search_text.json"
        self.record = {
            "exit": 0, "candidate_manifest_sha256": digest(self.bundle / "rivect.manifest.json"),
            "output_sha256": digest(self.log),
            "command": "cargo test --locked --test search_text -- --show-output",
        }
        self.save_record()
        self.receipt = self.root / "receipt.json"

    def save_record(self):
        self.status.write_text(json.dumps(self.record))

    def produce(self):
        # No Cargo exists at this path: log consumption must not execute tests.
        return subprocess.run([
            "sh", str(ROOT / "scripts/offline-evidence.sh"),
            "--manifest", str(self.manifest), "--receipt", str(self.receipt),
            "--bundle", str(self.bundle), "--logs-dir", str(self.logs),
        ], env={**os.environ, "CARGO": str(self.root / "must-not-run-cargo")},
            capture_output=True, text=True, cwd=ROOT)

    def test_one_execution_can_serve_multiple_receipts_without_rerun(self):
        for _ in range(2):
            result = self.produce()
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(self.receipt.read_text())
            self.assertEqual(receipt["counts"], {"rows": 20, "pass": 20, "unserved": 0})
            self.assertEqual(receipt["targets"][0]["output_sha256"], digest(self.log))
            self.assertIn("--show-output", receipt["targets"][0]["command"])

    def test_failed_stale_tampered_or_absent_execution_refuses_old_receipt(self):
        for field, value in [("exit", 101), ("candidate_manifest_sha256", "f" * 64),
                             ("output_sha256", "e" * 64)]:
            with self.subTest(field=field):
                original = self.record[field]
                self.record[field] = value
                self.save_record()
                self.receipt.write_text("stale receipt")
                self.assertNotEqual(self.produce().returncode, 0)
                self.assertFalse(self.receipt.exists())
                self.record[field] = original
        self.save_record()
        self.status.unlink()
        self.assertNotEqual(self.produce().returncode, 0)

    def test_a36_partial_evidence_requires_current_complete_native_measurements(self):
        rows = json.loads(self.manifest.read_text())["rows"][:3]
        selector = "v2_installed_package_measurement"
        marker = "PACKAGE_SIZE_MEASUREMENT"
        rows.append({"case_id": "A36", "provider": "offline", "marker": marker,
                     "expected": "unserved", "observation": "partial measurement",
                     "oracle": ["measurement::" + selector]})
        self.manifest.write_text(json.dumps({"schema_version": 1, "family": "acceptance", "rows": rows}))
        current = self.record["candidate_manifest_sha256"]
        prerequisite = "missing exact candidate resource observations"
        for digest_value, status, reason, missing_probe, accepted in [
            (current, "NOT_RUN", prerequisite, False, True),
            ("f" * 64, "NOT_RUN", prerequisite, False, False),
            (current, "PASS", prerequisite, False, False),
            (current, "NOT_RUN", "", False, False),
            (current, "NOT_RUN", prerequisite, True, False),
        ]:
            with self.subTest(digest_value=digest_value, status=status, reason=reason,
                              missing_probe=missing_probe):
                probes = dict.fromkeys(("version", "headless_cancel", "headless_search",
                                        "headless_index", "headless_status_polling"), 123)
                if missing_probe:
                    del probes["headless_cancel"]
                sample = {"schema_version": 1,
                          "v2": {"manifest_sha256": digest_value, "payload_files": 5,
                                 "receipt_bytes": 65, "payload_bytes": 1000,
                                 "installed_bytes": 1065, "local_tar_gz_bytes": 500},
                          "headless": {"elapsed_ns_one_sample_per_probe": probes},
                          "ac003": {"status": status, "prerequisite": reason}}
                log = self.logs / "measurement.log"
                log.write_text(f"test {selector} ... ok\n{marker} {json.dumps(sample)}\n"
                               "test result: ok. 1 passed; 0 failed; 0 ignored\n")
                (self.logs / "measurement.json").write_text(json.dumps({**self.record,
                    "output_sha256": digest(log), "command": "cargo test --locked --test measurement -- --show-output"}))
                result = self.produce()
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if accepted:
                    self.assertEqual(json.loads(self.receipt.read_text())["counts"], {"rows": 4, "pass": 3, "unserved": 1})
                else:
                    self.assertFalse(self.receipt.exists())

    def test_ignored_or_missing_oracle_never_serves_rows(self):
        for text in ["test probe ... ignored\n", "test another ... ok\n"]:
            self.log.write_text(text)
            self.record["output_sha256"] = digest(self.log)
            self.save_record()
            self.assertNotEqual(self.produce().returncode, 0)
            self.assertFalse(self.receipt.exists())


class CrossHostBinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rivect-ci-bind-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.receipts = {}
        self.make_candidates(2)

    def make_candidates(self, version):
        for platform, legs in [
            ("linux", ["auth.secret_service"]),
            ("macos", ["auth.keychain"]),
        ]:
            files = {"rivect": f"{platform} executable".encode(),
                     "rivect-sandbox-helper": f"{platform} helper".encode()}
            manifest = {"schema_version": version, "build": "rivect 0.1.0 (same-source)"}
            components = [("executable", "rivect"), ("helper", "rivect-sandbox-helper")]
            library = "libexec/libopentui." + ("so" if platform == "linux" else "dylib")
            components.extend([("ui", "libexec/rivect-tui"), ("library", library)])
            files.update({name: name.encode() for _, name in components[2:]})
            for key, name in components:
                manifest[key] = {"name": name, "sha256": hashlib.sha256(files[name]).hexdigest()}
            files["rivect.manifest.json"] = json.dumps(manifest).encode()
            host = self.root / f"xhost/xhost-{platform}"
            host.mkdir(parents=True, exist_ok=True)
            with tarfile.open(host / "candidate.tar.gz", "w:gz") as archive:
                for name, content in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
            receipt = {"schema_version": 2, "commit": "same-commit", "run_id": "42",
                       "platform": platform, "served_legs": legs,
                       "candidate_manifest_sha256": hashlib.sha256(files["rivect.manifest.json"]).hexdigest()}
            (host / 'candidate.manifest.sha256').write_text(receipt['candidate_manifest_sha256'] + '\n')
            bom = host / 'candidate.cdx.json'
            bom.write_text(json.dumps({'bomFormat':'CycloneDX','components':[{'type':'file','name':name,
                'hashes':[{'alg':'SHA-256','content':hashlib.sha256(content).hexdigest()}]} for name, content in files.items()]}))
            receipt['sbom_sha256'] = digest(bom)
            path = host / "xhost-receipt.json"
            path.write_text(json.dumps(receipt))
            self.receipts[platform] = (path, receipt)
            if platform == "linux":
                for name, content in files.items():
                    (self.bundle / name).parent.mkdir(parents=True, exist_ok=True)
                    (self.bundle / name).write_bytes(content)

    def bind(self):
        return subprocess.run(
            ["sh", str(ROOT / "scripts/xhost-bind.sh"), str(self.bundle), "same-commit"],
            cwd=self.root, env={**os.environ, "GITHUB_RUN_ID": "42"},
            capture_output=True, text=True)

    def test_complete_pair_binds_only_its_tested_candidate(self):
        result = self.bind()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads((self.root / "target/rivect-not-run-xhost/served.json").read_text())
        self.assertEqual(receipt["served_legs"],
                         ["auth.keychain", "auth.secret_service"])
        self.assertEqual(receipt["candidate_sha256"], digest(self.bundle / "rivect.manifest.json"))

    def test_unsupported_package_schema_never_binds(self):
        self.make_candidates(1)
        self.assertNotEqual(self.bind().returncode, 0)

    def test_changed_receipt_or_sbom_cannot_bind(self):
        for name in ['candidate.manifest.sha256', 'candidate.cdx.json']:
            target = self.root / 'xhost/xhost-macos' / name
            previous = target.read_bytes()
            target.write_bytes(previous + b'x')
            self.assertNotEqual(self.bind().returncode, 0)
            target.write_bytes(previous)

    def test_same_commit_cannot_rescue_wrong_run_platform_candidate_or_legs(self):
        path, original = self.receipts["linux"]
        for field, value in [("run_id", "old-run"), ("platform", "macos"),
                             ("candidate_manifest_sha256", "f" * 64), ("served_legs", [])]:
            with self.subTest(field=field):
                path.write_text(json.dumps({**original, field: value}))
                self.assertNotEqual(self.bind().returncode, 0)
        path.write_text(json.dumps(original))
        (self.bundle / "rivect.manifest.json").write_text("{}")
        self.assertNotEqual(self.bind().returncode, 0)

    def test_missing_host_or_tampered_archive_cannot_bind(self):
        archive = self.root / "xhost/xhost-macos/candidate.tar.gz"
        archive.unlink()
        self.assertNotEqual(self.bind().returncode, 0)
        with tarfile.open(archive, "w:gz"):
            pass
        self.assertNotEqual(self.bind().returncode, 0)


class ReleaseGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rivect-ci-gate-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(ROOT / "scripts/release-gate.sh", self.root / "scripts/release-gate.sh")
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        (self.bundle / "rivect.manifest.json").write_text('{"schema_version":2}')
        self.cargo = self.root / "cargo"
        self.cargo.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
with open('commands.jsonl', 'a') as stream:
    stream.write(json.dumps(sys.argv[1:]) + '\\n')
pathlib.Path('target').mkdir(exist_ok=True)
if os.environ.get('OMIT_VERDICT') != '1':
    pathlib.Path('target/final-acceptance.json').write_text(os.environ['VERDICT'])
sys.exit(int(os.environ['TEST_EXIT']))
""")
        self.cargo.chmod(0o755)

    def gate(self, ready, retained=0, code=0, omit=False):
        return subprocess.run([
            "sh", str(self.root / "scripts/release-gate.sh"), "--bundle", str(self.bundle),
            "--receipts-only",
        ], cwd=self.root, capture_output=True, text=True, env={
            **os.environ, "CARGO": str(self.cargo), "TEST_EXIT": str(code),
            "OMIT_VERDICT": str(int(omit)),
            "VERDICT": json.dumps({
                "schema_version": 1, "required": 1,
                "candidate_manifest_sha256": digest(self.bundle / "rivect.manifest.json"),
                "release_ready": ready, "blockers": {"retained_legs": retained},
            }),
        })

    def test_receipts_only_runs_exactly_one_conjunction_not_producers(self):
        result = self.gate(True)
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = [json.loads(line) for line in (self.root / "commands.jsonl").read_text().splitlines()]
        self.assertEqual(commands, [[
            "test", "--locked", "--test", "final_acceptance",
            "final_acceptance_passes_the_installed_rows_and_prints_the_verdict",
            "--", "--exact", "--show-output",
        ]])

    def test_v1_never_becomes_a_native_release_gate(self):
        (self.bundle / "rivect.manifest.json").write_text('{"schema_version":1}')
        self.assertNotEqual(self.gate(True).returncode, 0)

    def test_not_ready_is_distinct_from_crash_and_ready_cannot_hide_failure(self):
        for ready, retained, code, omit, expected in [
            (False, 0, 101, False, 5), (True, 1, 101, False, 5),
            (True, 0, 101, False, 1), (True, 0, 0, True, 1),
            ("true", 0, 0, False, 1), (True, -1, 0, False, 1),
            (False, 0, 137, False, 1), (False, 0, 143, False, 1),
        ]:
            with self.subTest(ready=ready, retained=retained, code=code, omit=omit):
                self.assertEqual(self.gate(ready, retained, code, omit).returncode, expected)


class TargetOwnership(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="rivect-ci-owner-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "scripts").mkdir()
        for script in ["ci-test.py", "offline-evidence.sh"]:
            shutil.copyfile(ROOT / "scripts" / script, self.root / "scripts" / script)
        fixtures = self.root / "tests/fixtures"
        fixtures.mkdir(parents=True)
        (fixtures.parent / "search_text.rs").touch()
        for stem, family, count in [
            ("provider-trials", "provider", 234), ("search-trials", "search", 20),
            ("acceptance-rows-a01-a12", "acceptance", 12),
            ("acceptance-rows-a13-a24", "acceptance", 12),
            ("acceptance-rows-a25-a36", "acceptance", 12),
            ("acceptance-rows-sections", "acceptance", 4),
        ]:
            (fixtures / f"{stem}.json").write_text(json.dumps({
                "schema_version": 1, "family": family, "rows": [
                    {"case_id": f"case-{i}", "provider": "offline", "expected": "pass",
                     "marker": f"ROW case-{i} ok", "observation": "fixture",
                     "oracle": ["search_text::probe"]} for i in range(count)
                ],
            }))
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        (self.bundle / "rivect.manifest.json").write_text("{}")
        tools = self.root / "tools"
        tools.mkdir()
        self.cargo = tools / "cargo"
        self.cargo.write_text("""#!/usr/bin/env python3
import json, os, socket, sys
from pathlib import Path
parallel_targets = ['provider_openai', 'provider_local']
phase_port = os.environ.get('CI_CONTRACT_PHASE_GATE_PORT')
if sys.argv[1] == 'metadata':
    with open('metadata-entries.jsonl','a') as stream:
        stream.write(json.dumps(sys.argv[1:])+'\\n')
    gate_port = os.environ.get('CI_CONTRACT_METADATA_GATE_PORT')
    if gate_port:
        with socket.create_connection(('127.0.0.1', int(gate_port)), timeout=60) as gate:
            gate.sendall(b'R')
            if gate.recv(1) != b'G':
                raise RuntimeError('metadata gate closed without release')
    print(json.dumps({'workspace_members':['root','helper'], 'packages':[
        {'id':'root','name':'rivect','targets':[
            {'name':'rivect','kind':['lib'],'test':True},
            *[{'name':name,'kind':['test'],'test':True}
              for name in ['search_text','new_target','final_acceptance']
              + (parallel_targets if phase_port else [])]]},
        {'id':'helper','name':'rivect-sandbox-helper','targets':[
            {'name':'rivect_sandbox_helper','kind':['lib'],'test':True},
            {'name':'rivect-sandbox-helper','kind':['bin'],'test':True},
            {'name':'launch','kind':['test'],'test':True}]},
    ]}))
    sys.exit(0)
target = sys.argv[sys.argv.index('--test')+1] if '--test' in sys.argv else None
if phase_port:
    import fcntl
    parallel = target in parallel_targets
    # Hold the phase lock until process exit, including while a worker waits at the gate.
    active = open('cargo-active.lock', 'a')
    mode = fcntl.LOCK_SH if parallel else fcntl.LOCK_EX
    fcntl.flock(active, mode | fcntl.LOCK_NB)
    if sys.argv[1] == 'record-evidence':
        commands = Path('commands.jsonl').read_text().splitlines()
        with open('evidence-entries.jsonl', 'a') as stream:
            stream.write(json.dumps(commands)+'\\n')
        sys.exit(0)
with open('commands.jsonl','a') as stream:
    stream.write(json.dumps(sys.argv[1:])+'\\n')
if phase_port and target in parallel_targets:
    with socket.create_connection(('127.0.0.1', int(phase_port)), timeout=30) as gate:
        gate.sendall((target+'\\n').encode())
        if gate.recv(1) != b'G':
            raise RuntimeError('parallel target gate closed without release')
if sys.argv[1] == 'build':
    Path('native-helper').touch()
    sys.exit(0)
if '--lib' in sys.argv and 'rivect-sandbox-helper' in sys.argv and not Path('native-helper').exists():
    print('native helper executable is missing before unit tests')
    sys.exit(101)
if target is not None:
    if target == os.environ.get('FAIL_TARGET'):
        print('test probe ... FAILED')
        sys.exit(101)
print('test probe ... ok')
for i in range(234): print(f'ROW case-{i} ok')
print('test result: ok. 1 passed; 0 failed; 0 ignored')
""")
        self.cargo.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
                    "RIVECT_TEST_BUNDLE": str(self.bundle), "CARGO": str(self.cargo)}

    def run_targets(self, fail=""):
        return subprocess.run(["python3", str(self.root / "scripts/ci-test.py")],
                              cwd=self.root, env={**self.env, "FAIL_TARGET": fail},
                              capture_output=True, text=True)

    def test_new_targets_are_included_once_and_shared_oracles_are_not_rerun(self):
        result = self.run_targets()
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = [json.loads(line) for line in (self.root / "commands.jsonl").read_text().splitlines()]
        targets = [args[args.index("--test") + 1] for args in commands if "--test" in args]
        self.assertEqual(sorted(targets), ["final_acceptance", "launch", "new_target", "search_text"])
        self.assertEqual(targets[0], "launch")
        self.assertEqual(len(list((self.root / "target").glob("*trials.json"))), 2)
        self.assertEqual(len(list((self.root / "target").glob("acceptance-rows-*.json"))), 4)

    def test_empty_restored_logs_run_once_and_replay_preserves_evidence(self):
        target = self.root / "target"
        logs = target / "ci-logs"
        logs.mkdir(parents=True)
        self.assertEqual(list(logs.iterdir()), [])

        result = self.run_targets()
        self.assertEqual(result.returncode, 0, result.stderr)
        commands_path = self.root / "commands.jsonl"
        original_commands = commands_path.read_bytes()
        commands = [json.loads(line) for line in original_commands.splitlines()]
        targets = [args[args.index("--test") + 1] for args in commands if "--test" in args]
        self.assertEqual(len(commands), 7)
        self.assertEqual(sorted(targets), ["final_acceptance", "launch", "new_target", "search_text"])
        self.assertEqual(targets[0], "launch")
        receipts = list(target.glob("*trials.json")) + list(target.glob("acceptance-rows-*.json"))
        self.assertCountEqual([path.name for path in receipts], [
            "provider-trials.json", "search-trials.json",
            "acceptance-rows-a01-a12.json", "acceptance-rows-a13-a24.json",
            "acceptance-rows-a25-a36.json", "acceptance-rows-sections.json",
        ])
        original_evidence = {
            path.relative_to(target): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in target.rglob("*") if path.is_file()
        }

        result = self.run_targets()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(commands_path.read_bytes(), original_commands)
        self.assertEqual({
            path.relative_to(target): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in target.rglob("*") if path.is_file()
        }, original_evidence)

    def test_symlink_logs_are_refused_without_writing_through_link(self):
        outside = self.root / "outside-logs"
        outside.mkdir()
        logs = self.root / "target/ci-logs"
        logs.parent.mkdir()
        logs.symlink_to(outside, target_is_directory=True)

        result = self.run_targets()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(logs.is_symlink())
        self.assertEqual(logs.readlink(), outside)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(list(logs.parent.iterdir()), [logs])
        self.assertFalse((self.root / "commands.jsonl").exists())

    def test_markerless_nonempty_logs_refuse_cargo_without_changing_evidence(self):
        target = self.root / "target"
        logs = target / "ci-logs"
        logs.mkdir(parents=True)
        (logs / "search_text.log").write_bytes(b"restored search output\n")
        original_evidence = {
            path.relative_to(target): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in target.rglob("*") if path.is_file()
        }

        result = self.run_targets()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "metadata-entries.jsonl").exists())
        self.assertFalse((self.root / "commands.jsonl").exists())
        self.assertEqual({
            path.relative_to(target): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in target.rglob("*") if path.is_file()
        }, original_evidence)

    def test_concurrent_runner_refuses_second_invocation_before_cargo(self):
        command = ["python3", str(self.root / "scripts/ci-test.py")]
        env = {**self.env, "FAIL_TARGET": "", "GITHUB_REF": "refs/heads/ci-contract-tests"}
        expected_metadata = [["metadata", "--locked", "--no-deps", "--format-version", "1"]]
        processes = []
        gate = None
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(30)
            try:
                first = subprocess.Popen(
                    command, cwd=self.root,
                    env={**env, "CI_CONTRACT_METADATA_GATE_PORT": str(listener.getsockname()[1])},
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    start_new_session=True)
                processes.append(first)
                gate, _ = listener.accept()
                gate.settimeout(30)
                self.assertEqual(gate.recv(1), b"R")
                self.assertFalse((self.root / "commands.jsonl").exists())

                second = subprocess.Popen(
                    command, cwd=self.root, env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    start_new_session=True)
                processes.append(second)
                _, stderr = second.communicate(timeout=30)
                self.assertNotEqual(second.returncode, 0, stderr)
                self.assertEqual([
                    json.loads(line) for line in
                    (self.root / "metadata-entries.jsonl").read_text().splitlines()
                ], expected_metadata)
                self.assertFalse((self.root / "commands.jsonl").exists())
                self.assertIsNone(first.poll())

                gate.sendall(b"G")
                _, stderr = first.communicate(timeout=60)
                self.assertEqual(first.returncode, 0, stderr)
                self.assertEqual([
                    json.loads(line) for line in
                    (self.root / "metadata-entries.jsonl").read_text().splitlines()
                ], expected_metadata)
                commands = [
                    json.loads(line) for line in
                    (self.root / "commands.jsonl").read_text().splitlines()
                ]
                self.assertEqual(commands, [
                    ["build", "--locked", "-p", "rivect-sandbox-helper",
                     "--bin", "rivect-sandbox-helper"],
                    ["test", "--locked", "-p", "rivect-sandbox-helper",
                     "--lib", "--bins", "--", "--show-output"],
                    ["test", "--locked", "-p", "rivect-sandbox-helper",
                     "--test", "launch", "--", "--show-output"],
                    ["test", "--locked", "-p", "rivect", "--lib", "--", "--show-output"],
                    ["test", "--locked", "--test", "final_acceptance", "--", "--show-output"],
                    ["test", "--locked", "--test", "new_target", "--", "--show-output"],
                    ["test", "--locked", "--test", "search_text", "--", "--show-output"],
                ])
            finally:
                if gate is not None:
                    gate.close()
                for child in processes:
                    try:
                        child.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            child.wait(timeout=10)
                        child.communicate(timeout=10)

    def test_failed_target_blocks_receipts_but_keeps_diagnostics(self):
        result = self.run_targets("search_text")
        self.assertNotEqual(result.returncode, 0)
        status = json.loads((self.root / "target/ci-logs/search_text.json").read_text())
        self.assertEqual(status["exit"], 101)
        self.assertFalse((self.root / "target/provider-trials.json").exists())

    def _run_bounded_targets(self, fail=""):
        script = self.root / "scripts/offline-evidence.sh"
        script.rename(script.with_name("offline-evidence-real.sh"))
        script.write_text(
            '#!/bin/sh\nset -eu\ncargo record-evidence\n'
            'exec sh scripts/offline-evidence-real.sh "$@"\n')
        targets = ["provider_openai", "provider_local"]
        command = ["python3", str(self.root / "scripts/ci-test.py"), "--jobs", "2"]
        output_path = self.root / "runner.log"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener, \
                output_path.open("w+") as output, ExitStack() as stack:
            listener.bind(("127.0.0.1", 0))
            listener.listen(2)
            listener.settimeout(10)
            env = {key: self.env[key] for key in ("PATH", "HOME", "LANG", "TMPDIR", "CARGO",
                                                  "RIVECT_TEST_BUNDLE") if key in self.env}
            env.update(FAIL_TARGET=fail, GITHUB_REF="refs/heads/ci-contract-tests",
                       CI_CONTRACT_PHASE_GATE_PORT=str(listener.getsockname()[1]))
            with subprocess.Popen(command, cwd=self.root, env=env, stdout=output,
                                  stderr=subprocess.STDOUT, start_new_session=True) as runner:
                try:
                    gates = []
                    for _ in targets:
                        gate, _ = listener.accept()
                        stack.enter_context(gate)
                        gate.settimeout(10)
                        with gate.makefile("rb") as ready:
                            gates.append((ready.readline(64).decode().strip(), gate))
                    self.assertCountEqual([name for name, _ in gates], targets)
                    self.assertEqual(self._bounded_receipts(), [])
                    # Unblock the peer before the failing target can trigger cancellation.
                    for _, gate in sorted(gates, key=lambda entry: entry[0] == fail):
                        gate.sendall(b"G")
                    result = runner.wait(timeout=60)
                except (TimeoutError, subprocess.TimeoutExpired) as error:
                    output.seek(0)
                    self.fail(f"bounded runner did not finish its handshake or run: {error}\n{output.read()}")
                finally:
                    if runner.returncode is None:
                        with suppress(ProcessLookupError):
                            os.killpg(runner.pid, signal.SIGKILL)
                        runner.wait(timeout=10)
            output.seek(0)
            return result, output.read()

    def _bounded_receipts(self):
        target = self.root / "target"
        return [path.name for pattern in ("*trials.json", "acceptance-rows-*.json")
                for path in target.glob(pattern)]

    def test_bounded_targets_overlap_in_isolation_before_receipts(self):
        result, output = self._run_bounded_targets()
        self.assertEqual(result, 0, output)
        commands = (self.root / "commands.jsonl").read_text().splitlines()
        checks = [args[args.index("--test") + 1] if "--test" in args
                  else (args[0], args[args.index("-p") + 1])
                  for args in map(json.loads, commands)]
        self.assertCountEqual(checks, [
            "final_acceptance", "launch", "new_target", "provider_local", "provider_openai",
            "search_text", ("build", "rivect-sandbox-helper"), ("test", "rivect-sandbox-helper"),
            ("test", "rivect"),
        ])
        receipts = self._bounded_receipts()
        self.assertCountEqual(receipts, [
            "provider-trials.json", "search-trials.json",
            "acceptance-rows-a01-a12.json", "acceptance-rows-a13-a24.json",
            "acceptance-rows-a25-a36.json", "acceptance-rows-sections.json",
        ])
        evidence_entries = (self.root / "evidence-entries.jsonl").read_text().splitlines()
        self.assertEqual(list(map(json.loads, evidence_entries)), [commands] * len(receipts))

    def _assert_bounded_failure(self, failed):
        result, output = self._run_bounded_targets(fail=failed)
        self.assertNotEqual(result, 0, output)
        logs = self.root / "target/ci-logs"
        log = logs / f"{failed}.log"
        status = json.loads((logs / f"{failed}.json").read_text())
        self.assertEqual(status["exit"], 101)
        self.assertIn("test probe ... FAILED", log.read_text())
        self.assertEqual(status["output_sha256"], digest(log))
        self.assertEqual(self._bounded_receipts(), [])
        commands = (self.root / "commands.jsonl").read_text().splitlines()
        targets = [args[args.index("--test") + 1] for args in map(json.loads, commands)
                   if "--test" in args]
        for name in ("provider_openai", "provider_local"):
            self.assertEqual(targets.count(name), 1, targets)
        self.assertFalse((self.root / "evidence-entries.jsonl").exists())

    def test_failed_bounded_openai_target_keeps_diagnostics_without_receipts(self):
        self._assert_bounded_failure("provider_openai")

    def test_failed_bounded_local_target_keeps_diagnostics_without_receipts(self):
        self._assert_bounded_failure("provider_local")


class ReleasePublisher(unittest.TestCase):
    def test_publication_boundaries(self):
        # Execute the write-token step itself; gh alone is replaced offline.
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        script = textwrap.dedent(workflow.split("  publish:\n", 1)[1]
                                 .split("        run: |\n", 1)[1])
        sha = "c" * 40
        targets = ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin"]
        scenarios = ["ready", "not-ready", "missing", "tampered", "foreign",
                     "moved-tag", "upload-fails", "malformed", "moved-during-upload",
                     "tampered-installer", "missing-installer", "mismatched-installer", "tampered-sbom", "tampered-receipt"]
        scenarios += ["missing-resources", "tampered-resources", "foreign-resource-archive"]
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                dist = root / "dist"
                dist.mkdir()
                installer_bytes = (ROOT / "install.sh").read_bytes()
                for target in targets:
                    manifest = json.dumps({"schema_version": 2, "build": target}).encode()
                    archive = dist / f"rivect-v0.1.1-{target}.tar.gz"
                    with tarfile.open(archive, "w:gz") as output:
                        info = tarfile.TarInfo("rivect.manifest.json")
                        info.size = len(manifest)
                        output.addfile(info, io.BytesIO(manifest))
                    (dist / f"{target}.sha256").write_text(
                        f"{digest(archive)}  ./{archive.name}\n")
                    base = f'rivect-v0.1.1-{target}'
                    candidate = hashlib.sha256(manifest).hexdigest()
                    (dist / f'{base}.manifest.sha256').write_text(candidate + '\n')
                    bom = dist / f'{base}.cdx.json'
                    bom.write_text(json.dumps({'components':[{'type':'file', 'name':'rivect.manifest.json',
                        'hashes':[{'alg':'SHA-256', 'content':candidate}]}]}))
                    resources = dist / f"{base}.resources.json"
                    resources.write_text(json.dumps({"archive_sha256": digest(archive)}))
                    installer = dist / f"install-{target}.sh"
                    installer.write_bytes(installer_bytes)
                    if scenario == "mismatched-installer" and target == targets[0]:
                        installer.write_bytes(installer_bytes + b"\n# different installer\n")
                    ready = not (scenario == "not-ready" and target == targets[0])
                    verdict = {
                        "schema_version": 1, "target": target, "commit": sha, "run_id": "7",
                        "candidate_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                        "installer_sha256": digest(installer),
                        "sbom_sha256": digest(bom),
                        "resources_sha256": digest(resources),
                        "archive_sha256": digest(archive),
                        "gate_exit": 0 if ready else 5, "release_ready": ready,
                        "blockers": {"retained_legs": 0 if ready else 1},
                    }
                    if scenario == "foreign":
                        verdict["commit"] = "d" * 40
                    if scenario == "malformed":
                        verdict["release_ready"] = "true"
                    if scenario == "foreign-resource-archive" and target == targets[0]:
                        verdict["archive_sha256"] = "e" * 64
                    (dist / f"report-{target}.json").write_text(json.dumps(verdict))
                    if target == targets[0] and scenario == 'tampered-sbom':
                        bom.write_bytes(bom.read_bytes() + b' ')
                    if target == targets[0] and scenario == 'tampered-receipt':
                        (dist / f'{base}.manifest.sha256').write_text('0'*64 + '\n')
                    if target == targets[0] and scenario == "missing-resources":
                        resources.unlink()
                    if target == targets[0] and scenario == "tampered-resources":
                        resources.write_bytes(resources.read_bytes() + b" ")
                first = dist / f"rivect-v0.1.1-{targets[0]}.tar.gz"
                if scenario == "missing":
                    first.unlink()
                if scenario == "tampered":
                    first.write_bytes(b"changed")
                installer = dist / f"install-{targets[0]}.sh"
                if scenario == "tampered-installer":
                    installer.write_bytes(installer_bytes + b"\n# tampered\n")
                if scenario == "missing-installer":
                    installer.unlink()
                gh = root / "gh"
                gh.write_text(textwrap.dedent("""\
                    #!/usr/bin/env python3
                    import json, os, pathlib, sys
                    with open(os.environ['CALLS'], 'a') as stream:
                        stream.write(json.dumps(sys.argv[1:])+'\\n')
                    if sys.argv[1] == 'api':
                        if not sys.argv[2].endswith('/commits/' + os.environ['GITHUB_REF_NAME']):
                            sys.exit(2)
                        prior = pathlib.Path(os.environ['CALLS']).read_text()
                        moved = os.environ['SCENARIO'] == 'moved-during-upload' and 'create' in prior
                        print('d' * 40 if moved else os.environ['TAG_SHA'])
                    if sys.argv[1:3] == ['release','create'] and os.environ['SCENARIO'] == 'upload-fails':
                        sys.exit(1)
                    """))
                gh.chmod(0o755)
                calls_path = root / "calls.jsonl"
                env = {
                    **os.environ, "PATH": f'{root}:{os.environ["PATH"]}',
                    "CALLS": str(calls_path), "SCENARIO": scenario,
                    "TAG_SHA": "d" * 40 if scenario == "moved-tag" else sha,
                    "GITHUB_REF_NAME": "v0.1.1", "GITHUB_SHA": sha, "GITHUB_RUN_ID": "7",
                    "GITHUB_REPOSITORY": "offline/fixture",
                }
                result = subprocess.run(["bash", "-euo", "pipefail", "-c", script],
                                        cwd=root, env=env, capture_output=True, text=True)
                calls = ([json.loads(line) for line in calls_path.read_text().splitlines()]
                         if calls_path.exists() else [])
                mutations = [call for call in calls if call[0] == "release"]
                creates = [call for call in mutations if call[:2] == ["release", "create"]]
                for create in creates:
                    for target in targets:
                        for suffix in ['cdx.json', 'manifest.sha256', 'resources.json', 'tar.gz']:
                            self.assertIn(f'./rivect-v0.1.1-{target}.{suffix}', create)
                    self.assertEqual(create.count("install.sh"), 1, create)
                    self.assertEqual(create.count("./install.sh.sha256"), 1, create)
                    self.assertFalse(any(arg.startswith("install-") for arg in create), create)
                    self.assertEqual((dist / "install.sh").read_bytes(), installer_bytes)
                    self.assertEqual((dist / "install.sh.sha256").read_text(),
                                     f"{digest(dist / 'install.sh')}  install.sh\n")
                if scenario == "ready":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual([call[:2] for call in mutations],
                                     [["release", "create"], ["release", "edit"]])
                    self.assertIn("--draft", mutations[0])
                    self.assertIn("--draft=false", mutations[1])
                elif scenario == "not-ready":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(mutations), 1, calls)
                    self.assertIn("--prerelease", mutations[0])
                    self.assertIn("--draft", mutations[0])
                else:
                    self.assertNotEqual(result.returncode, 0, calls)
                    self.assertEqual(len(mutations),
                                     1 if scenario in ["upload-fails", "moved-during-upload"] else 0,
                                     calls)


if __name__ == "__main__":
    unittest.main()
