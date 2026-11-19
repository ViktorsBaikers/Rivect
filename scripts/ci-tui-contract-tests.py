#!/usr/bin/env python3
"""Offline contracts for the packaged TUI suite runner."""

import contextlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest


RUNNER = Path("scripts/ci-tui-test.py")


class TuiRunnerContract(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="rivect tui contract ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.tui = self.root / "tui"
        self.tui.mkdir()
        self.logs = self.root / "target/tui-ci-logs"
        self.bundle = self.root / "candidate"
        (self.bundle / "libexec").mkdir(parents=True)
        for binary in (self.bundle / "rivect", self.bundle / "libexec/rivect-tui"):
            binary.write_text(f"#!/bin/sh\nprintf '%s\\n' '{binary.name}'\n", encoding="utf-8")
            binary.chmod(0o755)

        source = Path(__file__).resolve().parents[1] / RUNNER
        (self.root / RUNNER.parent).mkdir()
        if source.is_file():
            shutil.copyfile(source, self.root / RUNNER)

    def write_suite(self, stem, source):
        (self.tui / f"{stem}.py").write_text(source, encoding="utf-8")

    def run_suites(self):
        with subprocess.Popen(
            [sys.executable, str(RUNNER), str(self.bundle)],
            cwd=self.root,
            env={"PATH": os.environ.get("PATH", os.defpath), "HOME": str(self.root)},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        ) as runner:
            try:
                output, _ = runner.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                # Reap blocked handshake fixtures as well as the runner.
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(runner.pid, signal.SIGKILL)
                output, _ = runner.communicate()
                self.fail(f"{RUNNER} did not finish:\n{output}")
        return runner.returncode, output

    def test_discovers_each_suite_and_passes_the_exact_candidate(self):
        routes = {
            "installed_test": "libexec/rivect-tui",
            "thread_test": "libexec/rivect-tui",
            "input_test": "libexec/rivect-tui",
            "operator_test": "libexec/rivect-tui",
            "session_test": "libexec/rivect-tui",
            "streaming_test": "libexec/rivect-tui",
            "startup_test": "rivect",
            "new_streaming_test": "rivect",
        }
        for stem in routes:
            self.write_suite(stem, """\
import json
from pathlib import Path
import subprocess
import sys

candidate = subprocess.check_output([sys.argv[1]], text=True).strip()
with Path(__file__).with_suffix('.calls').open('a', encoding='utf-8') as calls:
    print(json.dumps([str(Path.cwd()), sys.argv[1:], candidate]), file=calls)
""")
        (self.tui / "nested").mkdir()
        for ignored in ("helper", "nested/ignored_test"):
            self.write_suite(ignored, "raise SystemExit('unexpected suite')\n")

        status, output = self.run_suites()
        self.assertEqual(status, 0, output)
        self.assertEqual({path.stem for path in self.tui.glob("*.calls")}, set(routes))
        for stem, route in routes.items():
            with self.subTest(suite=stem):
                records = (self.tui / f"{stem}.calls").read_text(encoding="utf-8").splitlines()
                self.assertEqual(
                    [json.loads(record) for record in records],
                    [[str(self.tui), [str(self.bundle / route)], Path(route).name]],
                )

    def test_finishes_other_suites_after_a_failure_and_keeps_complete_logs(self):
        suites = {"a_failing_test": 7, "b_surviving_test": 0, "c_surviving_test": 0}
        for stem, status in suites.items():
            self.write_suite(stem, f"""\
import sys

for index in range(512):
    print({stem!r}, 'stdout', index, flush=True)
    print({stem!r}, 'stderr', index, file=sys.stderr, flush=True)
sys.exit({status})
""")

        status, output = self.run_suites()
        self.assertNotEqual(status, 0, output)
        self.assertEqual({path.stem for path in self.logs.glob("*.log")}, set(suites), output)
        for stem in suites:
            with self.subTest(suite=stem):
                log = (self.logs / f"{stem}.log").read_text(encoding="utf-8").splitlines()
                for stream in ("stdout", "stderr"):
                    suite_lines = [line for line in log if line.startswith(f"{stem} {stream} ")]
                    self.assertEqual(suite_lines, [f"{stem} {stream} {i}" for i in range(512)])
                for other in suites.keys() - {stem}:
                    self.assertFalse(any(line.startswith(f"{other} ") for line in log))

    def test_runs_at_most_two_suites_at_once(self):
        pairs = 4
        for pair in range(pairs):
            os.mkfifo(self.tui / f"pair-{pair}")
        for index in range(2 * pairs):
            self.write_suite(f"handshake_{index}_test", """\
import fcntl
from pathlib import Path

with Path('events').open('a+', encoding='utf-8') as events:
    fcntl.flock(events, fcntl.LOCK_EX)
    events.seek(0)
    arrival = sum(event == '+\\n' for event in events)
    events.write('+\\n')
    events.flush()
    fcntl.flock(events, fcntl.LOCK_UN)

    fifo = Path(f'pair-{arrival // 2}')
    if arrival % 2:
        with fifo.open('wb') as peer:
            peer.write(b'!')
    else:
        with fifo.open('rb') as peer:
            if peer.read(1) != b'!':
                raise SystemExit('missing peer handshake')
    events.write('-\\n')
""")

        status, output = self.run_suites()
        self.assertEqual(status, 0, output)
        events = (self.tui / "events").read_text(encoding="utf-8").splitlines()
        self.assertCountEqual(events, ["+"] * (2 * pairs) + ["-"] * (2 * pairs))
        active = peak = 0
        for event in events:
            active += 1 if event == "+" else -1
            peak = max(peak, active)
        self.assertEqual(peak, 2, events)


if __name__ == "__main__":
    unittest.main()
