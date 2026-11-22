#!/usr/bin/env python3
"""Run each packaged OpenTUI suite once and retain separate diagnostics."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from pathlib import Path
import subprocess
import sys
from time import monotonic

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_CLIENT = frozenset({
    "input_test.py", "installed_test.py", "operator_test.py",
    "scroll_test.py", "share_test.py", "session_test.py", "streaming_test.py", "thread_test.py",
})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    bundle = parser.parse_args().bundle.resolve(strict=True)
    tui = ROOT / "tui"
    suites = sorted(tui.glob("*_test.py"))
    if not suites:
        parser.error("no OpenTUI suites found")
    logs = ROOT / "target/tui-ci-logs"
    logs.mkdir(parents=True, exist_ok=True)
    env = {key: os.environ[key] for key in (
        "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TERM", "CI",
        "CARGO_HOME", "CARGO_TARGET_DIR", "RUSTUP_HOME", "RIVECT_TEST_BUN",
    ) if key in os.environ}

    def run(suite):
        client = bundle / ("libexec/rivect-tui" if suite.name in PRIVATE_CLIENT else "rivect")
        log = logs / f"{suite.stem}.log"
        start = monotonic()
        with log.open("wb") as output:
            print(f"starting OpenTUI suite: {suite.name}", flush=True)
            status = subprocess.run([sys.executable, str(suite), str(client)], cwd=tui,
                                    env=env, stdout=output, stderr=subprocess.STDOUT).returncode
        return suite.name, status, log, monotonic() - start

    failed = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        for work in as_completed([pool.submit(run, suite) for suite in suites]):
            name, status, log, seconds = work.result()
            print(f"::group::{name} ({seconds:.2f}s, exit {status})", flush=True)
            with log.open(encoding="utf-8", errors="replace") as output:
                for line in output:
                    print(line, end="")
            print("\n::endgroup::", flush=True)
            if status:
                failed.append(name)
    if failed:
        print(f"failed OpenTUI suites: {', '.join(sorted(failed))}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
