#!/usr/bin/env python3
"""Run each Cargo target once; project family receipts from those exact logs."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from time import monotonic

ROOT = Path(__file__).resolve().parents[1]
CONJUNCTION = "final_acceptance_passes_the_installed_rows_and_prints_the_verdict"
# Only targets with isolated stores, roots or loopback fixtures. Start the
# longest suites first; new targets stay serial until their resources are audited.
PARALLEL_TARGETS = (
    "provider_local", "provider_gitlab", "provider_openai", "search_symbols",
    "provider_anthropic", "provider_cloudcode", "provider_gemini", "search_text",
    "provider_bedrock", "provider_copilot", "provider_vertex", "search_ast", "search_index",
)


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=1)
    jobs = parser.parse_args().jobs
    bundle = Path(os.environ["RIVECT_TEST_BUNDLE"]).resolve(strict=True)
    logs = ROOT / "target/ci-logs"
    # Logs are proof for this invocation, never a restored build cache.
    logs.mkdir(parents=True, exist_ok=True)
    if logs.is_symlink() or any(logs.iterdir()):
        raise FileExistsError(f"ci logs directory is not fresh: {logs}")
    (logs / "invocation.log").touch(exist_ok=False)
    candidate = sha256(bundle / "rivect.manifest.json")
    env = {**os.environ, "CARGO_TERM_COLOR": "never", "RUST_TEST_THREADS": "2"}
    env.pop("RUST_TEST_NOCAPTURE", None)
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        cwd=ROOT, env=env))
    packages = [p for p in metadata["packages"] if p["id"] in metadata["workspace_members"]]
    # Process-heavy helper launches run before the rest of the process table fills.
    packages.sort(key=lambda p: (p["name"] != "rivect-sandbox-helper", p["name"]))
    failed = []
    skipped = []
    parallel = {}

    def execute(name, command, threads):
        start = monotonic()
        output = logs / f"{name}.log"
        with output.open("wb") as stream:
            result = subprocess.run(command, cwd=ROOT,
                                    env={**env, "RUST_TEST_THREADS": threads},
                                    stdout=stream, stderr=subprocess.STDOUT)
        seconds = round(monotonic() - start, 3)
        (logs / f"{name}.json").write_text(json.dumps({
            "command": shlex.join(command), "exit": result.returncode,
            "candidate_manifest_sha256": candidate, "output_sha256": sha256(output),
            "duration_seconds": seconds,
        }) + "\n")
        return name, result.returncode, seconds

    def report(execution):
        name, status, seconds = execution
        # Only the main thread emits groups; the raw logs never interleave.
        print(f"::group::{name}", flush=True)
        with (logs / f"{name}.log").open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                print(line, end="")
        print(f"\n{name}: {seconds:.2f}s (exit {status})\n::endgroup::", flush=True)
        if status:
            failed.append(name)

    def run(name, command, threads):
        report(execute(name, command, threads))

    for package in packages:
        name = package["name"]
        threads = "1" if name == "rivect-sandbox-helper" else "2"
        if name == "rivect-sandbox-helper":
            # Unit harnesses locate a normal executable; --bins builds test harnesses.
            run("rivect-sandbox-helper-build",
                ["cargo", "build", "--locked", "-p", name, "--bin", name], threads)
        kinds = {kind for target in package["targets"] for kind in target["kind"]}
        flags = [flag for kind, flag in [("lib", "--lib"), ("bin", "--bins"),
                                        ("example", "--examples")] if kind in kinds]
        if flags:
            run(f"{name}-unit", ["cargo", "test", "--locked", "-p", name,
                                 *flags, "--", "--show-output"], threads)
        for target in sorted(package["targets"], key=lambda t: t["name"]):
            if "test" not in target["kind"] or not target["test"]:
                continue
            target_name = target["name"]
            args = []
            # These three pre-existing repository-policy checks require ignored
            # agent/ADR/research inputs not distributed in the source checkout.
            if target_name == "activation" and not (ROOT / "research/stack-selection.md").exists():
                args += ["--skip", "the_stack_admission_inputs_are_present_and_accepted"]
            if target_name == "code_conventions" and not (ROOT / "AGENTS.md").exists():
                args += ["--skip", "always_on_instructions_keep_their_size_budget",
                         "--skip", "every_denied_lint_stays_visible_to_agents"]
            if target_name == "index_worker" and sys.platform == "darwin":
                # Linux /proc carrier oracles remain owned by the Linux matrix leg.
                args += ["--skip", "alive_observer_passes_only_the_allowlist",
                         "--skip", "answer_cap_stop_kills_and_reaps_the_worker",
                         "--skip", "cancel_stop_kills_and_reaps_the_worker",
                         "--skip", "cancellation_reaches_the_worker_and_ends_the_run",
                         "--skip", "footprint_stop_threshold_is_the_memory_budget"]
            if (target_name == "final_acceptance"
                    and os.environ.get("GITHUB_REF", "").startswith("refs/tags/v")):
                args += ["--skip", CONJUNCTION]
            skipped.extend({"target": target_name, "test": test, "status": "NOT_RUN"}
                           for test in args[1::2])
            # Root oracle commands retain the consumer's --test target contract.
            command = ["cargo", "test", "--locked"]
            if name != "rivect":
                command += ["-p", name]
            command += ["--test", target_name, "--", "--show-output", *args]
            log_name = target_name if name == "rivect" else f"{name}-{target_name}"
            if jobs > 1 and name == "rivect" and target_name in PARALLEL_TARGETS:
                parallel[target_name] = command
            else:
                run(log_name, command, threads)
    if parallel:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            work = [pool.submit(execute, name, parallel[name], "2")
                    for name in PARALLEL_TARGETS if name in parallel]
            for target in as_completed(work):
                report(target.result())
    (logs / "not-run.json").write_text(json.dumps(skipped, indent=2) + "\n")
    if failed:
        raise RuntimeError(f"failed Cargo targets: {', '.join(failed)}")
    manifests = ["provider-trials", "acceptance-rows-a01-a12", "acceptance-rows-a13-a24",
                 "acceptance-rows-a25-a36", "acceptance-rows-sections", "search-trials"]
    for manifest in manifests:
        subprocess.run(["sh", "scripts/offline-evidence.sh", "--manifest",
                        f"tests/fixtures/{manifest}.json", "--receipt", f"target/{manifest}.json",
                        "--bundle", str(bundle), "--logs-dir", str(logs)], cwd=ROOT, env=env, check=True)


if __name__ == "__main__":
    main()
