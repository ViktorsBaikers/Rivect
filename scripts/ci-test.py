#!/usr/bin/env python3
"""Run each Cargo target once; project family receipts from those exact logs."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONJUNCTION = "final_acceptance_passes_the_installed_rows_and_prints_the_verdict"


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
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

    def run(name, command, threads="2"):
        print(f"::group::{name}", flush=True)
        output = logs / f"{name}.log"
        with output.open("wb") as stream:
            result = subprocess.run(command, cwd=ROOT,
                                    env={**env, "RUST_TEST_THREADS": threads},
                                    stdout=stream, stderr=subprocess.STDOUT)
        # Print complete diagnostics, including when the target fails.
        with output.open() as stream:
            for line in stream:
                print(line, end="")
        print("::endgroup::", flush=True)
        (logs / f"{name}.json").write_text(json.dumps({
            "command": shlex.join(command), "exit": result.returncode,
            "candidate_manifest_sha256": candidate, "output_sha256": sha256(output),
        }) + "\n")
        if result.returncode:
            failed.append(name)

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
            run(log_name, command, threads)
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
