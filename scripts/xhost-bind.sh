#!/bin/sh
# Bind only complete same-run receipts to one of their tested candidates.
# usage: xhost-bind.sh <bundle-dir> <commit>
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 bundle commit" >&2; exit 2; }
python3 - "$1" "$2" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile

bundle, commit = Path(sys.argv[1]), sys.argv[2]
destination = Path("target/rivect-not-run-xhost/served.json")
destination.unlink(missing_ok=True)
expected = {
    "linux": ["auth.secret_service"],
    "macos": ["auth.keychain"],
}
candidates = []
builds = []
for platform, legs in expected.items():
    root = Path("xhost") / f"xhost-{platform}"
    receipt = json.loads((root / "xhost-receipt.json").read_text())
    if (receipt.get("schema_version") != 2 or receipt.get("commit") != commit
            or receipt.get("run_id") != os.environ.get("GITHUB_RUN_ID", "local")
            or receipt.get("platform") != platform or receipt.get("served_legs") != legs):
        raise SystemExit(f"invalid cross-host receipt: {platform}")
    with tarfile.open(root / "candidate.tar.gz") as archive:
        members = archive.getmembers()
        if not all(m.type in (tarfile.REGTYPE, tarfile.AREGTYPE) for m in members) or not any(m.name == "rivect.manifest.json" for m in members):
            raise SystemExit(f"invalid bundle inventory: {platform}")
        manifest_bytes = archive.extractfile("rivect.manifest.json").read()
        candidate = hashlib.sha256(manifest_bytes).hexdigest()
        if candidate != receipt.get("candidate_manifest_sha256"):
            raise SystemExit(f"candidate mismatch: {platform}")
        if (root / 'candidate.manifest.sha256').read_bytes() != (candidate + '\n').encode():
            raise SystemExit(f"detached manifest mismatch: {platform}")
        bom = (root / 'candidate.cdx.json').read_bytes()
        if hashlib.sha256(bom).hexdigest() != receipt.get('sbom_sha256'):
            raise SystemExit(f"candidate sbom mismatch: {platform}")
        manifest = json.loads(manifest_bytes)
        components = [("executable", "rivect"), ("helper", "rivect-sandbox-helper")]
        if manifest.get("schema_version") != 2:
            raise SystemExit(f"required native candidate: {platform}")
        ext = "so" if platform == "linux" else "dylib"
        components.extend([("ui", "libexec/rivect-tui"), ("library", "libexec/libopentui." + ext)])
        if sorted(m.name for m in members) != sorted(["rivect.manifest.json", *(n for _, n in components)]):
            raise SystemExit(f"invalid bundle inventory: {platform}")
        for key, name in components:
            actual = hashlib.file_digest(archive.extractfile(name), "sha256").hexdigest()
            if manifest[key]["name"] != name or manifest[key]["sha256"] != actual:
                raise SystemExit(f"binary digest mismatch: {platform}/{name}")
        builds.append(manifest["build"])
        candidates.append(candidate)
candidate = hashlib.sha256((bundle / "rivect.manifest.json").read_bytes()).hexdigest()
if candidate not in candidates or builds[0] != builds[1]:
    raise SystemExit("acting candidate was not tested by this workflow")
destination.parent.mkdir(parents=True, exist_ok=True)
temporary = destination.with_suffix(".tmp")
temporary.write_text(json.dumps({
    "schema_version": 1, "candidate_sha256": candidate, "host": "ci-cross-host",
    "served_legs": sorted(leg for legs in expected.values() for leg in legs),
}) + "\n")
temporary.replace(destination)
PY