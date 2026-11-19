"""Measure physical files and fresh-process startup; no inference or UI."""
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import perf_counter_ns


kit = Path(sys.argv[1]).resolve(strict=True)
fixture = Path(__file__).resolve().parents[1] / 'tests/fixtures/messages-sdk'
# Resolve the real runtime rather than charging a version-manager shim.
node = Path(subprocess.check_output(['node', '-p', 'process.execPath'], text=True).strip()).resolve(strict=True)
package = fixture / 'node_modules/@anthropic-ai/sdk/index.mjs'
probe = f'''import Anthropic from {json.dumps(package.resolve(strict=True).as_uri())};
const sdk = new Anthropic({{apiKey:'fixture-not-a-key',baseURL:'http://127.0.0.1:1',maxRetries:0}});
if (typeof sdk.messages.stream !== 'function') process.exitCode = 1;
'''
manifest = json.loads((kit / 'rivect.manifest.json').read_bytes())
roles = {1: ('executable', 'helper'), 2: ('executable', 'helper', 'ui', 'library')}[manifest['schema_version']]
files = [f for f in kit.rglob('*') if f.is_file() and not f.is_symlink()]
assert {f.relative_to(kit).as_posix() for f in files} == {'rivect.manifest.json', *(manifest[r]['name'] for r in roles)}
modules = [p for p in (fixture / 'node_modules').rglob('*') if p.is_file() and not p.is_symlink()]
print(json.dumps({'kit_bytes': sum(p.stat().st_size for p in files), 'kit_files': len(files),
                  'kit_manifest_sha256': hashlib.sha256((kit / 'rivect.manifest.json').read_bytes()).hexdigest(),
                  'runtime_bytes': node.stat().st_size, 'modules_bytes': sum(p.stat().st_size for p in modules),
                  'modules_files': len(modules)}))
with TemporaryDirectory() as home:
    for label, command in [('installed_cli_version', [kit / 'rivect', '--version']),
                           ('node_start', [node, '-e', '']),
                           ('sdk_construct', [node, '--input-type=module', '-e', probe])]:
        samples = []
        for _ in range(20):
            start = perf_counter_ns()
            subprocess.run(command, env={'HOME': home, 'TMPDIR': home, 'PATH': os.defpath},
                           cwd=home, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           check=True, timeout=10)
            samples.append((perf_counter_ns() - start) / 1_000_000)
        print(json.dumps({'probe': label, 'n': len(samples), 'p50_ms': statistics.median(samples),
                          'p95_ms': sorted(samples)[18]}))
