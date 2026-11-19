#!/usr/bin/env python3
"""Check the native candidate against its external CycloneDX inventory."""
import hashlib
import json
import platform
import sys
from pathlib import Path


def verify(bundle):
    manifest = bundle / 'rivect.manifest.json'
    assert json.loads(manifest.read_bytes())['schema_version'] == 2
    stamp = Path(str(bundle) + '.manifest.sha256')
    assert stamp.is_file() and not stamp.is_symlink()
    assert stamp.read_bytes() == (hashlib.sha256(manifest.read_bytes()).hexdigest() + '\n').encode()
    bom = json.loads(Path(str(bundle) + '.cdx.json').read_bytes())
    assert (bom['bomFormat'], bom['specVersion']) == ('CycloneDX', '1.6')
    components = bom['components']
    files = {c['name']: c for c in components if c['type'] == 'file'}
    ext = {'darwin': 'dylib', 'linux': 'so'}[sys.platform]
    expected = {'rivect', 'rivect-sandbox-helper', 'libexec/rivect-tui', 'libexec/libopentui.' + ext, manifest.name}
    assert set(files) == expected, (set(files), expected)
    for name, item in files.items():
        with (bundle / name).open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        assert item['hashes'] == [{'alg': 'SHA-256', 'content': digest}], name
    refs = [c['bom-ref'] for c in components]
    assert len(refs) == len(set(refs))
    names = {c['name']: c for c in components if c['type'] != 'file'}
    for name in ('rivect', 'rivect-sandbox-helper', 'tokio', 'rusqlite', 'bun', '@opentui/core', '@opentui/solid', 'solid-js'):
        assert names[name]['version'], name
    assert names['bun']['version'] == '1.4.4'
    assert names['@opentui/core']['version'] == '0.9.2'
    arch = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'x64'}[platform.machine()]
    native = {name for name in names if name.startswith('@opentui/core-')}
    assert native == {f'@opentui/core-{sys.platform}-{arch}'}, native
    assert 'wiremock' not in names and 'typescript' not in names


if __name__ == '__main__':
    verify(Path(sys.argv[1]))
