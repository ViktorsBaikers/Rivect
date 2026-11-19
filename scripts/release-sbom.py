#!/usr/bin/env python3
"""Emit the CycloneDX sidecar from this build's compiler receipts."""
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import quote


def inventory(bundle, artifacts, metadata, ui):
    manifest_path = bundle / 'rivect.manifest.json'
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    if manifest['schema_version'] != 2 or any(ui[k] != manifest[k]['sha256'] for k in ('ui', 'library')):
        raise ValueError('UI build inventory does not match staged release')
    components = {}

    def package(ecosystem, name, version, license=None):
        ref = f'pkg:{ecosystem}/{quote(name, safe="/")}@{quote(version, safe="")}'
        item = {'type': 'library', 'name': name, 'version': version, 'purl': ref, 'bom-ref': ref}
        if license:
            item['licenses'] = [{'expression': license}]
        components[ref] = item

    built = {row['package_id'] for row in map(json.loads, artifacts) if row['reason'] == 'compiler-artifact'}
    by_id = {p['id']: p for p in metadata['packages']}
    if not built:
        raise ValueError('empty Cargo build inventory')
    for key in built:
        p = by_id[key]
        # Cargo historically accepted slash as an OR between SPDX identifiers.
        license = ' OR '.join(s.strip() for s in p['license'].split('/')) if p['license'] else None
        package('cargo', p['name'], p['version'], license)
    for p in ui['packages']:
        package('npm', p['name'], p['version'], p.get('license'))
    package('generic', 'bun', ui['bun'])
    hashes = {manifest_path.name: hashlib.sha256(raw).hexdigest()}
    hashes.update({manifest[k]['name']: manifest[k]['sha256'] for k in ('executable', 'helper', 'ui', 'library')})
    for name, sha in hashes.items():
        ref = 'file:' + name
        components[ref] = {'type': 'file', 'name': name, 'bom-ref': ref,
                           'hashes': [{'alg': 'SHA-256', 'content': sha}]}
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': {'type': 'application', 'name': 'Rivect', 'version': manifest['build']}},
            'components': [components[key] for key in sorted(components)]}


if __name__ == '__main__':
    stage, cargo_log, metadata, ui = map(Path, sys.argv[1:])
    with cargo_log.open() as artifacts:
        json.dump(inventory(stage, artifacts, json.loads(metadata.read_bytes()), json.loads(ui.read_bytes())),
                  sys.stdout, ensure_ascii=False, indent=2)
    print()
