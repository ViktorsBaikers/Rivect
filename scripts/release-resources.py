"""Collect or verify the AC-003 observation for one native release candidate."""
import argparse
import gzip
import hashlib
import json
import math
import os
import platform
import re
import runpy
import stat
import subprocess
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path
from typing import Any

MANIFEST = 'rivect.manifest.json'
IDLE_METRICS = ('launch_to_input_ms', 'input_ms', 'idle_ctrl_c_restore_ms')
PRESSURE_METRICS = ('input_ms', 'cancel_to_peer_eof_ms', 'cancel_to_durable_ms')
WORKLOADS = {'idle': 0, 'history_1': 1, 'history_100': 100}
REPEATS = 20


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    obj = dict(pairs)
    require(len(obj) == len(pairs), 'duplicate json key')
    return obj


def reject_constant(_):
    raise ValueError('nonfinite json number')


def read_json(path):
    return json.loads(path.read_bytes(), object_pairs_hook=unique_object, parse_constant=reject_constant)


def exact_keys(obj, keys, label) -> dict[str, Any]:
    if not isinstance(obj, dict) or obj.keys() != set(keys):
        raise ValueError(f'invalid {label} fields')
    return obj


def identity():
    host = {'Linux': 'linux', 'Darwin': 'macos'}.get(platform.system())
    arch = platform.machine()
    require((host, arch) in {('linux', 'x86_64'), ('macos', 'arm64')}, 'unsupported native release host')
    commit = os.environ.get('GITHUB_SHA')
    run_id = os.environ.get('GITHUB_RUN_ID')
    local = commit is None and run_id is None and os.environ.get('GITHUB_ACTIONS') != 'true'
    require(local or (commit is not None and re.fullmatch(r'[0-9a-f]{40}', commit)
                      and run_id is not None and re.fullmatch(r'[1-9][0-9]*', run_id)),
            'invalid or incomplete github identity')
    return {'schema_version': 1, 'os': host, 'arch': arch, 'commit': commit, 'run_id': run_id}


def digest(stream):
    sha = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        sha.update(chunk)
    return sha.hexdigest()


def file_info(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), 'expected regular candidate file')
    with path.open('rb') as stream:
        return info.st_size, stat.S_IMODE(info.st_mode), digest(stream)


def receipt_path(bundle):
    return bundle.with_name(bundle.name + '.manifest.sha256')


def binding(bundle, archive):
    bound = identity()
    ext = 'so' if bound['os'] == 'linux' else 'dylib'
    components = {'executable': 'rivect', 'helper': 'rivect-sandbox-helper',
                  'ui': 'libexec/rivect-tui', 'library': f'libexec/libopentui.{ext}'}
    names = {MANIFEST, *components.values()}
    libexec = bundle / 'libexec'
    require(not libexec.is_symlink() and libexec.is_dir(), 'invalid installed libexec directory')
    require({p.name for p in bundle.iterdir()} == {MANIFEST, 'rivect', 'rivect-sandbox-helper', 'libexec'}
            and {p.relative_to(bundle).as_posix() for p in libexec.iterdir()} == {components['ui'], components['library']},
            'unexpected installed candidate inventory')
    files = {name: file_info(bundle / name) for name in names}
    candidate = files[MANIFEST][2]
    manifest = read_json(bundle / MANIFEST)
    require(type(manifest) is dict and type(manifest.get('schema_version')) is int
            and manifest['schema_version'] == 2, 'invalid candidate manifest version')
    for key, name in components.items():
        require(manifest.get(key) == {'name': name, 'sha256': files[name][2]}, 'candidate manifest inventory mismatch')
    receipt = receipt_path(bundle)
    receipt_size, _, receipt_sha = file_info(receipt)
    require(receipt_sha == hashlib.sha256((candidate + '\n').encode()).hexdigest(),
            'candidate manifest receipt mismatch')

    info = archive.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size > 0, 'invalid candidate archive file')
    with archive.open('rb') as stream:
        archive_sha = digest(stream)
        stream.seek(0)
        with gzip.GzipFile(fileobj=stream) as payload, tarfile.open(fileobj=payload, mode='r:') as tar:
            seen = set()
            for member in tar:
                name = member.name
                require(name in files and name not in seen and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE),
                        'unexpected archive candidate inventory')
                size, mode, sha = files[name]
                require(member.size == size and member.mode == mode, 'archive candidate metadata mismatch')
                contents = tar.extractfile(member)
                if contents is None:
                    raise ValueError('missing archive candidate content')
                with contents:
                    require(digest(contents) == sha, 'archive candidate content mismatch')
                seen.add(name)
            require(seen == names, 'incomplete archive candidate inventory')
            for padding in iter(lambda: payload.read(1024 * 1024), b''):
                require(not padding.strip(b'\0'), 'unexpected data after archive inventory')
    return {**bound, 'archive_sha256': archive_sha, 'candidate_manifest_sha256': candidate,
            'archive_bytes': info.st_size, 'installed_bytes': sum(row[0] for row in files.values()) + receipt_size}


def nonnegative_number(value):
    return type(value) in (int, float) and value >= 0 and math.isfinite(value)


def summarize(rows, tasks):
    metrics = PRESSURE_METRICS if tasks else IDLE_METRICS
    rss = 'tree_rss_kib' if tasks else 'group_rss_kib'
    keys = (*metrics, rss, 'tasks', 'processes_sampled') if tasks else (*metrics, rss)
    require(type(rows) is list and len(rows) == REPEATS, 'invalid sample count')
    checked = [exact_keys(row, keys, 'sample') for row in rows]
    for row in checked:
        require(all(nonnegative_number(row[key]) for key in metrics), 'invalid latency measurement')
        require(type(row[rss]) is int and row[rss] > 0, 'invalid observed rss')
        if tasks:
            require(type(row['tasks']) is int and row['tasks'] == tasks
                    and type(row['processes_sampled']) is int and row['processes_sampled'] >= 2,
                    'invalid pressure workload or process count')
            require(row['cancel_to_durable_ms'] >= row['cancel_to_peer_eof_ms'], 'invalid pressure event order')
        else:
            require(row['launch_to_input_ms'] >= row['input_ms'], 'invalid idle event order')
    summary = {'max_observed_rss_kib': max(row[rss] for row in checked)}
    for key in metrics:
        ordered = sorted(row[key] for row in checked)
        summary[key] = {f'p{p}': ordered[math.ceil(p * len(rows) / 100) - 1] for p in (50, 95)}
    return summary


def check_summary(actual, expected):
    exact_keys(actual, expected, 'summary')
    for key, value in expected.items():
        if type(value) is dict:
            exact_keys(actual[key], value, 'percentiles')
            require(all(nonnegative_number(actual[key][p]) and actual[key][p] == v for p, v in value.items()),
                    'percentiles do not match raw samples')
        else:
            require(type(actual[key]) is int and actual[key] == value, 'rss maximum does not match raw samples')


def verify(report, bound):
    exact_keys(report, (*bound, 'observations'), 'report')
    require(all(type(report[key]) is type(value) and report[key] == value for key, value in bound.items()),
            'resource report does not match candidate, host or run')
    observations = report['observations']
    exact_keys(observations, WORKLOADS, 'observations')
    for name, tasks in WORKLOADS.items():
        observation = observations[name]
        exact_keys(observation, ('samples', 'summary'), 'observation')
        check_summary(observation['summary'], summarize(observation['samples'], tasks))


def collect(binary):
    scripts = Path(__file__).resolve().parent
    idle = runpy.run_path(str(scripts / 'opentui-baseline.py'))['samples']
    pressure = runpy.run_path(str(scripts / 'opentui-pressure.py'))['sample']
    observations = {}
    for name, tasks in WORKLOADS.items():
        if tasks:
            rows = [pressure(binary, tasks) for _ in range(REPEATS)]
        else:
            rows = [{**dict(zip(IDLE_METRICS, (launch / 1e6, echo / 1e6, restore / 1e6), strict=True)),
                     'group_rss_kib': rss}
                    for launch, echo, restore, rss in idle(binary)]
        observations[name] = {'samples': rows, 'summary': summarize(rows, tasks)}
    return observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('collect', 'verify'))
    for name in ('bundle', 'archive', 'report'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    bundle = args.bundle.resolve(strict=True)
    archive = args.archive.absolute()
    report = args.report.absolute()
    if args.mode == 'verify':
        require(stat.S_ISREG(report.lstat().st_mode), 'expected regular report file')
        verify(read_json(report), binding(bundle, archive))
        return

    require(__debug__, 'resource collection requires enabled assertions')
    destination = report.resolve()
    require(bundle != destination and bundle not in destination.parents
            and destination not in (archive.resolve(), receipt_path(bundle).resolve()),
            'resource report must not overwrite candidate files')
    bound = binding(bundle, archive)
    observations = collect(bundle / 'rivect')
    require(binding(bundle, archive) == bound, 'candidate changed during resource collection')
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=report.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump({**bound, 'observations': observations}, stream, allow_nan=False, indent=2)
            stream.write('\n')
            stream.close()
            temporary.replace(report)
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, AssertionError, EOFError, OSError, OverflowError, RecursionError, RuntimeError,
            subprocess.SubprocessError, tarfile.TarError, zlib.error) as exc:
        print(f'release resources: {exc}', file=sys.stderr)
        sys.exit(1)
