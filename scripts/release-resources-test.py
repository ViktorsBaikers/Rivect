"""Exercise the exact-package resource verifier without running a candidate or opening sockets."""
import copy
import hashlib
import io
import json
import platform
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

VERIFIER = Path(__file__).with_name('release-resources.py').resolve()
MANIFEST = 'rivect.manifest.json'
COMMIT = 'a' * 40
RUN_ID = '12345'


def sha256(contents):
    return hashlib.sha256(contents).hexdigest()


def idle_observation():
    return {
        'samples': [{'launch_to_input_ms': 500_000 + n, 'input_ms': 400_000 + n,
                     'idle_ctrl_c_restore_ms': 300_000 + n, 'group_rss_kib': 1000 + n}
                    for n in reversed(range(20))],
        'summary': {'launch_to_input_ms': {'p50': 500_009, 'p95': 500_018},
                    'input_ms': {'p50': 400_009, 'p95': 400_018},
                    'idle_ctrl_c_restore_ms': {'p50': 300_009, 'p95': 300_018},
                    'max_observed_rss_kib': 1019},
    }


def pressure_observation(tasks):
    return {
        'samples': [{'tasks': tasks, 'input_ms': 200_000 + n / 2,
                     'cancel_to_peer_eof_ms': 700_000 + n, 'cancel_to_durable_ms': 800_000 + n,
                     'tree_rss_kib': 4000 + n, 'processes_sampled': 2} for n in range(20)],
        'summary': {'input_ms': {'p50': 200_004.5, 'p95': 200_009},
                    'cancel_to_peer_eof_ms': {'p50': 700_009, 'p95': 700_018},
                    'cancel_to_durable_ms': {'p50': 800_009, 'p95': 800_018},
                    'max_observed_rss_kib': 4019},
    }


class ReleaseResourcesVerify(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.bundle = root / 'candidate'
        (self.bundle / 'libexec').mkdir(parents=True)
        self.archive = root / 'candidate.tar.gz'
        self.report = root / 'resources.json'
        self.receipt = root / 'candidate.manifest.sha256'
        self.host = {'Darwin': 'macos', 'Linux': 'linux'}[platform.system()]
        ext = 'dylib' if self.host == 'macos' else 'so'
        components = {
            'executable': 'rivect', 'helper': 'rivect-sandbox-helper',
            'ui': 'libexec/rivect-tui', 'library': f'libexec/libopentui.{ext}',
        }
        self.files = {path: f'fixture:{key}\n'.encode() for key, path in components.items()}
        manifest = {'schema_version': 2, 'build': 'fixture build'}
        for key, path in components.items():
            manifest[key] = {'name': path, 'sha256': sha256(self.files[path])}
        self.files[MANIFEST] = json.dumps(manifest).encode() + b'\n'
        self.modes = {name: 0o755 if name in ('rivect', 'rivect-sandbox-helper', 'libexec/rivect-tui') else 0o644
                      for name in self.files}
        for name, contents in self.files.items():
            path = self.bundle / name
            path.write_bytes(contents)
            path.chmod(self.modes[name])
        candidate = sha256(self.files[MANIFEST])
        self.receipt.write_bytes(candidate.encode() + b'\n')
        self.write_tar(self.files.items())
        self.valid = {
            'schema_version': 1, 'os': self.host, 'arch': platform.machine(),
            'commit': COMMIT, 'run_id': RUN_ID, 'archive_sha256': sha256(self.archive.read_bytes()),
            'candidate_manifest_sha256': candidate, 'archive_bytes': self.archive.stat().st_size,
            'installed_bytes': sum(map(len, self.files.values())) + 65,
            'observations': {'idle': idle_observation(), 'history_1': pressure_observation(1),
                             'history_100': pressure_observation(100)},
        }
        self.env = {'GITHUB_ACTIONS': 'true', 'GITHUB_SHA': COMMIT, 'GITHUB_RUN_ID': RUN_ID}

    def write_tar(self, entries, *, mtime=0):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, contents in entries:
                entry = tarfile.TarInfo(name)
                entry.mode = self.modes.get(name, 0o644)
                entry.size = len(contents)
                entry.mtime = mtime
                archive.addfile(entry, io.BytesIO(contents))

    def write_report(self, report):
        self.report.write_text(json.dumps(report), encoding='utf-8')

    def verify(self, *, error=None, env=None):
        run = subprocess.run([sys.executable, '-I', VERIFIER, 'verify', self.bundle, self.archive, self.report],
                             env=self.env if env is None else env, capture_output=True, text=True, timeout=10)
        self.assertEqual(run.stdout, '')
        if error is None:
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stderr, '')
        else:
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertIn(error, run.stderr)
            self.assertNotIn('Traceback', run.stderr)

    def test_accepts_complete_slow_observations_without_performance_threshold(self):
        self.write_report(self.valid)
        self.verify()

    def test_accepts_null_commit_and_run_only_for_local_verification(self):
        self.write_report(dict(self.valid, commit=None, run_id=None))
        self.verify(env={})
        self.verify(error='candidate, host or run')
        self.verify(error='github identity', env={'GITHUB_ACTIONS': 'true'})

    def test_rejects_missing_malformed_and_duplicate_report(self):
        self.verify(error='No such file or directory')
        for contents, error in [('not a report', 'Expecting value'),
                                ('{"schema_version":1,"schema_version":1}', 'duplicate json key'),
                                ('{}', 'invalid report fields')]:
            with self.subTest(contents=contents):
                self.report.write_text(contents, encoding='utf-8')
                self.verify(error=error)

    def test_rejects_wrong_identity_or_sizes(self):
        cases = {
            'schema_version': True, 'os': 'windows', 'arch': 'riscv64', 'commit': 'b' * 40, 'run_id': '12344',
            'archive_sha256': '0' * 64, 'candidate_manifest_sha256': '0' * 64,
            'archive_bytes': self.valid['archive_bytes'] + 1, 'installed_bytes': self.valid['installed_bytes'] - 65,
        }
        for key, wrong in cases.items():
            with self.subTest(field=key):
                self.write_report(dict(self.valid, **{key: wrong}))
                self.verify(error='candidate, host or run')
        self.write_report(self.valid)
        self.verify(error='candidate, host or run', env=dict(self.env, GITHUB_RUN_ID='12346'))

    def test_rejects_sparse_samples_in_every_leg(self):
        for name in self.valid['observations']:
            with self.subTest(workload=name):
                report = copy.deepcopy(self.valid)
                report['observations'][name]['samples'].pop()
                self.write_report(report)
                self.verify(error='invalid sample count')

    def test_rejects_wrong_sample_types_counts_values_and_summary(self):
        for field, wrong, error in [
            ('input_ms', True, 'invalid latency'), ('input_ms', -1, 'invalid latency'),
            ('input_ms', '100', 'invalid latency'), ('input_ms', float('nan'), 'nonfinite'),
            ('input_ms', float('inf'), 'nonfinite'), ('tree_rss_kib', 4000.0, 'invalid observed rss'),
            ('tree_rss_kib', 0, 'invalid observed rss'), ('tasks', 10, 'invalid pressure workload'),
            ('processes_sampled', 1, 'invalid pressure workload'), ('cancel_to_durable_ms', 0, 'event order'),
            ('extra', 1, 'invalid sample fields'),
        ]:
            with self.subTest(field=field, wrong=wrong):
                report = copy.deepcopy(self.valid)
                report['observations']['history_100']['samples'][0][field] = wrong
                self.write_report(report)
                self.verify(error=error)
        report = copy.deepcopy(self.valid)
        report['observations']['idle']['summary']['input_ms']['p95'] -= 1
        self.write_report(report)
        self.verify(error='percentiles do not match')
        report = copy.deepcopy(self.valid)
        report['observations']['idle']['summary']['max_observed_rss_kib'] -= 1
        self.write_report(report)
        self.verify(error='rss maximum does not match')

    def test_rejects_different_archive_bytes_even_with_same_inventory(self):
        self.write_tar(self.files.items(), mtime=42)
        self.write_report(self.valid)
        self.verify(error='candidate, host or run')

    def test_rejects_archive_that_is_not_installed_candidate_even_with_matching_archive_digest(self):
        cases = [
            (list(dict(self.files, **{MANIFEST: self.files[MANIFEST][:-1] + b' '}).items()), 'content mismatch'),
            (list(dict(self.files, rivect=b'x' * len(self.files['rivect'])).items()), 'content mismatch'),
            (list(self.files.items()) + [('rivect', self.files['rivect'])], 'unexpected archive'),
            (list(self.files.items()) + [('../secret', b'never print this')], 'unexpected archive'),
            ([(key, val) for key, val in self.files.items() if key != MANIFEST], 'incomplete archive'),
        ]
        for entries, error in cases:
            with self.subTest(error=error, entries=[name for name, _ in entries]):
                self.write_tar(entries)
                self.write_report(dict(self.valid, archive_sha256=sha256(self.archive.read_bytes()),
                                       archive_bytes=self.archive.stat().st_size))
                self.verify(error=error)

    def test_rejects_corrupt_gzip_footer_with_matching_archive_digest(self):
        original = self.archive.read_bytes()
        corrupt = original[:-8] + bytes([original[-8] ^ 1]) + original[-7:]
        self.archive.write_bytes(corrupt)
        self.write_report(dict(self.valid, archive_sha256=sha256(corrupt)))
        self.verify(error='CRC check failed')

    def test_rejects_modified_installed_inventory_and_receipt(self):
        self.write_report(self.valid)
        executable = self.bundle / 'rivect'
        executable.write_bytes(b'changed bytes')
        self.verify(error='manifest inventory mismatch')
        executable.write_bytes(self.files['rivect'])
        self.receipt.write_bytes(b'0' * 64 + b'\n')
        self.verify(error='manifest receipt mismatch')


if __name__ == '__main__':
    unittest.main()
