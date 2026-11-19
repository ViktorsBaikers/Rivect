"""Offline TS/TSX definition trial; no downloads, build, or user checkout indexed."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import statistics
import subprocess
import tempfile
import time
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests/fixtures/semantic-trial'
MODULES = ROOT / 'tui/node_modules'
MODEL, APP = 'model.ts', 'app.tsx'
# use line, UTF-16 column, spelling, target (file, line, start, end-exclusive).
# Labels are independent of both engines. No oracle qualifier is sent to Rivect.
CASES = [
    (3, 22, 'tint', (MODEL, 0, 16, 21)),
    (4, 36, 'mark', (MODEL, 2, 13, 17)),
    (5, 25, 'mark', (MODEL, 5, 2, 6)),
    (6, 22, 'Badge', (MODEL, 7, 16, 21)),
    (8, 17, 'local', (APP, 7, 6, 11)),
]


def ms(start):
    return round((time.monotonic() - start) * 1000, 3)


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def kit_info(kit):
    manifest = json.loads((kit / 'rivect.manifest.json').read_bytes())
    for role in ('executable', 'helper'):
        entry = manifest[role]
        assert file_hash(kit / entry['name']) == entry['sha256'], role
    return {'build': manifest['build'], 'files': sorted(p.name for p in kit.iterdir()),
            'manifest_sha256': file_hash(kit / 'rivect.manifest.json')}


def native(root, home, kit, version):
    def query(name, op, document=None):
        req = {'protocol': 1, 'crate_version': version, 'answer_cap': 1024**2, 'deadline_ms': 5000,
               'query': {'kind': 'symbol', 'root': str(root), 'ignore': 'respect', 'limit': 128,
                         'symbol_op': op, 'pattern': name, 'document': document}}
        child = subprocess.run([kit / 'rivect-sandbox-helper', 'launch', '--memory-budget',
                                str(512 * 1024**2), '--', kit / 'rivect', '--index-worker'],
                               env={'HOME': str(home)}, cwd=root, input=json.dumps(req),
                               text=True, capture_output=True, check=True, timeout=10)
        return json.loads(child.stdout)['body']

    def rows(name, op, document=None):
        reply = query(name, op, document)
        assert reply['outcome'] == 'answer', reply
        return [row['kind'] for row in reply['result']['matches']]

    def span(row):
        assert row['encoding'] == 'utf-8'
        path = file_path(row['uri'], root)
        lines = (root / path).read_bytes().splitlines()
        r = row['range']
        line = r['start']['line']
        assert line == r['end']['line']
        def col(pos):
            return len(lines[line][:r[pos]['character']].decode().encode('utf-16-le')) // 2
        return (path, line, col('start'), col('end'))

    observations = []
    pin = {'path': APP, 'encoding': 'utf-8'}
    for line, col, name, expected in CASES:
        start = time.monotonic()
        candidates = [span(row) for row in rows(name, 'definition')]
        refs = [row for row in rows(name, 'references', pin)
                if span(row) == (APP, line, col, col + len(name))]
        bound = len(refs) == 1 and refs[0]['resolved']
        observations.append({'candidates': candidates, 'use_bound': bound,
                             'exact': bound and candidates == [expected], 'two_workers_ms': ms(start)})
    # Native versions pin saved bytes, unlike the LSP unsaved overlay below.
    path = root / APP
    original = path.read_text(encoding='utf8')
    old = rows('local', 'references', pin)[0]['version']
    path.write_text(original.replace('ink.mark()', 'pen.mark()'), encoding='utf8')
    try:
        stale = query('local', 'references', {**pin, 'version': old})
        assert stale['outcome'] == 'failed' and stale['tag'] == 'stale_document_version', stale
        fresh = rows('local', 'references', pin)[0]['version']
        assert old != fresh and rows('local', 'references', {**pin, 'version': fresh})
    finally:
        path.write_text(original, encoding='utf8')
    return {'sites': observations, 'exact': sum(o['exact'] for o in observations),
            'old_pin': stale['tag'], 'new_pin': 'served'}


def file_path(uri, root):
    u = urlsplit(uri)
    assert u.scheme == 'file' and not u.netloc, uri
    return str(Path(unquote(u.path)).resolve().relative_to(root))


def locations(reply, root):
    found = reply['result'] or []
    if isinstance(found, dict):
        found = [found]
    out = []
    for loc in found:
        r = loc['range'] if 'range' in loc else loc['targetSelectionRange']
        assert r['start']['line'] == r['end']['line'], r
        out.append((file_path(loc.get('uri') or loc['targetUri'], root), r['start']['line'],
                    r['start']['character'], r['end']['character']))
    return out


async def session(exe, root, home):
    log = home / 'lsp.stderr'
    with log.open('wb') as err:
        start = time.monotonic()
        proc = await asyncio.create_subprocess_exec(exe, '--lsp', '--stdio', cwd=root, stderr=err,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                env={'HOME': str(home), 'TMPDIR': str(home), 'PATH': '', 'GOTELEMETRY': 'off'},
                start_new_session=True)
    inp, out = proc.stdin, proc.stdout
    assert inp is not None and out is not None
    next_id = 0

    def send(message):
        body = json.dumps({'jsonrpc': '2.0', **message}).encode()
        inp.write(f'Content-Length: {len(body)}\r\n\r\n'.encode() + body)

    def notify(method, params=None):
        send({'method': method} if params is None else {'method': method, 'params': params})

    def request(method, params=None):
        nonlocal next_id
        next_id += 1
        message = {'id': next_id, 'method': method}
        if params is not None:
            message['params'] = params
        send(message)
        return next_id

    async def response(expect):
        while True:
            headers = (await out.readuntil(b'\r\n\r\n')).decode().splitlines()
            fields = {k.lower(): v for k, v in (h.split(':', 1) for h in headers if h)}
            n = int(fields['content-length'])
            assert 0 < n <= 4 * 1024**2, n
            msg = json.loads(await out.readexactly(n))
            if 'method' in msg:
                if 'id' in msg:
                    send({'id': msg['id'], 'error': {'code': -32601, 'message': 'method not supported'}})
            else:
                assert msg['id'] == expect, msg
                return msg

    td = {'uri': (root / APP).as_uri()}
    def definition(case):
        return request('textDocument/definition', {'textDocument': td,
                       'position': {'line': case[0], 'character': case[1]}})

    try:
        async with asyncio.timeout(20):
            init = await response(request('initialize', {'processId': os.getpid(), 'rootUri': root.as_uri(),
                'workspaceFolders': [{'name': 'trial', 'uri': root.as_uri()}],
                'capabilities': {'general': {'positionEncodings': ['utf-16']}}}))
            enc = init['result']['capabilities'].get('positionEncoding', 'utf-16')
            assert enc == 'utf-16', enc
            initialized = ms(start)
            notify('initialized', {})
            text = (root / APP).read_text(encoding='utf8')
            current = 1
            notify('textDocument/didOpen', {'textDocument': {**td, 'version': current,
                                            'languageId': 'typescriptreact', 'text': text}})
            answers = [locations(await response(definition(CASES[0])), root)]
            first = ms(start)
            warm = []
            for case in CASES[1:]:
                answers.append(locations(await response(definition(case)), root))
            for _ in range(12):
                t = time.monotonic()
                hits = locations(await response(definition(CASES[1])), root)
                warm.append(ms(t))
                assert hits == answers[1], hits
            rss = int(subprocess.check_output(['/bin/ps', '-o', 'rss=', '-p', str(proc.pid)],
                                              env={}, timeout=2))
            pending_version, pending = current, definition(CASES[1])
            current += 1
            notify('textDocument/didChange', {'textDocument': {**td, 'version': current},
                   'contentChanges': [{'text': text.replace('ink.mark()', 'pen.mark()')}]})
            old_reply = await response(pending)
            # A definition response has no document version. Fence the pending ID before display.
            visible = locations(old_reply, root) if pending_version == current else None
            old_payload = old_reply['error']['code'] if 'error' in old_reply else locations(old_reply, root)
            new = locations(await response(definition(CASES[1])), root)
            assert visible is None and new == [CASES[2][3]], (visible, new)
            t = time.monotonic()
            req = request('textDocument/references', {'textDocument': td,
                          'position': {'line': 5, 'character': 25}, 'context': {'includeDeclaration': True}})
            notify('$/cancelRequest', {'id': req})
            cancelled = await response(req)
            cancel_ms = ms(t)
            cancel = cancelled['error']['code'] if 'error' in cancelled else 'completed_before_cancel'
            assert cancel in (-32800, 'completed_before_cancel'), cancelled
            t = time.monotonic()
            shutdown = await response(request('shutdown'))
            assert 'result' in shutdown and shutdown['result'] is None, shutdown
            notify('exit')
            await inp.drain()
            rc = await proc.wait()
            teardown = ms(t)
            with log.open('rb') as err:
                diagnostic = err.read(2048).decode('utf8', errors='replace').strip()
            try:
                os.killpg(proc.pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError('server process group survived exit')
            return {'answers': answers, 'exact': sum(a == [c[3]] for a, c in zip(answers, CASES)),
                    'encoding': enc, 'v1_reply_after_edit': old_payload, 'v1_visible': visible,
                    'v2_target': new, 'initialize_ms': initialized, 'first_answer_ms': first,
                    'warm_ms': warm, 'warm_median_ms': statistics.median(warm), 'server_rss_kib': rss,
                    'cancel': cancel, 'cancel_reply_ms': cancel_ms, 'shutdown_to_reap_ms': teardown,
                    'exit_code': rc, 'stderr_prefix': diagnostic, 'group_gone': True}
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await proc.wait()
        inp.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kit', type=Path, default=ROOT / 'tui/build/core',
                        help='existing Rivect release kit containing the native worker and manifest')
    args = parser.parse_args()
    kit = args.kit.resolve(strict=True)
    inventory = kit_info(kit)
    arch = {'aarch64': 'arm64', 'x86_64': 'x64'}.get(platform.machine(), platform.machine())
    pkg = MODULES / '@typescript' / f'typescript-{platform.system().lower()}-{arch}'
    for package in (MODULES / 'typescript', pkg):
        assert json.loads((package / 'package.json').read_bytes())['version'] == '7.0.2', package.name
    exe = pkg / 'lib/tsc'
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp).resolve()
        root = Path(shutil.copytree(CORPUS, home / 'project'))
        report = {'platform': platform.platform(), 'typescript': '7.0.2', 'server_sha256': file_hash(exe),
                  'server_bytes': exe.stat().st_size, 'platform_package_bytes': sum(
                      p.stat().st_size for p in pkg.rglob('*') if p.is_file()), 'kit': inventory,
                  'corpus_sha256': {p.name: file_hash(p) for p in sorted(root.iterdir())},
                  'native': native(root, home, kit, inventory['build'].split()[1]),
                  'lsp': [asyncio.run(session(exe, root, home)) for _ in range(3)]}
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
