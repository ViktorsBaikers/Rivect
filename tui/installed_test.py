"""Exercise the shipped terminal editor without a global Bun or Node."""
from contextlib import contextmanager
import fcntl
from http.client import parse_headers
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import pty
import select
import shutil
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import termios
from threading import Thread
import time


def painted_text(fd, received):
    rows, cols = termios.tcgetwinsize(fd)
    root = Path(__file__).resolve().parents[1]
    reader = root / os.getenv('CARGO_TARGET_DIR', 'target') / 'debug/examples/pty-screen'
    return subprocess.run([reader, str(rows), str(cols)], input=received, capture_output=True,
                          timeout=2, check=True).stdout


def wait_text(fd, text, prior=b'', timeout=5):
    end = time.monotonic() + timeout
    received = bytearray()
    while text not in received:
        remaining = end - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise AssertionError(f'missing {text!r}; last bytes: {received[-300:]!r}')
        part = os.read(fd, 65536)
        if not part:
            raise EOFError(text)
        received.extend(part)
        if text not in received and b'\x1b' not in text and received.endswith(b'\x1b[?2026l'):
            if text in painted_text(fd, prior + received):
                break
    return received


def wait_terminal_exit(master, child):
    wait_text(master, b'\x1b[?1049l')
    deadline = time.monotonic() + 5
    while child.poll() is None and time.monotonic() < deadline:
        if select.select([master], [], [], .05)[0]:
            os.read(master, 65536)
    return child.wait(timeout=1)


@contextmanager
def chat_terminal(binary, connection, endpoint, *, monochrome=False, before_start=None, kind='local', args=()):
    with tempfile.TemporaryDirectory() as home:
        root = Path(home) / '.rivect'
        root.mkdir(mode=0o700)
        effort = '{ mode = "fixed", value = "medium" }' if connection == 'loopback' else '{ mode = "auto" }'
        model = 'deepseek-chat' if connection == 'deepseek' else 'offline'
        credential = f'credential_ref = "file:rivect/{connection}"\n' if kind == 'api_key' else ''
        (root / 'config.toml').write_text(
            f'config_version = 1\n[connections.{connection}]\nkind = "{kind}"\nendpoint = "{endpoint}"\n'
            f'{credential}[models.defaults]\nmodel = {{ mode = "fixed", connection = "{connection}", model_id = "{model}" }}\n'
            f'effort = {effort}\nfallback = {{ mode = "off" }}\n')
        if before_start is not None:
            before_start(Path(home))
        master, slave = pty.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 100, 0, 0))
            env = {'HOME':home, 'TMPDIR':home, 'PATH':'/usr/bin:/bin', 'TERM':'xterm-256color'}
            if monochrome:
                env['NO_COLOR'] = '1'
            with subprocess.Popen([binary, *args], stdin=slave, stdout=slave, stderr=slave, cwd=home,
                                  env=env) as child:
                try:
                    first = wait_text(master, b'Message')
                    if monochrome:
                        assert b'Agents' in first
                        assert not re.search(rb'\x1b\[(?:[0-9;]*;)?(?:3[0-8]|4[0-8]|9[0-7]|10[0-7])(?:[;:][0-9;:]*)?m', first), 'NO_COLOR drew explicit colors'
                    yield master, root / 'runtime/rivect.db', child
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)
        finally:
            os.close(master)
            os.close(slave)


def check_provider_reply(binary):
    with chat_terminal(binary, 'loopback', '') as (master, database, _):
        os.write(master, b'Explain this change\r')
        wait_text(master, b'no permitted action; waiting for a decision')
        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
            session, = db.execute('SELECT session_id FROM tasks').fetchone()
            os.write(master, b'/clear\r')
            wait_text(master, b'conversation:')
            os.write(master, ('/resume ' + session + '\r').encode())
            wait_text(master, b'no permitted action; waiting for a decision')
            assert db.execute('SELECT count(*) FROM usage_settlements').fetchone() == (1,)


def check_pending_session(binary, interruption):
    with socket.create_server(('127.0.0.1', 0)) as listener:
        listener.settimeout(5)
        endpoint = f'http://127.0.0.1:{listener.getsockname()[1]}/v1'
        with chat_terminal(binary, 'vllm', endpoint) as (master, database, child):
            os.write(master, b'session-A-question\r')
            peer, _ = listener.accept()
            with peer, peer.makefile('rb') as request:
                peer.settimeout(5)
                assert request.readline().startswith(b'POST /v1/chat/completions ')
                headers = parse_headers(request)
                assert b'session-A-question' in request.read(int(headers['Content-Length']))
                with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                    session, = db.execute('SELECT session_id FROM tasks').fetchone()
                    if interruption == 'disconnect':
                        child.kill()
                        child.wait(timeout=5)
                    elif interruption == 'switch':
                        task_id, = db.execute('SELECT task_id FROM tasks').fetchone()
                        os.write(master, b'/clear\r')
                        wait_text(master, ('task ' + task_id + ' is running').encode())
                        assert db.execute('SELECT count(*) FROM sessions').fetchone() == (1,)
                        assert db.execute('SELECT lifecycle FROM tasks').fetchone() == ('running',)
                        os.write(master, b'/cancel\r')
                        wait_text(master, b'cancelled')
                        os.write(master, b'/clear\r')
                        wait_text(master, b'New conversation')
                    else:
                        os.write(master, b'draft-before-cancel')
                        wait_text(master, b'draft-before-cancel')
                        os.write(master, b'\x03')
                        wait_text(master, b'cancelled')
                    assert peer.recv(1) == b'', 'provider transport still connected'
                    if interruption == 'switch':
                        # The upstream can still compute. Its late bytes have no client in B.
                        try:
                            peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nlate-A')
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        os.write(master, ('/resume ' + session + '\r').encode())
                        wait_text(master, b'cancelled')
                    deadline = time.monotonic() + 5
                    while db.execute('SELECT session_id, lifecycle FROM tasks').fetchall() != [(session, 'cancelled')]:
                        if time.monotonic() >= deadline:
                            raise AssertionError(f'{interruption}: core did not settle cancellation')
                        time.sleep(.01)
                    assert not select.select([listener], [], [], .2)[0], 'passive resume caused another POST'


def dismiss_pending(fd):
    wait_text(fd, b'Esc returns')
    time.sleep(.23)  # The real card refuses type-ahead before its first paint is stable.
    os.write(fd, b'\x1b')
    wait_text(fd, b'Message')


def check(binary):
    with tempfile.TemporaryDirectory() as home:
        stale = Path(home) / 'rivect-native-interrupted'
        stale.mkdir(mode=0o700)
        old = stale / 'libopentui'
        old.write_bytes(b'interrupted extraction')
        master, slave = pty.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 32, 100, 0, 0))
            with subprocess.Popen([binary], cwd=home, stdin=slave, stdout=slave, stderr=slave,
                                  env={'TERM':'xterm-256color', 'PATH':'/usr/bin:/bin', 'HOME':home, 'TMPDIR':home,
                                       'OPENTUI_LIB_PATH': str(old)}) as child:
                try:
                    wait_text(master, b'Message')
                    if sys.platform == 'darwin':
                        mapped = subprocess.check_output(['/usr/sbin/lsof', '-Fn', '-p', str(child.pid)], text=True)
                        assert 'n' + str(binary.with_name('libopentui.dylib')) in mapped.splitlines()
                    else:
                        mapped = Path(f'/proc/{child.pid}/maps').read_text().splitlines()
                        assert any(line.endswith(' ' + str(binary.with_name('libopentui.so'))) for line in mapped)
                    def native_leftovers():
                        return [p for p in Path(home).iterdir() if p != stale and p.name.startswith(('.bun-', 'rivect-native-'))]
                    assert not native_leftovers(), f'loaded native file still on disk: {native_leftovers()}'
                    os.write(master, b'/task first-row\r')
                    dismiss_pending(master)
                    db = Path(home) / '.rivect/runtime/rivect.db'
                    deadline = time.monotonic() + 5
                    while not db.is_file() and time.monotonic() < deadline:
                        time.sleep(.01)
                    with sqlite3.connect(f'{db.as_uri()}?mode=ro', uri=True) as store:
                        deadline = time.monotonic() + 5
                        while True:
                            goals = store.execute('SELECT goal_bytes FROM tasks').fetchall()
                            if goals or time.monotonic() >= deadline:
                                break
                            time.sleep(.01)
                    assert goals == [(b'first-row',)], goals
                    os.write(master, b'/clear\r')
                    wait_text(master, b'New conversation')
                    os.write(master, b'/task new-session-goal\r')
                    dismiss_pending(master)
                    deadline = time.monotonic() + 5
                    while True:
                        with sqlite3.connect(f'{db.as_uri()}?mode=ro', uri=True) as store:
                            goals = store.execute('SELECT session_id, goal_bytes FROM tasks ORDER BY rowid').fetchall()
                        if len(goals) == 2 or time.monotonic() >= deadline:
                            break
                        time.sleep(.01)
                    assert [row[1] for row in goals] == [b'first-row', b'new-session-goal']
                    assert goals[0][0] != goals[1][0], 'new task leaked into the previous session'
                    os.write(master, b'/resume\r')
                    wait_text(master, goals[0][0].encode())
                    # Crash this fixture's Rust owner. The terminal process must survive.
                    rows = subprocess.check_output(['ps', '-axo', 'pid=,ppid=,args='], text=True).splitlines()
                    owners = [int(pid) for pid, parent, args in (line.split(None, 2) for line in rows)
                              if int(parent) == child.pid and args.endswith(' --ui-wire-v1')]
                    assert len(owners) == 1, owners
                    os.kill(owners[0], signal.SIGKILL)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        try:
                            os.kill(owners[0], 0)
                        except ProcessLookupError:
                            break
                        time.sleep(.01)
                    else:
                        raise AssertionError('dead owner was not reaped')
                    os.write(master, ('/resume ' + goals[0][0] + '\r').encode())
                    dismiss_pending(master)
                    with sqlite3.connect(f'{db.as_uri()}?mode=ro', uri=True) as store:
                        assert store.execute('SELECT count(*) FROM tasks').fetchone() == (2,)
                        assert store.execute("SELECT count(*) FROM tasks WHERE lifecycle != 'waiting'").fetchone() == (0,)
                    os.write(master, b'\x03')
                    assert wait_terminal_exit(master, child) == 130
                    assert not native_leftovers(), 'native extraction survived normal exit'
                    assert old.read_bytes() == b'interrupted extraction', 'reused or removed another launch’s file'
                finally:
                    if child.poll() is None:
                        child.kill()
        finally:
            os.close(master)
            os.close(slave)


def check_core_affinity(binary):
    with tempfile.TemporaryDirectory() as tmp:
        original = binary.parent.parent
        release = Path(tmp) / 'kit'
        shutil.copytree(original, release)
        shutil.copyfile(str(original) + '.manifest.sha256', str(release) + '.manifest.sha256')
        core = release / 'rivect'
        marker = release / 'unverified-core-ran'
        for damage in ('symlink', 'replaced'):
            core.unlink()
            if damage == 'symlink':
                core.symlink_to(original / 'rivect')
            else:
                core.write_text('#!/bin/sh\ntouch "${0%/*}/unverified-core-ran"\n')
                core.chmod(0o700)
            with chat_terminal(release / 'libexec' / binary.name, 'loopback', '') as (master, database, child):
                os.write(master, b'check binding\r')
                report = wait_text(master, b'installed core unavailable or invalid')
                assert b'\x1b[?1049l' in report and child.wait(timeout=5) == 1
                assert not database.exists(), 'UI launched core from outside its release'
                assert not marker.exists(), 'UI launched replaced core before checking its digest'


def check_renderer_refusal(binary):
    with tempfile.TemporaryDirectory() as home:
        isolated = Path(home) / binary.name
        shutil.copy2(binary, isolated)
        library = isolated.with_name('libopentui.' + ('dylib' if sys.platform == 'darwin' else 'so'))
        original = binary.with_name(library.name)
        for damage in ('missing', 'symlink', 'modified'):
            if damage == 'symlink':
                library.symlink_to(original)
            elif damage == 'modified':
                library.unlink()
                shutil.copyfile(original, library)
                with library.open('r+b') as file:
                    first = file.read(1)[0]
                    file.seek(0)
                    file.write(bytes([first ^ 1]))
            master, slave = pty.openpty()
            try:
                with subprocess.Popen([isolated], stdin=slave, stdout=slave, stderr=slave, cwd=home,
                                      env={'HOME':home, 'TMPDIR':home, 'TERM':'xterm-256color'}) as child:
                    try:
                        wait_text(master, b'installed renderer unavailable or invalid')
                        assert child.wait(timeout=5) == 1
                    finally:
                        if child.poll() is None:
                            child.kill()
            finally:
                os.close(master)
                os.close(slave)


def check_first_step_auto_start(binary):
    class Peer(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            frames = (b'data: {"id":"r","object":"chat.completion.chunk","choices":'
                      b'[{"index":0,"delta":{"content":"AUTO_START_REPLY"},"finish_reason":null}]}\n\n'
                      b'data: [DONE]\n\n')
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(frames)))
            self.end_headers()
            self.wfile.write(frames)

    server = HTTPServer(('127.0.0.1', 0), Peer)
    worker = Thread(target=server.serve_forever)
    worker.start()
    endpoint = f'http://127.0.0.1:{server.server_port}/v1'
    def seed(home):
        runtime = home / '.rivect' / 'runtime'
        runtime.mkdir(mode=0o700)
        (runtime / 'credentials.json').write_text(json.dumps({
            'version': 1, 'entries': {'rivect/deepseek': list(b'sk-local-test-key')}}))
        os.chmod(runtime / 'credentials.json', 0o600)
    try:
        with chat_terminal(binary, 'deepseek', endpoint, kind='api_key',
                           args=('--terminal-client',), before_start=seed) as (master, database, _child):
            os.write(master, b'explain this project\r')
            history = bytearray()
            deadline = time.monotonic() + 10
            applied = 0
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    part = os.read(master, 65536)
                    if not part:
                        break
                    history.extend(part)
                try:
                    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                        applied = db.execute(
                            "select count(*) from answer_attempts where outcome='applied'").fetchone()[0]
                except sqlite3.OperationalError:
                    applied = 0
                if applied and b'AUTO_START_REPLY' in history:
                    break
            screen = painted_text(master, history)
            assert applied == 1, f'the ordinary prompt was not started: {screen!r}'
            assert b'AUTO_START_REPLY' in screen, screen
            for forbidden in (b'Begin the first step', b'to confirm, or press Enter to cancel'):
                assert forbidden not in history and forbidden not in screen, forbidden
    finally:
        server.shutdown()
        worker.join()


def check_api_key_login(binary):
    with chat_terminal(binary, 'loopback', '') as (master, database, _child):
        os.write(master, b'/login\r')
        wait_text(master, b'Sign in to a provider')
        os.write(master, b'deepseek')
        wait_text(master, b'DeepSeek')
        os.write(master, b'\r')
        wait_text(master, b'API key')
        os.write(master, b'sk-local-test-key\r')
        wait_text(master, b'Login complete: deepseek')
        credentials = database.parent / 'credentials.json'
        assert credentials.is_file(), 'the key landed in no local credential file'
        assert stat.S_IMODE(credentials.stat().st_mode) == 0o600, oct(
            credentials.stat().st_mode)
        document = json.loads(credentials.read_text())
        assert document['version'] == 1
        assert bytes(document['entries']['rivect/deepseek']) == b'sk-local-test-key', document


if __name__ == '__main__':
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory() as home:
        result = subprocess.run([binary], stdin=subprocess.DEVNULL, capture_output=True,
                                env={'HOME': home, 'TMPDIR': home, 'PATH': '/usr/bin:/bin'}, timeout=5)
        assert result.returncode == 2 and not result.stdout, (result.returncode, result.stdout[:80])
        assert not list(Path(home).glob('*.dylib')), 'non-terminal invocation loaded native UI'
    check_renderer_refusal(binary)
    check_core_affinity(binary)
    check(binary)
    with chat_terminal(binary, 'loopback', '', monochrome=True) as (master, _, _child):
        os.write(master, 'черновик'.encode())
        wait_text(master, 'черновик'.encode())
    check_provider_reply(binary)
    check_first_step_auto_start(binary)
    check_api_key_login(binary)
    for interruption in ('cancel', 'switch', 'disconnect'):
        check_pending_session(binary, interruption)
