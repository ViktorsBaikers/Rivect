"""Session recovery and live-send ownership through the installed terminal."""
from http.client import parse_headers
import json
import os
from pathlib import Path
import select
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import unittest

from installed_test import chat_terminal, wait_terminal_exit, wait_text


def core_pid(child):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        rows = subprocess.check_output(['ps', '-axo', 'pid=,ppid=,args='], text=True).splitlines()
        for pid, parent, args in (row.split(None, 2) for row in rows):
            if int(parent) == child.pid and args.endswith(' --ui-wire-v1'):
                return int(pid)
        time.sleep(.01)
    raise AssertionError('UI did not start the core')


def wait_reaped(pid):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(.01)
    raise AssertionError('UI core still alive after shutdown')


def disconnect(master, database, child):
    os.write(master, b'original message\r')
    wait_text(master, b'no permitted action; waiting for a decision')
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
        session, = db.execute('SELECT session_id FROM tasks').fetchone()
    pid = core_pid(child)
    os.kill(pid, signal.SIGKILL)
    wait_reaped(pid)
    return session


def saved_running_task(core, home):
    def frame(method, **params):
        return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
                           'params': {'schema_version': 1, **params}}) + '\n'

    def call(*frames):
        result = subprocess.run([core, '--ui-wire-v1'], cwd=home,
                                env={'HOME': str(home), 'TMPDIR': str(home), 'PATH': '/usr/bin:/bin'},
                                input=''.join(frames), capture_output=True, text=True, timeout=5, check=True)
        return [json.loads(line)['result'] for line in result.stdout.splitlines()]

    opened, = call(frame('session.open', bootstrap_id='saved'))
    session = opened['session_id']
    _, created = call(frame('session.attach', session_id=session, bootstrap_id='seed'),
                      frame('task.submit', session_id=session, command_id='saved-task', kind='create',
                            goal='saved running task', contract={'criteria': [], 'constraints': []}))
    assert created['snapshot']['lifecycle'] == 'running', created
    return session


class SessionTest(unittest.TestCase):
    def test_discovery_after_owner_loss(self):
        with chat_terminal(binary, 'loopback', '') as (master, database, child):
            session = disconnect(master, database, child)
            os.write(master, b'/resume\r')
            wait_text(master, session.encode())
            os.write(master, ('/resume ' + session + '\r').encode())
            wait_text(master, b'Resumed session:')
            with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                self.assertEqual(db.execute('SELECT session_id,goal_bytes FROM tasks').fetchall(),
                                 [(session, b'original message')])
                self.assertEqual(db.execute('SELECT count(*) FROM usage_settlements').fetchone(), (1,))

    def test_exit_during_replacement_attach(self):
        with chat_terminal(binary, 'loopback', '') as (master, database, child):
            session = disconnect(master, database, child)
            with sqlite3.connect(database) as gate:
                gate.execute('BEGIN IMMEDIATE')
                os.write(master, ('/resume ' + session + '\r').encode())
                replacement = core_pid(child)
                os.write(master, b'\x03')
                wait_text(master, b'\x1b[?1049l')
                gate.rollback()
            deadline = time.monotonic() + 5
            while child.poll() is None and time.monotonic() < deadline:
                if select.select([master], [], [], .05)[0]:
                    os.read(master, 65536)
            self.assertIn(child.wait(timeout=1), (0, 130))
            wait_reaped(replacement)

    def test_only_local_send_is_watched_or_cancelled(self):
        with socket.create_server(('127.0.0.1', 0)) as listener:
            listener.settimeout(5)
            endpoint = f'http://127.0.0.1:{listener.getsockname()[1]}/v1'
            def seed(home):
                saved_running_task(binary.parent.parent / 'rivect', home)
            with chat_terminal(binary, 'vllm', endpoint, before_start=seed) as (master, database, child):
                with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                    session, = db.execute('SELECT session_id FROM tasks WHERE goal_bytes=?', (b'saved running task',)).fetchone()
                os.write(master, ('/resume ' + session + '\r').encode())
                wait_text(master, b'Resumed session:')
                os.write(master, b'new local message\r')
                peer, _ = listener.accept()
                with peer, peer.makefile('rb') as request:
                    peer.settimeout(5)
                    self.assertTrue(request.readline().startswith(b'POST /v1/chat/completions '))
                    headers = parse_headers(request)
                    self.assertIn(b'new local message', request.read(int(headers['Content-Length'])))
                    body = (b'data: {"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,'
                            b'"delta":{"role":"assistant","content":"Reply to local message"},"finish_reason":"stop"}]}\n\n'
                            b'data: [DONE]\n\n')
                    peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: '
                                 + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
                wait_text(master, b'Reply to local message')
                os.write(master, b'\x03')
                self.assertIn(wait_terminal_exit(master, child), (0, 130))
                with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                    self.assertEqual(db.execute('SELECT lifecycle FROM tasks WHERE goal_bytes=?',
                                                (b'saved running task',)).fetchone(), ('running',))


if __name__ == '__main__':
    binary = Path(sys.argv.pop(1)).resolve(strict=True)
    unittest.main()
