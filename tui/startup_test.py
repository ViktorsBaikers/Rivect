"""A real terminal restores only its project's tasks before any user input."""
import fcntl
import json
import os
from pathlib import Path
import pty
import sqlite3
import struct
import subprocess
import sys
import tempfile
import termios
import time

from installed_test import painted_text, wait_terminal_exit, wait_text


binary = Path(sys.argv[1]).resolve(strict=True)
with tempfile.TemporaryDirectory() as tmp:
    home = Path(tmp)
    project, other = home / 'workspace-a', home / 'workspace-b'
    project.mkdir()
    other.mkdir()
    env = {'HOME': tmp, 'PATH': '/usr/bin:/bin', 'TMPDIR': tmp, 'TERM': 'xterm-256color'}
    def seed(pending, previous=None):
        with subprocess.Popen([binary, '--ui-wire-v1'], cwd=project, env=env,
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as core:
            def call(method, **params):
                assert core.stdin and core.stdout
                core.stdin.write(json.dumps({'id': 1, 'jsonrpc': '2.0', 'method': method,
                                             'params': {'schema_version': 1, **params}}) + '\n')
                core.stdin.flush()
                return json.loads(core.stdout.readline())['result']
            assert call('runtime.boot')['session_id'] == previous
            session = call('session.project')['session_id']
            task = call('task.submit', kind='create', first_question=pending,
                        goal='pending cobalt decision' if pending else 'previous cobalt inventory',
                        session_id=session, command_id='startup-pending' if pending else 'startup-running',
                        contract={'criteria': [], 'constraints': []})['task_id']
            assert core.stdin
            core.stdin.close()
            assert core.wait(timeout=5) == 0
            return session, task

    database = (home / '.rivect/runtime/rivect.db').as_uri() + '?mode=ro'
    def counts():
        with sqlite3.connect(database, uri=True) as db:
            return db.execute('''SELECT (SELECT count(*) FROM sessions), (SELECT count(*) FROM tasks),
                (SELECT count(*) FROM answer_attempts), (SELECT count(*) FROM attempts),
                (SELECT count(*) FROM usage_settlements)''').fetchone()
    def inspect(cwd, before, task, pending=False):
        master, slave = pty.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 50, 160, 0, 0))
            attrs = termios.tcgetattr(slave)
            with subprocess.Popen([binary], cwd=cwd, env=env, stdin=slave, stdout=slave, stderr=slave) as ui:
                try:
                    goal = b'previous cobalt inventory'
                    if pending:
                        raw = wait_text(master, b'PgUp/PgDn scroll')
                        if not raw.endswith(b'\x1b[?2026l'):
                            raw += wait_text(master, b'\x1b[?2026l')
                        assert b'Begin the first step' in painted_text(master, raw)
                        assert counts() == before, 'restoring the pending question answered it'
                        time.sleep(.25)  # A deliberate dismissal follows the first-paint type-ahead guard.
                        os.write(master, b'\x1b')  # The full-screen modal covers the Thread until dismissed.
                        raw += wait_text(master, goal)
                        assert goal in painted_text(master, raw) and b'pending cobalt decision' in painted_text(master, raw)
                    elif cwd == project:
                        raw = wait_text(master, goal)
                        assert goal in painted_text(master, raw)
                    else:
                        raw = wait_text(master, b'Message')
                        assert goal not in raw and task.encode() not in raw
                    assert counts() == before, 'startup created a session, answered, or executed work'
                    os.write(master, b'\x03')
                    assert wait_terminal_exit(master, ui) == 130
                    assert termios.tcgetattr(slave) == attrs
                finally:
                    if ui.poll() is None:
                        ui.kill()
        finally:
            os.close(master)
            os.close(slave)
    session, task = seed(False)
    before = counts()
    assert before[:3] == (1, 1, 0), before
    inspect(project, before, task)
    inspect(other, before, task)
    assert counts() == before
    same_session, waiting = seed(True, session)
    assert same_session == session
    before = counts()
    assert before[:3] == (1, 2, 0), before
    inspect(project, before, waiting, pending=True)
    assert counts() == before
