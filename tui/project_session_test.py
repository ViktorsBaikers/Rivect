"""First use reattaches only this project's last conversation, without replaying work."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve(strict=True)
with tempfile.TemporaryDirectory() as tmp:
    home = Path(tmp)
    def project(directory, fresh=False):
        directory.mkdir(exist_ok=True)
        with subprocess.Popen([binary, '--ui-wire-v1'], cwd=directory, env={'HOME': tmp, 'PATH': os.defpath},
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as core:
            sender, reader = core.stdin, core.stdout
            assert sender is not None and reader is not None
            def call(method, **params):
                req = dict(jsonrpc='2.0', id=1, method=method, params=dict(schema_version=1, **params))
                sender.write(json.dumps(req) + '\n'); sender.flush()
                reply = json.loads(reader.readline())
                assert 'result' in reply, reply
                return reply['result']
            session = call('session.project')['session_id']
            if fresh:
                session = call('command.execute', session_id=session, command={'kind': 'session.new'})['session_id']
            sender.close()
            assert core.wait(timeout=5) == 0
            return session
    a, b = home / 'a', home / 'b'
    initial = project(a)
    assert project(a) == initial
    other = project(b)
    assert other != initial
    next_session = project(a, fresh=True)
    assert next_session != initial and project(a) == next_session and project(b) == other
    with sqlite3.connect((home / '.rivect/runtime/rivect.db').as_uri() + '?mode=ro', uri=True) as db:
        assert db.execute('SELECT count(*) FROM sessions').fetchone() == (3,)
        assert db.execute('SELECT count(*) FROM tasks').fetchone() == (0,)
