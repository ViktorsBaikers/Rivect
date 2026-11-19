"""Installed PTY proof: visible consent geometry and externally moved decision pins."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import select
import sqlite3
import sys
import tempfile
import termios
import time
from installed_test import painted_text
from witness_pty import witness_pty


class Screen:
    def __init__(self, master):
        self.fd = master
        self.history = bytearray()

    def send(self, data):
        os.write(self.fd, data)

    def read(self, seconds):
        if not select.select([self.fd], [], [], max(0, seconds))[0]: return False
        data = os.read(self.fd, 65536)
        if not data: raise EOFError('terminal closed')
        self.history.extend(data)
        return True

    def wait(self, *visible, absent=()):
        deadline = time.monotonic() + 5
        while self.read(deadline - time.monotonic()):
            cells = painted_text(self.fd, self.history)
            if all(t in cells for t in visible) and not any(t in cells for t in absent): return cells
            if time.monotonic() >= deadline: break
        raise AssertionError(f'expected {visible} without {absent}; terminal: {painted_text(self.fd, self.history)!r}')

    def quiet(self, *forbidden, duration=.28):
        start = len(self.history)
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline and self.read(deadline-time.monotonic()): pass
        raw = self.history[start:]
        cells = painted_text(self.fd, self.history) if min(termios.tcgetwinsize(self.fd)) > 1 else b''
        assert not any(t in raw or t in cells for t in forbidden), 'unexpected consent/witness surface'


@contextmanager
def installed(binary):
    with tempfile.TemporaryDirectory() as work:
        root = Path(work) / '.rivect'; root.mkdir(mode=0o700)
        (root/'config.toml').write_text('config_version = 1\n[connections.loopback]\nkind = "local"\nendpoint = ""\n'
            '[models.defaults]\nmodel = { mode = "fixed", connection = "loopback", model_id = "offline" }\n'
            'effort = { mode = "auto" }\nfallback = { mode = "off" }\n')
        env = {'TERM':'xterm-256color','PATH':'/usr/bin:/bin','HOME':work,'TMPDIR':work}
        with witness_pty(binary, work, env, 36, 120) as (master, slave):
            screen = Screen(master); screen.wait(b'Message'); screen.send(b'/task consent sample\r')
            screen.wait(b'Begin the first step', b'focus 1/2')
            with sqlite3.connect(root/'runtime/rivect.db') as db: yield screen, db, slave


def counts(db):
    return db.execute("select (select count(*) from answer_attempts where outcome='applied'), "
                      '(select count(*) from usage_settlements), (select count(*) from attempts)').fetchone()


def witness(screen):
    # A stale challenge may remain in scrollback across suspend/resume. Only
    # actual terminal output from the current witness can authorize this row.
    start = len(screen.history)
    deadline = time.monotonic() + 5
    while screen.read(deadline - time.monotonic()):
        found = re.search(rb'Type ([A-F0-9]{6}) to confirm, or press Enter to cancel:', screen.history[start:])
        if found: return found[1]
        if time.monotonic() >= deadline: break
    raise AssertionError('current witness missing')


def geometry(binary):
    with installed(binary) as (s, db, slave):
        time.sleep(.25)
        for rows, cols in ((24,1),(1,80)):
            termios.tcsetwinsize(slave,(rows,cols)); s.quiet(b'press Enter to cancel:')
            s.send(b'\r'); s.quiet(b'press Enter to cancel:'); assert counts(db) == (0,0,0)
        termios.tcsetwinsize(slave,(36,120)); s.wait(b'Begin the first step', b'1. Begin', b'focus 1/2')
        s.send(b'\r'); s.quiet(b'press Enter to cancel:'); assert counts(db) == (0,0,0)
        s.send(b'\r'); challenge = witness(s); assert counts(db) == (0,0,0)
        s.send(challenge+b'\r'); s.wait(b'decision answer recorded')
        assert counts(db)[0] == 1


def publish_fixture(db, title, new_intent=False):
    # External-change fixture only: replace immutable authoring input, never create answers,
    # witness receipts, attempts, or model results. Product owns every observed transition.
    with db:
        (raw,) = db.execute("select body_json from questions order by rowid desc limit 1").fetchone()
        q = json.loads(raw); old = q['question_id']; q['question_id'] = title
        if new_intent: q['intent_revision'] += 1
        q['prompt'] = title
        db.execute("update questions set state='superseded' where question_id=?",(old,))
        db.execute("insert into questions(question_id,task_id,revision,intent_revision,prompt,body_json,state) values(?,?,?,?,?,?,'pending')",
                   (title,q['task_id'],q['question_revision'],q['intent_revision'],title,json.dumps(q)))
        db.execute('update tasks set revision=revision+1, intent_revision=? where task_id=?',(q['intent_revision'],q['task_id']))


def external(binary):
    with installed(binary) as (s, db, _):
        s.send(b'\x1b'); s.quiet(b'question stays pending')  # Arriving-card type-ahead.
        assert counts(db) == (0,0,0)
        s.send(b'\x1b'); s.wait(b'question stays pending', absent=(b'focus 1/2',)); s.quiet(b'focus 1/2',duration=.55)
        publish_fixture(db,'replacement one',new_intent=True)
        s.wait(b'replacement one', b'focus 1/2'); s.send(b'\r'); s.quiet(b'press Enter to cancel:')
        # A visible card may vanish before the owner publishes its successor.
        with db: db.execute("update questions set state='superseded' where state='pending'")
        s.wait(b'Question changed.', absent=(b'focus 1/2',)); assert counts(db) == (0,0,0)
        publish_fixture(db,'after gap')
        s.wait(b'after gap', b'focus 1/2'); s.send(b'\r'); s.quiet(b'press Enter to cancel:')
        # Same identifier, revised authoring input: the old paint clock grants nothing.
        with db:
            (raw,) = db.execute("select body_json from questions where state='pending'").fetchone()
            revised = json.loads(raw); revised['question_revision'] += 1; revised['prompt'] = 'revised scope'
            db.execute('update questions set revision=?, prompt=?, body_json=? where question_id=?',
                       (revised['question_revision'], revised['prompt'], json.dumps(revised), revised['question_id']))
        s.wait(b'revised scope', b'focus 1/2'); s.send(b'\r'); s.quiet(b'press Enter to cancel:')
        assert counts(db) == (0,0,0)
        s.send(b'\r'); challenge = witness(s)
        publish_fixture(db,'replacement two'); s.send(challenge+b'\r')
        s.wait(b'replacement two', b'focus 1/2'); assert counts(db) == (0,0,0)
        s.send(b'\r'); s.quiet(b'press Enter to cancel:'); s.send(b'\r'); challenge = witness(s)
        s.send(challenge+b'\r'); s.wait(b'decision answer recorded')
        assert db.execute("select question_id from answer_attempts where outcome='applied'").fetchall() == [('replacement two',)]


if __name__ == '__main__':
    binary = Path(sys.argv[1]).resolve(strict=True)
    for name in sys.argv[2:] or ('geometry', 'external'):
        {'geometry':geometry,'external':external}[name](binary)
