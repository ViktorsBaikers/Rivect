"""Reviewing a real pending question, pasting or cancelling must never record an answer."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import sqlite3
import struct
import subprocess
import sys
import tempfile
import termios
import time

from installed_test import wait_terminal_exit
from screen_reader import terminal_reader


def controlling_terminal():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def rpc(child, method, **params):
    sender, reader = child.stdin, child.stdout
    assert sender is not None and reader is not None
    sender.write(json.dumps({'jsonrpc':'2.0', 'id':1, 'method':method,
                             'params':{'schema_version':1, **params}}) + '\n')
    sender.flush()
    if not select.select([reader], [], [], 5)[0]:
        child.kill()
        raise AssertionError(f'private owner timed out on {method}')
    return json.loads(reader.readline())


def seed(core, home, env):
    with subprocess.Popen([core, '--ui-wire-v1'], cwd=home, env=env, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, text=True) as child:
        session = rpc(child, 'session.open', bootstrap_id='decision-fixture')['result']['session_id']
        task = rpc(child, 'task.submit', session_id=session, command_id='start-decision', kind='create',
                   goal='inspect only', contract={'criteria':[], 'constraints':[]}, first_question=True)['result']['task_id']
        assert child.stdin is not None
        child.stdin.close()
        assert child.wait(timeout=5) == 0
        return session, task


def refuse_unowned_tty(core, home, env, session, task, slave):
    with subprocess.Popen([core, '--ui-terminal-wire-v1'], cwd=home, env=env, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=slave, start_new_session=True, text=True) as child:
        assert rpc(child, 'session.attach', session_id=session, bootstrap_id='unowned-tty')['result']['session_id'] == session
        question = rpc(child, 'operator.question', session_id=session, task_id=task)['result']['question']
        reply = rpc(child, 'operator.answer', session_id=session, task_id=task, question_id=question['question_id'],
                    expected_intent_revision=question['intent_revision'], question_revision=question['question_revision'],
                    selection={'kind':'option', 'option_id':question['recommended_option_id']})
        assert reply['error']['code'] == 'denied'
        assert child.stdin is not None
        child.stdin.close()
        assert child.wait(timeout=5) == 0


binary = Path(sys.argv[1]).resolve(strict=True)
with tempfile.TemporaryDirectory() as work:
    home = Path(work)
    root = home / '.rivect'
    root.mkdir(mode=0o700)
    verdict = root / 'image-read-policy.json'
    verdict.write_text('{"decision":"allow"}')
    image = home / 'figure.png'
    original = bytes.fromhex('89504e470d0a1a0a') + b'example'
    image.write_bytes(original)
    alternate = home / 'alternate.png'
    alternate.write_bytes(original)
    (root / 'config.toml').write_text('config_version = 1\n[connections.loopback]\nkind = "local"\nendpoint = ""\n'
        '[models.defaults]\nmodel = { mode = "fixed", connection = "loopback", model_id = "offline" }\n'
        'effort = { mode = "fixed", value = "medium" }\nfallback = { mode = "off" }\n'
        f'[hooks."effect.request@project"]\ncommand = "/bin/cat"\nargs = [{json.dumps(str(verdict))}]\n')
    env = {'TERM':'xterm-256color', 'PATH':'/usr/bin:/bin', 'HOME':work, 'TMPDIR':work}
    session, task = seed(binary, home, env)
    database = root / 'runtime/rivect.db'
    master, slave = pty.openpty()
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 36, 120, 0, 0))
        refuse_unowned_tty(binary, home, env, session, task, slave)
        with (
            subprocess.Popen([binary], env=env, cwd=home, stdin=slave, stdout=slave, stderr=slave,
                             preexec_fn=controlling_terminal) as client,
            sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db,
        ):
            wait_text = terminal_reader()
            def counts():
                return db.execute('SELECT (SELECT count(*) FROM answer_attempts), '
                                  '(SELECT count(*) FROM usage_settlements)').fetchone()
            try:
                wait_text(master, b'Message')
                os.write(master, f'/resume {session}\r\r'.encode())  # Type-ahead must not select the arriving card.
                wait_text(master, b'Begin the first step')
                os.write(master, b'\x1b[200~yes\n\x1b[201~')
                wait_text(master, b'Paste refused')
                assert counts() == (0, 0)
                time.sleep(.25)  # Cross the product's 200ms first-paint consent floor.
                os.write(master, b'\t')
                wait_text(master, b'focus 2/2')
                time.sleep(.25)  # The newly focused row must itself remain visible for 200ms.
                os.write(master, b'\r')
                wait_text(master, b'Enter newline')
                os.write(master, b'\x1b[200~first line\nsecond line\x1b[201~')
                wait_text(master, b'second line')
                os.write(master, b'\x1b')
                wait_text(master, b'Enter selects')
                assert counts() == (0, 0)
                os.write(master, b'k')
                wait_text(master, b'focus 1/2')
                time.sleep(.25)
                os.write(master, b'\r')
                wait_text(master, b'press Enter to cancel:')
                assert counts() == (0, 0)
                os.write(master, b'\r')
                wait_text(master, b'Check /decision')
                assert counts() == (0, 0)
                os.write(master, b'/image figure.png\r')
                wait_text(master, b'image png 15 bytes')
                image.write_bytes(original[:-1] + b'2')
                os.write(master, b'/decision\r')
                wait_text(master, b'Begin the first step')
                time.sleep(.25)
                os.write(master, b'\r')
                refused = wait_text(master, b'Check /decision')
                assert b'press Enter to cancel:' not in refused and counts() == (0, 0)
                for reason in ('content', 'inode', 'deny', 'redirect'):
                    image.write_bytes(original)
                    verdict.write_text('{"decision":"allow"}')
                    os.write(master, b'/image figure.png\r')
                    wait_text(master, b'image png 15 bytes')
                    os.write(master, b'/decision\r')
                    wait_text(master, b'Begin the first step')
                    time.sleep(.25)
                    os.write(master, b'\r')
                    witness = wait_text(master, b'press Enter to cancel:')
                    assert hashlib.sha256(original).hexdigest().encode() in witness
                    challenge = re.search(rb'Type ([0-9A-F]{6}) to confirm', witness)
                    assert challenge
                    if reason == 'content':
                        image.write_bytes(original[:-1] + b'2')
                    elif reason == 'inode':
                        other = home / 'updated.png'
                        other.write_bytes(original)
                        other.replace(image)
                    elif reason == 'deny':
                        verdict.write_text('{"decision":"deny"}')
                    else:
                        verdict.write_text(json.dumps({'decision':'allow','args':{'path':str(alternate)}}))
                    os.write(master, challenge[1] + b'\r')
                    wait_text(master, b'Check /decision')
                    assert db.execute("SELECT count(*) FROM answer_attempts WHERE outcome='applied'").fetchone() == (0,), reason
                    assert counts()[1] == 0, reason
                verdict.write_text('{"decision":"allow"}')
                os.write(master, b'/image figure.png\r')
                wait_text(master, b'image png 15 bytes')
                os.write(master, b'/decision\r')
                wait_text(master, b'Begin the first step')
                time.sleep(.25)
                os.write(master, b'\r')
                witness = wait_text(master, b'press Enter to cancel:')
                assert hashlib.sha256(original).hexdigest().encode() in witness
                assert counts()[1] == 0
                match = re.search(rb'Type ([0-9A-F]{6}) to confirm', witness)
                assert match, 'missing independent terminal witness'
                os.write(master, match[1] + b'\r')
                deadline = time.monotonic() + 5
                while db.execute("SELECT count(*) FROM answer_attempts WHERE outcome='applied'").fetchone() != (1,):
                    if time.monotonic() >= deadline:
                        raise AssertionError('witnessed answer did not reach the owner')
                    time.sleep(.02)
                wait_text(master, b'\x1b[?2026l')  # The next real question can cover the receipt.
                os.write(master, b'\x03')
                assert wait_terminal_exit(master, client) in (0, 130)
            finally:
                if client.poll() is None:
                    client.kill()
    finally:
        os.close(master)
        os.close(slave)
