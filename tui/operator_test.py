"""Operator reads in a real terminal must not submit a task or approve a question."""
import os
from pathlib import Path
import sqlite3
import sys

from installed_test import chat_terminal, wait_text


with chat_terminal(Path(sys.argv[1]).resolve(strict=True), 'loopback', '') as (master, database, _):
    for command, marker in [(b'/settings', b'context.auto_compact'), (b'/permissions', b'Permissions:'),
                            (b'/accounting', b'quota'), (b'/login cancel', b'No login is pending')]:
        os.write(master, command + b'\r')
        wait_text(master, marker)
        if command == b'/settings':
            os.write(master, b'\x1b')
            wait_text(master, b'Message')
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
        assert db.execute('SELECT (SELECT count(*) FROM tasks), (SELECT count(*) FROM answer_attempts), '
                          '(SELECT count(*) FROM usage_settlements)').fetchone() == (0, 0, 0)
        os.write(master, b'inspect accounting\r')
        wait_text(master, b'no permitted action; waiting for a decision')
        os.write(master, b'/accounting\r')
        wait_text(master, b'model: offline (fixed pin)')
        assert db.execute('SELECT count(*) FROM usage_settlements').fetchone() == (1,)
