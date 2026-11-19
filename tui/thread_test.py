"""Exercise activity navigation without replacing the draft editor."""
import fcntl
import os
import signal
from pathlib import Path
import sqlite3
import struct
import sys
import termios
import unittest

from installed_test import chat_terminal, wait_text


class ThreadTest(unittest.TestCase):
    def test_command_completion_does_not_submit(self):
        with chat_terminal(binary, 'loopback', '') as (master, database, _):
            os.write(master, b'/ne')
            wait_text(master, b'/ne')
            os.write(master, b'\t')
            # Only the suffix changes; Enter below proves the whole command.
            wait_text(master, b'w')
            if database.exists():
                with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM sessions').fetchone(), (0,))
            os.write(master, b'\r')
            wait_text(master, b'New conversation:')

    def test_detail_resize_and_pasted_draft(self):
        with chat_terminal(binary, 'loopback', '') as (master, database, child):
            os.write(master, b'first turn\r')
            wait_text(master, b'no permitted action; waiting for a decision')
            os.write(master, b'\x1b[200~draft line one\ndraft line two\x1b[201~')
            wait_text(master, b'draft line two')
            os.write(master, b'\t')
            # Detail alone exposes the full owner ID; its title is painted as separate changed cells.
            with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                task_id, = db.execute('SELECT task_id FROM tasks').fetchone()
            wait_text(master, task_id.encode())
            os.write(master, b'\x1b[200~not in draft\x1b[201~')
            wait_text(master, b'Close task details before pasting.')
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 16, 42, 0, 0))
            os.kill(child.pid, signal.SIGWINCH)
            os.write(master, b'\x1b')
            wait_text(master, b'Message')
            os.write(master, b'\r')
            wait_text(master, b'no permitted action;')
            with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                self.assertEqual(db.execute('SELECT goal_bytes FROM tasks ORDER BY rowid').fetchall(),
                                 [(b'first turn',), (b'draft line one\ndraft line two',)])


if __name__ == '__main__':
    binary = Path(sys.argv.pop(1)).resolve(strict=True)
    unittest.main()
