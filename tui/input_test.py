"""Installed keyboard modes: edit literal text and restore terminal on Escape."""
import os
from pathlib import Path
import sqlite3
import sys
import unittest

from installed_test import chat_terminal, wait_terminal_exit, wait_text


class InputTest(unittest.TestCase):
    def test_mouse_paste_and_escape(self):
        with chat_terminal(binary, 'loopback', '') as (master, database, child):
            os.write(master, b'/tui mouse on\r')
            mouse_on = wait_text(master, b'tui: mouse on')
            os.write(master, b'/tui mouse off\r')
            # OpenTUI can repaint only the changed suffix of the notice.
            wait_text(master, b'tui: mouse off', prior=mouse_on)
            os.write(master, b'\x1b[200~/new\x1b[31m\r\x1b[201~')
            wait_text(master, b'Paste contains terminal control characters.')
            os.write(master, b'\x1b[200~A\r\n' + '雪'.encode() + b'\x1b[201~')
            wait_text(master, '雪'.encode())
            self.assertFalse(database.exists(), 'local commands or paste opened the core')
            os.write(master, b'\r')
            wait_text(master, b'no permitted action; waiting for a decision')
            with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                self.assertEqual(db.execute('SELECT goal_bytes FROM tasks').fetchone(), ('A\n雪'.encode(),))
            os.write(master, b'\x1b')
            self.assertEqual(wait_terminal_exit(master, child), 0)


if __name__ == '__main__':
    binary = Path(sys.argv.pop(1)).resolve(strict=True)
    unittest.main()
