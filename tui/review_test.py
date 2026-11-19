"""All inherited review IDs must paint their seeded facts and restore the terminal."""
import fcntl
import os
from pathlib import Path
import pty
import struct
import subprocess
import sys
import tempfile
import termios

from installed_test import wait_text, wait_terminal_exit


states = {
    'start-no-connection': 'not connected', 'no-project-index': 'No project or index',
    'ready-for-input': 'draft a change', 'streaming-long-output': 'streaming marker line',
    'parallel-work': 'task task-1: running', 'awaiting-decision': 'awaiting decision',
    'awaiting-permission': 'awaiting permission', 'fullscreen-inline': 'draft survives',
    'pause-cancel': 'cancelled', 'quota-fallback': 'quota exhausted',
    'error-offline-partial': 'connection lost', 'success': 'completed',
    'settings-default-modified-locked-pending': 'profile = next (pending)',
    'settings-invalid-conflict': 'config.set refused: conflict', 'resume-compaction-upgrade': 'Context compacted:',
    'rewind-preview-conflict-partial': 'no rollback applied', 'big-list-narrow-window': 'task task-8:',
    'workflow-off': 'workflow: off', 'non-tty': 'structured events on stdout',
}

binary = Path(sys.argv[1]).resolve(strict=True)
with tempfile.TemporaryDirectory() as home:
    env = {'HOME': home, 'TMPDIR': home, 'TERM': 'xterm-256color', 'PATH': '/usr/bin:/bin'}
    cases = [(state, marker, 52, 160) for state, marker in states.items()]
    cases += [('parallel-work', 'Review · Esc closes', 17, 48), ('parallel-work', 'task task-1: running', 17, 48)]
    cases.append(('big-list-narrow-window', 'task task-1: running', 9, 48))
    for state, marker, height, width in cases:
        master, slave = pty.openpty()
        try:
            settings = termios.tcgetattr(slave)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', height, width, 0, 0))
            with subprocess.Popen([binary, '--ui-review', state], cwd=home, env=env,
                                  stdin=slave, stdout=slave, stderr=slave) as client:
                try:
                    wait_text(master, marker.encode())
                    if height == 9:
                        os.write(master, b'\x1b[6~')
                        wait_text(master, b'task task-8: completed')
                    os.write(master, b'j\t\r\x1b[200~allow once\n\x1b[201~')
                    interrupt = state == 'awaiting-permission'
                    os.write(master, b'\x03' if interrupt else b'\x1b')
                    assert wait_terminal_exit(master, client) == (130 if interrupt else 0), state
                    assert termios.tcgetattr(slave) == settings, state
                finally:
                    if client.poll() is None:
                        client.kill()
        finally:
            os.close(master)
            os.close(slave)
    assert not (Path(home) / '.rivect').exists(), 'review opened runtime state'
