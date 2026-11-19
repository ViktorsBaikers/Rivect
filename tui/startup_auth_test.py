"""Installed startup renders local facts without initializing a fresh home or calling a provider."""
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import termios
import time

from installed_test import painted_text


def shows_project(screen, expected):
    rows = screen.splitlines()
    for i, row in enumerate(rows):
        _, label, path = row.partition(b'Project:')
        if label:
            path = path.strip(b' ')
            if path == expected or (i + 1 < len(rows) and path + rows[i + 1].strip(b' ') == expected):
                return True
    return False


def expect(fd, history, project, *markers):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
        part = os.read(fd, 65536)
        if not part:
            break
        history.extend(part)
        if b'\x1b[?2026l' in part:
            screen = painted_text(fd, history)
            if shows_project(screen, project) and all(marker in screen for marker in markers):
                return screen
    raise AssertionError(f'missing project {project!r} or {markers!r} on startup screen: {painted_text(fd, history)!r}')


binary = Path(sys.argv[1]).resolve(strict=True)
with tempfile.TemporaryDirectory(dir='/tmp', prefix='riv-auth-') as work:
    home = Path(work).resolve()
    project = home / 'project'
    project.mkdir()
    alias = home / 'alias'
    alias.symlink_to(project, target_is_directory=True)
    env = {'HOME':str(home), 'TMPDIR':str(home), 'PATH':'/usr/bin:/bin', 'TERM':'xterm-256color'}
    for height, width in ((24,80),(9,48)):
        master, slave = os.openpty()
        try:
            termios.tcsetwinsize(slave,(height,width))
            with subprocess.Popen([binary],cwd=alias,env=env,stdin=slave,stdout=slave,stderr=slave) as client:
                try:
                    screen = expect(master,bytearray(),str(project).encode(),b'Run /login',b'not connected',b'Message')
                    assert b'/alias' not in screen
                    assert not (home / '.rivect').exists()
                finally:
                    if client.poll() is None:
                        client.kill()
        finally:
            os.close(master)
            os.close(slave)
