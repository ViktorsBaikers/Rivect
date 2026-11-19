"""A real controlling terminal; close its master before reaping the session leader."""
from contextlib import contextmanager
import fcntl
import os
import pty
import subprocess
import termios


@contextmanager
def witness_pty(binary, cwd, env, rows, cols):
    master, slave = pty.openpty()
    child = None
    def acquire():
        os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    try:
        termios.tcsetwinsize(slave, (rows, cols))
        child = subprocess.Popen([binary], cwd=cwd, env=env, stdin=slave, stdout=slave, stderr=slave, preexec_fn=acquire)
        yield master, slave
    finally:
        if child is not None and child.poll() is None: child.kill()
        os.close(master); os.close(slave)
        if child is not None: child.wait(timeout=5)
