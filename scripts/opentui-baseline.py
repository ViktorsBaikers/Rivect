"""Measure the idle OpenTUI client at 160x50; fresh HOME, OS cache untouched."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time


def observe(fd, marker):
    end = time.monotonic() + 5
    data = bytearray()
    while marker not in data:
        if not select.select([fd], [], [], max(0, end - time.monotonic()))[0]:
            raise TimeoutError(marker)
        chunk = os.read(fd, 65536)
        if not chunk:
            raise EOFError(marker)
        data.extend(chunk)
    return time.monotonic_ns()


def sample(binary, project):
    master, slave = pty.openpty()
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 50, 160, 0, 0))
        internal = binary.name == 'rivect-tui'
        manifest = binary.with_name('rivect.manifest.json')
        if not internal and json.loads(manifest.read_bytes())["schema_version"] != 2:
            raise ValueError("expected an OpenTUI package manifest")
        args = [] if internal else ['--tui', 'fullscreen', '--data-root', project + '/state']
        start = time.monotonic_ns()
        with subprocess.Popen([binary, *args], start_new_session=True,
                              cwd=project, stdin=slave, stdout=slave, stderr=slave,
                              env={'HOME': project, 'TERM': 'xterm-256color', 'PATH': '/usr/bin:/bin'}) as child:
            try:
                observe(master, b'Message')
                entry = time.monotonic_ns()
                marker = 'Ω'.encode()
                os.write(master, marker)
                echo = observe(master, marker)
                rows = subprocess.check_output(['ps', '-axo', 'pgid=,rss='], text=True).splitlines()
                rss = sum(int(row.split()[1]) for row in rows if int(row.split()[0]) == child.pid)
                assert rss > 0, 'empty process group'
                cancel = time.monotonic_ns()
                os.write(master, b'\x03')
                restored = observe(master, b'\x1b[?1049l')
                deadline = time.monotonic() + 5
                while child.poll() is None and time.monotonic() < deadline:
                    if select.select([master], [], [], .05)[0]:
                        os.read(master, 65536)
                code = child.wait(timeout=5)
                if code not in (0, 130):
                    raise RuntimeError(code)
                return echo-start, echo-entry, restored-cancel, rss
            finally:
                if child.poll() is None:
                    child.kill()
    finally:
        os.close(master)
        os.close(slave)


def samples(binary):
    for _ in range(20):
        with tempfile.TemporaryDirectory() as project:
            yield sample(binary, project)


if __name__ == '__main__':
    binary = Path(sys.argv[1]).resolve(strict=True)
    rows = list(samples(binary))
    for name, values in zip(('launch to accepted input', 'input to echo', 'idle Ctrl+C restore'), zip(*rows)):
        print(f'{name} p95: {sorted(values)[18] / 1e6:.2f} ms')
    print('process group RSS after echo, max KiB:', max(row[3] for row in rows))
