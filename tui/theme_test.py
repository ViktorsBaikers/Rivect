"""Check actual SGR emitted by installed renderer, not its configuration."""
import fcntl
import os
import pty
import re
import struct
import subprocess
import sys
import tempfile
import termios
import unittest
from pathlib import Path

from installed_test import wait_text


class ThemeTest(unittest.TestCase):
    def frame(self, inline=False, **extra):
        master, slave = pty.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
            with tempfile.TemporaryDirectory() as home:
                env = {'TERM': 'xterm-256color', 'HOME': home, 'TMPDIR': home, 'PATH': '/usr/bin:/bin', **extra}
                argv = [binary, '--tui', 'inline'] if inline else [binary]
                child = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, cwd=home, env=env)
                try:
                    raw = wait_text(master, b'Message')
                    if inline:
                        os.write(master, b'/help\r')
                        raw += wait_text(master, b'Status: Commands: Enter submits')
                    return bytes(raw)
                finally:
                    child.kill()
                    child.wait(timeout=5)
        finally:
            os.close(slave)
            os.close(master)

    def test_indexed_themes(self):
        for theme, status, composer in [('dark', 6, 13), ('light', 4, 5), ('high-contrast', 11, 14)]:
            with self.subTest(theme=theme):
                raw = self.frame(RIVECT_THEME=theme, COLORFGBG='15;0')
                colors = re.findall(rb'(?:38|48);5;(\d+)', raw)
                self.assertIn(str(status).encode(), colors)
                self.assertIn(str(composer).encode(), colors)
                self.assertNotRegex(raw, rb'(?:38|48)[;:]2[;:]')

    def test_inline_scrollback_is_monochrome_when_requested(self):
        for override in ({'TERM': 'dumb'}, {'NO_COLOR': ''}):
            with self.subTest(override=override):
                raw = self.frame(inline=True, RIVECT_THEME='high-contrast', **override)
                self.assertNotRegex(raw, rb'\x1b\[(?:[0-9;]*;)?(?:3[0-8]|4[0-8]|58|9[0-7]|10[0-7])(?:[;:][0-9;:]*)?m')

    def test_background_heuristic(self):
        for background, status in [('15;0', b'6'), ('0;15', b'4')]:
            with self.subTest(background=background):
                colors = re.findall(rb'38;5;(\d+)', self.frame(COLORFGBG=background))
                self.assertIn(status, colors)

    def test_mono_and_unknown(self):
        for env in [{}, {'COLORFGBG':'15;999'}, {'RIVECT_THEME':'light', 'NO_COLOR':''}, {'RIVECT_THEME':'dark', 'TERM':'dumb'},
                    {'RIVECT_THEME':'bad-control-value', 'COLORFGBG':'15;0'}]:
            with self.subTest(env=env):
                raw = self.frame(**env)
                self.assertNotRegex(raw, rb'\x1b\[(?:[0-9;]*;)?(?:3[0-8]|4[0-8]|9[0-7]|10[0-7])(?:[;:][0-9;:]*)?m')
                if env.get('RIVECT_THEME') == 'bad-control-value':
                    self.assertEqual(raw.count(b'unknown RIVECT_THEME'), 1)
                    self.assertLess(raw.index(b'unknown RIVECT_THEME'), raw.index(b'\x1b[?1049h'))
                    self.assertNotIn(b'bad-control-value', raw)


if __name__ == '__main__':
    binary = Path(sys.argv.pop(1)).resolve(strict=True)
    unittest.main()
