"""Run against the public CLI of a locally packaged v2 kit (no global Bun)."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest

from installed_test import painted_text, wait_text, wait_terminal_exit
from session_test import core_pid, saved_running_task


def ready_after(master, marker):
    response = wait_text(master, 'Message · Enter submits'.encode())
    if marker not in response: raise AssertionError(response)
    return response


def restored_linear_output(master, child):
    received = wait_text(master, b'\x1b[?2004l')
    deadline = time.monotonic() + 5
    while child.poll() is None and time.monotonic() < deadline:
        if select.select([master], [], [], .05)[0]: received += os.read(master, 65536)
    if child.wait(timeout=1) != 0: raise AssertionError('linear client did not exit cleanly')
    return received


class Launch(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.bin = self.home / 'rivect'
        self.bin.symlink_to(binary)
        self.env = {'HOME': tmp.name, 'TMPDIR': tmp.name, 'TERM': 'xterm-256color', 'PATH': '/usr/bin:/bin'}

    @contextmanager
    def terminal(self, *args, program=None, cwd=None):
        master, slave = pty.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
            settings = termios.tcgetattr(slave)
            with subprocess.Popen([program or self.bin, *args], cwd=cwd or self.home, env=self.env, stdin=slave, stdout=slave, stderr=slave) as ui:
                try:
                    yield ui, master
                    self.assertEqual(settings, termios.tcgetattr(slave))
                finally:
                    if ui.poll() is None:
                        ui.kill()
        finally:
            os.close(master)
            os.close(slave)

    def test_mux_environment_never_requests_synchronized_output(self):
        for env in ({'TERM':'tmux-256color'}, {'TERM':'screen-256color'}, {'TMUX':'private-test-socket'}, {'STY':'private-screen'}):
            with self.subTest(env=env):
                previous = self.env; self.env = {**previous, **env}
                try:
                    with self.terminal() as (ui, master):
                        first = wait_text(master, b'Message')
                        self.assertNotIn(b'\x1b[?2026h', first)
                        os.write(master, b'\x03')
                        self.assertEqual(wait_terminal_exit(master, ui), 130)
                finally:
                    self.env = previous

    def test_default_installed_command_runs_packaged_renderer(self):
        with self.terminal() as (ui, master):
            first = wait_text(master, b'Message')
            self.assertIn(b'\x1b[?1049h', first)
            command = subprocess.check_output(['ps', '-p', str(ui.pid), '-o', 'comm='], text=True).strip()
            self.assertEqual(Path(command).resolve(), binary.parent / 'libexec/rivect-tui')
            os.write(master, b'\x03')
            self.assertEqual(wait_terminal_exit(master, ui), 130)
        self.assertFalse((self.home / '.rivect').exists())

    def test_linear_stream_preserves_data_root_and_never_addresses_cursor(self):
        root = self.home / 'state with spaces'
        with self.terminal('--linear', '--data-root', str(root)) as (ui, master):
            transcript = wait_text(master, b'Message')
            os.write(master, b'linear goal\r')
            transcript += wait_text(master, b'waiting')
            os.write(master, b'\x04')
            transcript += restored_linear_output(master, ui)
            self.assertNotIn(b'\x1b', transcript.replace(b'\x1b[?2004h', b'').replace(b'\x1b[?2004l', b''))
        self.assertTrue((root / 'runtime/rivect.db').is_file())
        self.assertFalse((self.home / '.rivect').exists())

    def test_inline_retains_turn_outside_fullscreen(self):
        with self.terminal('--tui', 'inline') as (ui, master):
            transcript = wait_text(master, b'Message')
            os.write(master, b'inline goal\r')
            transcript += wait_text(master, b'waiting')
            os.write(master, b'\x03')
            deadline = time.monotonic() + 5
            while ui.poll() is None and time.monotonic() < deadline:
                if select.select([master], [], [], .05)[0]:
                    transcript += os.read(master, 65536)
            self.assertEqual(ui.wait(timeout=1), 130)
            self.assertNotIn(b'\x1b[?1049h', transcript)
            self.assertIn(b'You: inline goal', painted_text(master, transcript))

    def test_roundtrip_switches_capture(self):
        with self.terminal('--tui', 'inline') as (ui, master):
            wait_text(master, b'Message')
            os.write(master, b'/tui fullscreen\r')
            wait_text(master, b'\x1b[?1049h')
            os.write(master, b'\x14')  # Ctrl+T returns to captured scrollback.
            raw = wait_text(master, b'\x1b[?1049l')
            os.write(master, b'captured turn\r')
            raw += wait_text(master, b'waiting')
            if b'Enter selects' not in raw: raw += wait_text(master, b'Enter selects')
            time.sleep(.23)
            os.write(master, b'\x1b')
            raw += wait_text(master, b'Message')
            os.write(master, b'/exit\r')
            deadline = time.monotonic() + 5
            while ui.poll() is None and time.monotonic() < deadline:
                if select.select([master], [], [], .05)[0]: raw += os.read(master, 65536)
            self.assertEqual(ui.wait(timeout=1), 0)
            self.assertIn(b'You: captured turn', painted_text(master, raw))
            with sqlite3.connect((self.home / '.rivect/runtime/rivect.db').as_uri() + '?mode=ro', uri=True) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM answer_attempts').fetchone(), (0,))

    def test_linear_paste_is_draft(self):
        with self.terminal('--linear') as (ui, master):
            raw = wait_text(master, b'Message')
            self.assertIn(b'\x1b[?2004h', raw)
            os.write(master, b'\x1b[200~alpha\r\n')
            os.write(master, '雪'.encode() + b'\x1b[20')
            os.write(master, b'1~')
            wait_text(master, '雪'.encode())
            database = self.home / '.rivect/runtime/rivect.db'
            self.assertFalse(database.exists())
            os.write(master, b'\r')
            wait_text(master, b'waiting')
            with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                self.assertEqual(db.execute('SELECT goal_bytes FROM tasks').fetchall(), [('alpha\n雪'.encode(),)])
            os.write(master, b'/exit\r')
            restored_linear_output(master, ui)

    def test_linear_rejects_unlabelled_login_callback(self):
        with self.terminal('--linear') as (ui, master):
            wait_text(master, b'Message')
            url = b'http://localhost:1455/auth/callback?code=private-oauth-canary&state=private-state'
            os.write(master, b'\x1b[200~' + url + b'\x1b[201~\r')
            raw = wait_text(master, b'Use /login')
            os.write(master, b'/login callback\r')
            raw += wait_text(master, b'Input hidden')
            os.write(master, b'\x1b[200~' + url + b'\x1b[201~\x1b')
            raw += wait_text(master, b'Private input discarded')
            os.write(master, b'/exit\r')
            raw += restored_linear_output(master, ui)
            self.assertNotIn(b'private-', raw)
            self.assertFalse((self.home / '.rivect/runtime/rivect.db').exists())

    def test_linear_settings_never_create_absent_user_config(self):
        with self.terminal('--linear') as (ui, master):
            wait_text(master, b'Message')
            os.write(master, b'/workflow off\r')
            ready_after(master, b'User config.toml missing')
            os.write(master, b'/settings confirm\r')
            ready_after(master, b'No pending settings change')
            os.write(master, b'/exit\r')
            restored_linear_output(master, ui)
            self.assertFalse((self.home / '.rivect/config.toml').exists())

    def test_linear_settings_require_typed_confirmation(self):
        config = self.home / '.rivect/config.toml'
        config.parent.mkdir(mode=0o700)
        config.write_text('config_version = 1\n[connections.loopback]\nkind = "local"\nendpoint = ""\n'
                          '[models.defaults]\nmodel = { mode = "fixed", connection = "loopback", model_id = "offline" }\n'
                          'effort = { mode = "fixed", value = "medium" }\nfallback = { mode = "off" }\n')
        before = config.read_bytes()
        with self.terminal('--linear') as (ui, master):
            wait_text(master, b'Message')
            os.write(master, b'/workflow off\r')
            preview = ready_after(master, b'/settings confirm')
            self.assertIn(b'workflow.enabled', preview)
            self.assertRegex(bytes(preview), rb'[a-f0-9]{64}')
            os.write(master, b'\x1b[200~/settings confirm\x1b[201~\r')
            ready_after(master, b'Type the confirmation')
            self.assertEqual(config.read_bytes(), before)
            os.write(master, b'/settings confirm\r')
            ready_after(master, b'Saved to user config')
            self.assertNotEqual(config.read_bytes(), before)
            os.write(master, b'/workflow status\r')
            ready_after(master, b'workflow.enabled = false')
            os.write(master, b'/exit\r')
            restored_linear_output(master, ui)

    def test_empty_linear_compact_never_opens_store(self):
        with self.terminal('--linear') as (ui, master):
            wait_text(master, b'Message')
            os.write(master, b'/compact\r')
            ready_after(master, b'No conversation to compact yet; submit a task first.')
            os.write(master, b'/exit\r')
            restored_linear_output(master, ui)
        self.assertFalse((self.home / '.rivect').exists())

    def test_linear_compact_explains_short_history(self):
        session = saved_running_task(binary, self.home)
        with self.terminal('--linear') as (ui, master):
            wait_text(master, b'Message')
            os.write(master, ('/resume ' + session + '\r').encode())
            ready_after(master, ('Resumed session: ' + session).encode())
            os.write(master, b'/compact\r')
            ready_after(master, b'compaction would not shorten the history')
            os.write(master, b'/exit\r')
            restored_linear_output(master, ui)

    def test_linear_refuses_switch_for_passive_running_task(self):
        session = saved_running_task(binary, self.home)
        database = self.home / '.rivect/runtime/rivect.db'
        with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
            task, = db.execute('SELECT task_id FROM tasks WHERE session_id=?', (session,)).fetchone()
            with self.terminal('--linear') as (ui, master):
                wait_text(master, b'Message')
                os.write(master, ('/resume ' + session + '\r').encode())
                ready_after(master, b'Resumed session: ' + session.encode())
                for command in (b'/new', b'/clear'):
                    os.write(master, command + b'\r')
                    ready_after(master, ('task ' + task + ' is running').encode())
                os.write(master, b'/exit\r')
                restored_linear_output(master, ui)
            self.assertEqual(db.execute('SELECT lifecycle FROM tasks WHERE task_id=?', (task,)).fetchone(), ('running',))

    def test_uncaught_restores_terminal(self):
        source = Path(__file__).resolve().parent
        inject = ('import {runClient} from "./modes"; process.on("SIGUSR1", () => { throw new Error("private-throw-canary"); }); '
                  'await runClient([]);')
        bun = os.environ.get('RIVECT_TEST_BUN') or shutil.which('bun')
        self.assertIsNotNone(bun)
        # The signal injector exists only in this source-mode test; its core is
        # the authentic supplied release, not the checkout's stale development build.
        app = self.home / 'client'
        app.mkdir()
        for file in (*source.glob('*.ts'), *source.glob('*.tsx'), source/'bunfig.toml', source/'tsconfig.json', source/'package.json'):
            shutil.copyfile(file, app/file.name)
        (app/'node_modules').symlink_to(source/'node_modules', target_is_directory=True)
        (app/'build').mkdir()
        (app/'build/core').symlink_to(binary.parent, target_is_directory=True)
        with self.terminal('-e', inject, program=bun, cwd=app) as (ui, master):
            raw = wait_text(master, b'Message')
            os.write(master, b'/task crash ownership probe\r')
            raw += wait_text(master, b'Begin the first step')
            owner = core_pid(ui)
            os.kill(owner, signal.SIGSTOP)
            try:
                ui.send_signal(signal.SIGUSR1)
                raw += wait_text(master, b'terminal client stopped unexpectedly')
                self.assertLess(raw.index(b'\x1b[?1049l'), raw.index(b'terminal client stopped unexpectedly'))
                with self.assertRaises(subprocess.TimeoutExpired):
                    ui.wait(timeout=.15)  # Cannot exit while the stopped owner still holds its locks.
            finally:
                os.kill(owner, signal.SIGCONT)
            self.assertNotIn(b'private-throw-canary', raw)
            self.assertEqual(ui.wait(timeout=5), 1)
            with self.assertRaises(ProcessLookupError):
                os.kill(owner, 0)

    def test_machine_surface_never_enters_client(self):
        for args in ([], ['--headless'], ['--linear']):
            with self.subTest(args=args):
                request = json.dumps({'jsonrpc':'2.0', 'id':1, 'method':'doctor', 'params':{'schema_version':1}})
                result = subprocess.run([self.bin, *args], cwd=self.home, env=self.env,
                                        input=request+'\n', text=True, capture_output=True, timeout=5)
                self.assertEqual(json.loads(result.stdout)['id'], 1)
                self.assertNotIn('\x1b', result.stdout + result.stderr)


if __name__ == '__main__':
    binary = Path(sys.argv.pop(1)).resolve(strict=True)
    unittest.main()
