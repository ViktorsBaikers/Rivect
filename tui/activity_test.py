"""Keep reading position and draft when the project executor requests check approval."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import termios
from threading import Event, Thread
import time

from installed_test import painted_text, wait_text
from project_diff_test import tool_stream


def activity(binary, *, editing):
    requested, release = Event(), Event()
    posts = []

    class LocalProvider(BaseHTTPRequestHandler):
        def log_message(self, format, *args): pass

        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"data":[]}')

        def do_POST(self):
            posts.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            self.send_response(200); self.send_header('Content-Type', 'text/event-stream'); self.end_headers()
            def frame(choice):
                chunk = {'id':'activity', 'choices':[{'index':0, **choice}]}
                self.wfile.write(('data: ' + json.dumps(chunk) + '\n\n').encode()); self.wfile.flush()
            if len(posts) == 1:
                call = tool_stream('read_file', {'path':'inventory.rs'})
            elif len(posts) == 2:
                call = tool_stream('write_file', {'path':'inventory.rs','text':'const STOCK: u8 = 2;\n'})
            elif len(posts) == 3:
                first, finish = tool_stream('run_check', {'test':'stock_matches'})
                frame(first)  # Arguments arrived, but the provider has not committed the tool call.
                requested.set()
                if not release.wait(15): return
                call = [finish]
            else: raise AssertionError('inspection repeated provider work')
            for choice in call: frame(choice)
            self.wfile.write(b'data: [DONE]\n\n')

    def controlling_tty():
        os.setsid(); fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    with tempfile.TemporaryDirectory() as directory, HTTPServer(('127.0.0.1', 0), LocalProvider) as server:
        home = Path(directory); project = home/'project'; project.mkdir()
        (home/'.cargo').mkdir(); (project/'inventory.rs').write_text('const STOCK: u8 = 1;\n')
        (project/'Cargo.toml').write_text('[package]\nname="stock"\nversion="0.1.0"\n')
        (project/'src').mkdir(); (project/'src/lib.rs').write_text('#[test] fn stock_matches() {}\n')
        data = home/'.rivect'; data.mkdir(mode=0o700)
        (data/'config.toml').write_text(f'config_version = 1\n[connections.vllm]\nkind="local"\nendpoint="http://127.0.0.1:{server.server_port}/v1"\n'
            '[models.defaults]\nmodel={mode="fixed", connection="vllm", model_id="offline"}\neffort={mode="auto"}\nfallback={mode="off"}\n')
        cargo = subprocess.check_output(['rustup', 'which', 'cargo'], text=True).strip() if shutil.which('rustup') else shutil.which('cargo')
        assert cargo and Path(cargo).is_file(), 'installed Cargo toolchain required for real check admission'
        env = {'HOME':directory, 'TMPDIR':directory, 'PATH':f'{Path(cargo).parent}:/usr/bin:/bin', 'TERM':'xterm-256color', 'NO_COLOR':'1'}
        # Retain history through the owner before the interactive check. Do not inject
        # events into SQLite or pad the live decision card to manufacture scrollback.
        with subprocess.Popen([binary, '--ui-wire-v1'], env=env, cwd=project, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True) as seed:
            assert seed.stdin is not None and seed.stdout is not None
            def request(method, **params):
                assert seed.stdin is not None and seed.stdout is not None
                seed.stdin.write(json.dumps({'id':1, 'jsonrpc':'2.0', 'method':method,
                    'params':{'schema_version':1, **params}}) + '\n'); seed.stdin.flush()
                assert select.select([seed.stdout], [], [], 5)[0], method
                return json.loads(seed.stdout.readline())['result']
            session = request('session.project')['session_id']
            goal = '\n'.join(f'ARCHIVE-{n:03d} inspect previous change' for n in range(100 if editing else 1))
            request('task.submit', session_id=session, command_id='retained-history', kind='create',
                    goal=goal, contract={'criteria':[], 'constraints':[]})
            seed.stdin.close(); assert seed.wait(timeout=5) == 0
        master, slave = pty.openpty(); termios.tcsetwinsize(slave, (40,160))
        worker = Thread(target=server.serve_forever); worker.start()
        transcript = bytearray()
        def screen(predicate):
            deadline = time.monotonic() + 7
            while True:
                frame_end = b'\x1b[?2026l'
                last = transcript.rfind(frame_end)
                cells = painted_text(master, transcript[:last + len(frame_end)]).decode() if last >= 0 else ''
                if cells and predicate(cells): return cells
                if time.monotonic() >= deadline or not select.select([master], [], [], max(0, deadline-time.monotonic()))[0]:
                    raise AssertionError(f'expected frame did not arrive ({len(posts)} POSTs, exit {child.poll()}):\n{cells}')
                part = os.read(master, 65536)
                if not part: raise EOFError('terminal exited')
                transcript.extend(part)
        def see(text): return screen(lambda cells: text in cells)
        def send(value): os.write(master, value.encode())
        def answer(option):
            see('Enter selects · focus 1/')
            time.sleep(.25)  # Independent first-paint consent floor.
            if option:
                send('j'); see('focus 2/'); time.sleep(.25)
            send('\r')
            witness = wait_text(master, b'press Enter to cancel:')
            transcript.extend(witness)
            challenge = re.search(rb'Type ([0-9A-F]{6}) to confirm', witness)
            assert challenge, witness
            os.write(master, challenge[1] + b'\r')
        child = subprocess.Popen([binary], cwd=project, env=env, stdin=slave, stdout=slave, stderr=slave, preexec_fn=controlling_tty)
        os.close(slave)
        try:
            see('ARCHIVE-'); send('/task update and check inventory\r'); see('Begin the first step'); answer(0)
            see('Share inventory.rs'); answer(1); see('Write inventory.rs'); answer(1)
            assert requested.wait(7), 'owner never sent the authorized write observation'
            if not editing:
                release.set(); idle = screen(lambda cells: 'Run Cargo test stock_matches' in cells and 'Enter selects' in cells)
                assert 'Enter selects' in idle and 'Verifier' in idle and 'check approval' in idle, idle
                assert len(posts) == 3
                return
            following = see('decision answer recorded'); send('\x1b[5~')
            send('\x1b[200~first draft line\nsecond draft line\x1b[201~'); before = see('second draft line')
            def anchor(cells):
                return next(((n,m[0]) for n,line in enumerate(cells.splitlines()) if (m:=re.search(r'ARCHIVE-\d{3}',line))), None)
            fixed = anchor(before); assert fixed is not None and 'first draft line' in before
            assert fixed != anchor(following) and 'Verifier' not in before, before
            def divider(cells):
                rows = cells.splitlines()
                return rows[1].find('│') if len(rows) > 1 else -1
            split = divider(before)
            assert split > 0, before
            def sidebar(cells): return '\n'.join(line[:split] for line in cells.splitlines())
            def timeline(cells): return '\n'.join(line[split:] for line in cells.splitlines())
            send('\t'); active_detail = see('Task detail')
            with sqlite3.connect((data/'runtime/rivect.db').as_uri()+'?mode=ro', uri=True) as db:
                current, = db.execute('SELECT task_id FROM tasks WHERE goal_bytes=?', (b'update and check inventory',)).fetchone()
            assert current in active_detail and len(posts) == 3, active_detail
            send('\x1b'); kept = screen(lambda cells: 'Message → Main' in cells and 'Task detail' not in cells)
            assert anchor(kept) == fixed and 'second draft line' in kept, kept
            transcript.clear()  # The screen oracle replays bytes at one fixed geometry.
            termios.tcsetwinsize(master, (31, 101))
            os.kill(child.pid, signal.SIGWINCH)
            resized = screen(lambda cells: 0 < divider(cells) < split and 'second draft line' in cells)
            resized_anchor = anchor(resized)
            assert resized_anchor is not None and resized_anchor[1] == fixed[1], resized
            transcript.clear()
            termios.tcsetwinsize(master, (40, 160))
            os.kill(child.pid, signal.SIGWINCH)
            screen(lambda cells: divider(cells) == split and anchor(cells) == fixed)
            release.set()
            frame = screen(lambda cells: 'Verifier' in sidebar(cells) and 'check approval' in sidebar(cells))
            assert anchor(frame) == fixed and 'second draft line' in frame, frame
            assert 'Enter selects' not in frame, 'arriving question stole composer focus'
            send('!'); see('second draft line!'); send('\t'); detail = see('Verifier detail')
            assert 'check approval' in detail and 'question.published' in detail, detail
            send('\x1b'); restored = screen(lambda cells: 'Message → Main' in cells and 'Verifier detail' not in cells)
            assert anchor(restored) == fixed and 'first draft line' in restored and 'second draft line!' in restored, restored
            linked = restored
            for _ in range(5):  # Fixture retains 100 old rows, plus the event history.
                if 'Verifier · waiting' in timeline(linked): break
                prior = timeline(linked)
                send('\x1b[6~'); linked = screen(lambda cells: timeline(cells) != prior)
            assert 'Verifier · waiting for check approval' in timeline(linked) and 'question.published' in timeline(linked), linked
            assert len(posts) == 3
            with sqlite3.connect((data/'runtime/rivect.db').as_uri()+'?mode=ro', uri=True) as db:
                assert db.execute("SELECT count(*) FROM questions WHERE state='pending' AND question_id LIKE 'run-check:%'").fetchone() == (1,)
                assert db.execute("SELECT count(*) FROM attempts WHERE effect_class='exec'").fetchone() == (0,)
        finally:
            release.set()
            if child.poll() is None: os.killpg(child.pid, signal.SIGKILL)
            os.close(master)
            try: child.wait(timeout=5)
            finally: server.shutdown(); worker.join(timeout=5)


if __name__ == '__main__':
    binary = Path(sys.argv[1]).resolve(strict=True)
    if sys.argv[2:] != ['editing']: activity(binary, editing=False)
    if sys.argv[2:] != ['idle']: activity(binary, editing=True)
