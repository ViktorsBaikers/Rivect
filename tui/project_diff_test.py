"""Installed public terminal: review a live project rewrite before authorizing it."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import select
import sqlite3
import sys
import tempfile
import time
from threading import Event, Thread

from installed_test import painted_text
from witness_pty import witness_pty


def tool_stream(name, args):
    call = {'index': 0, 'id': 'one', 'type': 'function',
            'function': {'name': name, 'arguments': json.dumps(args)}}
    return [{'delta': {'role': 'assistant', 'tool_calls': [call]}, 'finish_reason': None},
            {'delta': {}, 'finish_reason': 'tool_calls'}]


@contextmanager
def peer(original, proposed, delay):
    posts = []
    class Handler(BaseHTTPRequestHandler):
        timeout = 12
        def log_message(self, format, *args): pass
        def do_GET(self):
            body = b'{"object":"list","data":[]}'
            self.send_response(200); self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def do_POST(self):
            posts.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            if delay is not None:
                entered, closed = delay
                entered.set()
                self.connection.settimeout(12)
                if self.connection.recv(1) == b'': closed.set()
                return
            if len(posts) == 1:
                choices = tool_stream('read_file', {'path': 'inventory.rs'})
            elif len(posts) == 2:
                assert original.splitlines()[0] in str(posts[-1])
                choices = tool_stream('write_file', {'path': 'inventory.rs', 'text': proposed})
            else:
                choices = [{'delta': {'role': 'assistant', 'content': 'Finished inventory edit.'}, 'finish_reason': 'stop'}]
            frames = [{'id': 'chat1', 'choices': [{'index': 0, **choice}]} for choice in choices]
            frames.append({'id': 'chat1', 'choices': [], 'usage': {'prompt_tokens': 9, 'completion_tokens': 4, 'total_tokens': 13}})
            body = (''.join('data: ' + json.dumps(f) + '\n\n' for f in frames) + 'data: [DONE]\n\n').encode()
            self.send_response(200); self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    with HTTPServer(('127.0.0.1', 0), Handler) as server:
        worker = Thread(target=server.serve_forever); worker.start()
        try: yield f'http://127.0.0.1:{server.server_port}/v1', posts
        finally: server.shutdown(); worker.join()


def exercise(binary, allow, secret, *, delayed=False, chat=False, connection='vllm'):
    original = 'const STOCK: u8 = 41;\n'
    proposed = 'const STOCK: u8 = 53;\n' if not secret else 'const API_TOKEN: &str = "private-canary-945";\n'
    delay = (Event(), Event()) if delayed else None
    with tempfile.TemporaryDirectory() as work, peer(original, proposed, delay) as (endpoint, posts):
        home = Path(work); project = home / 'project'; project.mkdir()
        file = project / 'inventory.rs'; file.write_text(original)
        data = home / '.rivect'; data.mkdir(mode=0o700)
        (data / 'config.toml').write_text(f'config_version = 1\n[connections."{connection}"]\nkind = "local"\nendpoint = "{endpoint}"\n'
            f'[models.defaults]\nmodel = {{ mode = "fixed", connection = "{connection}", model_id = "fixture-chat-model" }}\n'
            'effort = { mode = "auto" }\nfallback = { mode = "off" }\n')
        env = {'HOME':work,'TMPDIR':work,'PATH':'/usr/bin:/bin','TERM':'xterm-256color','NO_COLOR':'1'}
        with witness_pty(binary, project, env, 40, 160) as (master, _):
            def send(text): os.write(master, text.encode())
            transcript = bytearray()
            def see(text):
                return screen([text.encode()], [], allow_raw=True)
            def screen(includes, excludes, *, allow_raw=False):
                deadline = time.monotonic() + 5
                start = len(transcript)
                while time.monotonic() < deadline and select.select([master], [], [], max(0, deadline - time.monotonic()))[0]:
                    part = os.read(master, 65536)
                    if not part: raise EOFError('terminal closed')
                    transcript.extend(part)
                    if allow_raw and all(transcript.find(marker, start) >= 0 for marker in includes): return transcript[start:]
                    if b'\x1b[?2026l' in part:
                        cells = painted_text(master, transcript)
                        if all(s in cells for s in includes) and all(s not in cells for s in excludes): return cells
                raise AssertionError(f'expected visible {includes} without {excludes}; screen: {painted_text(master, transcript)!r}')
            def answer(option=0):
                time.sleep(.25)  # Real first-paint consent floor.
                if option:
                    send('j'); screen([b'focus 2/'], [])
                    time.sleep(.25)  # The newly selected row needs its own consent floor.
                send('\r'); banner = see('press Enter to cancel:')
                match = re.search(rb'Type ([0-9A-F]{6}) to confirm', banner)
                assert match, 'independent terminal witness did not paint its challenge'
                os.write(master, match[1] + b'\r')
            try:
                see('Message'); send('update inventory\r' if chat else '/task update inventory\r')
                if not chat:
                    see('Begin the first step')
                    answer()
                if chat:
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        if posts:
                            with sqlite3.connect((data / 'runtime/rivect.db').as_uri() + '?mode=ro', uri=True) as db:
                                lifecycle = db.execute('select lifecycle from tasks').fetchone()[0]
                            if lifecycle != 'running':
                                break
                        time.sleep(.05)
                    assert len(posts) == 2 and posts[0].get('tools') and file.read_text() == original
                    assert 'const STOCK: u8 = 41;' in json.dumps(posts[1]), 'the read was not shared with the served connection'
                    with sqlite3.connect((data/'runtime/rivect.db').as_uri()+'?mode=ro', uri=True) as db:
                        assert not db.execute(
                            "select 1 from attempts where effect_class in ('write','exec')").fetchone()
                    return
                if delay is not None:
                    entered, closed = delay
                    assert entered.wait(5), 'verified project adapter did not POST to the local fixture'
                    see('decision answer recorded'); send('draft during project work'); see('draft during project work')
                    send('\x03'); assert closed.wait(5), 'cancel did not close the pending project transport'
                    see('cancelled'); assert len(posts) == 1 and file.read_text() == original
                    return
                see('Share inventory.rs')
                assert len(posts) == 1 and file.read_text() == original
                answer(1)
                initial = screen([b'withheld' if secret else b'V view proposed diff', b'Esc returns'], [])
                assert b'const STOCK' not in initial and b'private-canary' not in initial
                if not secret:
                    send('v'); paint = screen([b'Esc back', b'const STOCK: u8 = 41;', b'const STOCK: u8 = 53;'], [])
                    assert re.search(rb'-[ \t]*const STOCK: u8 = 41;', paint) and re.search(rb'\+[ \t]*const STOCK: u8 = 53;', paint)
                    send('\x1b'); screen([b'Write inventory.rs', b'Esc returns', b'V view proposed diff'], [b'Esc back', b'const STOCK'])
                else:
                    assert b'V view proposed diff' not in initial
                assert file.read_text() == original and len(posts) == 2
                time.sleep(.25)  # The card's first-paint guard also rejects arrival-time Esc.
                send('\x1b'); see('question stays pending')
                with sqlite3.connect((data/'runtime/rivect.db').as_uri()+'?mode=ro', uri=True) as db:
                    session, = db.execute('select session_id from tasks').fetchone()
                send('/new\r'); other = see('New conversation:')
                assert b'const STOCK' not in other and b'private-canary' not in other
                send(f'/resume {session}\r')
                screen([b'Write inventory.rs', b'Enter selects'], [])
                assert file.read_text() == original and len(posts) == 2
                answer(int(allow)); see('Finished inventory edit.' if allow else 'permission denied; file unchanged')
                assert file.read_text() == (proposed if allow else original)
                assert len(posts) == (3 if allow else 2)
                for dbfile in (data / 'runtime').glob('rivect.db*'):
                    raw = dbfile.read_bytes()
                    assert proposed.strip().encode() not in raw and original.strip().encode() not in raw
            except (AssertionError, EOFError) as error:
                uri = (data / 'runtime/rivect.db').as_uri() + '?mode=ro'
                with sqlite3.connect(uri, uri=True) as db:
                    snapshot = db.execute('select lifecycle from tasks').fetchall()
                    answers = db.execute('select outcome from answer_attempts').fetchall()
                    attempts = db.execute('select effect_class, state from attempts').fetchall()
                    usage = db.execute('select state, exactness, unknown_reason, prompt_tokens from usage_settlements').fetchall()
                raise AssertionError(f'{error}; posts={len(posts)}, tasks={snapshot}, answers={answers}, attempts={attempts}, usage={usage}') from error


if __name__ == '__main__':
    target = Path(sys.argv[1]).resolve(strict=True)
    if sys.argv[2:] == ['chat']:
        exercise(target, allow=False, secret=False, chat=True, connection='lm-studio')
    elif len(sys.argv) > 2:
        exercise(target, allow=False, secret=False, delayed=True, connection=sys.argv[2])
    else:
        exercise(target, allow=False, secret=False)
        exercise(target, allow=False, secret=True)
        exercise(target, allow=True, secret=False)
        exercise(target, allow=False, secret=False, delayed=True, connection='lm-studio')
        exercise(target, allow=False, secret=False, chat=True, connection='lm-studio')
