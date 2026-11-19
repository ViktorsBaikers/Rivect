"""Offline fullscreen parity, using real Core effects and tui-test PTY cells.

python3 tui/thread_visual.py RIVECT [--capture DIR --label before|after] [--compare-only]
"""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
from threading import Thread
import time
import uuid

from project_diff_test import tool_stream


SIZES = [(160, 50), (101, 31), (80, 24), (60, 20)]


def exercise(binary, capture, label, compare_only):
    posts = []
    calls = [None, ('read_file', {'path': 'inventory.rs'}),
             ('write_file', {'path': 'inventory.rs', 'text': 'const STOCK: u8 = 2;\n'}),
             ('run_check', {'test': 'stock_matches'}), None,
             ('read_file', {'path': 'inventory.rs'}),
             ('write_file', {'path': 'inventory.rs', 'text': 'const STOCK: u8 = 3;\n'}),
             ('run_check', {'test': 'stock_matches'})]

    class LocalProvider(BaseHTTPRequestHandler):
        def log_message(self, format, *args): pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"data":[]}')

        def do_POST(self):
            posts.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            index = len(posts) - 1
            call = calls[index]
            if call:
                choices = tool_stream(*call)
            else:
                message = ('I will trace the reservation before changing inventory.' if index == 0 else
                           'The regression passed. Full suite not run.')
                choices = [{'delta': {'role': 'assistant', 'content': message}, 'finish_reason': 'stop'}]
            frames = [{'id': 'offline', 'choices': [{'index': 0, **choice}]} for choice in choices]
            body = (''.join('data: ' + json.dumps(frame) + '\n\n' for frame in frames) + 'data: [DONE]\n\n').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with tempfile.TemporaryDirectory() as directory, HTTPServer(('127.0.0.1', 0), LocalProvider) as server:
        home = Path(directory).resolve()
        project = home / 'inventory-cache'
        project.mkdir()
        (home / '.cargo').mkdir()
        (project / 'inventory.rs').write_text('const STOCK: u8 = 1;\n')
        (project / 'Cargo.toml').write_text('[package]\nname="inventory"\nversion="0.1.0"\nedition="2024"\n')
        (project / 'Cargo.lock').write_text('version = 4\n[[package]]\nname = "inventory"\nversion = "0.1.0"\n')
        (project / 'src').mkdir()
        (project / 'src/lib.rs').write_text('include!("../inventory.rs");\n#[test] fn stock_matches() { assert_eq!(STOCK, 2); }\n')
        config = home / '.rivect'
        config.mkdir(mode=0o700)
        (config / 'config.toml').write_text(
            f'config_version=1\n[connections.vllm]\nkind="local"\nendpoint="http://127.0.0.1:{server.server_port}/v1"\n'
            '[models.defaults]\nmodel={mode="fixed",connection="vllm",model_id="offline"}\n'
            'effort={mode="auto"}\nfallback={mode="off"}\n')
        cargo = Path(subprocess.check_output(['rustup', 'which', 'cargo'], text=True).strip())
        session = 'thread-' + uuid.uuid4().hex[:10]

        def terminal(*args):
            call = subprocess.run(['tui-test', '--session', session, *args], capture_output=True, text=True, timeout=30)
            if call.returncode:
                raise AssertionError(f'{args}: {call.stdout}{call.stderr}')
            return call.stdout

        def see(text, *args):
            return terminal('expect', 'text', text, '--timeout', '12000', *args)

        def send(text):
            terminal('write', text)

        challenges_seen = []
        def answer(option=0):
            see('Enter selects')
            time.sleep(.25)  # Required independent first-paint consent floor.
            if option:
                send('j')
                see('focus 2/')
                time.sleep(.25)
            send('\r')
            deadline = time.monotonic() + 7
            while time.monotonic() < deadline:
                for challenge in reversed(re.findall(r'Type ([0-9A-F]{6}) to confirm', terminal('text'))):
                    if challenge not in challenges_seen:
                        challenges_seen.append(challenge)
                        send(challenge + '\r')
                        return
                time.sleep(.02)
            raise AssertionError('missing fresh independent terminal challenge')

        def snapshot(name):
            cells = terminal('text')
            if capture:
                (capture / f'{label}-{name}.txt').write_text(cells)
                terminal('screenshot', '-o', str(capture / f'{label}-{name}.png'))
            return cells

        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            terminal('run', '--cols', '160', '--rows', '50', '--cwd', str(project), '/usr/bin/env', '-i',
                     f'HOME={home}', f'TMPDIR={home}', f'PATH={cargo.parent}:/usr/bin:/bin',
                     'TERM=xterm-256color', 'COLORTERM=truecolor', 'RIVECT_THEME=dark', str(binary))
            see('Message')
            snapshot('empty-160x50')
            send('Why does inventory still show the old stock count?\r')
            see('I will trace the reservation')
            for goal in ('Update inventory and run the regression', 'Prepare the remaining inventory check'):
                send(f'/task {goal}\r')
                see('Begin the first step')
                answer()
                see('Share inventory.rs')
                answer(1)
                see('Write inventory.rs')
                if goal.startswith('Update'):
                    send('v')
                    see('Proposed diff · Esc back')
                    see('const STOCK: u8 = 2;')
                    snapshot('diff-160x50')
                    send('\x1b')
                    see('Write inventory.rs')
                    see('V view proposed diff')
                answer(1)
                see('Run Cargo test stock_matches')
                if goal.startswith('Update'):
                    answer(1)
                    see('Cargo test stock_matches: exit 0.')
            time.sleep(.25)
            send('\x1b')
            see('question stays pending')
            assert len(posts) == len(calls), f'expected exactly {len(calls)} provider calls, got {len(posts)}'
            assert '"exit_code":0' in str(posts[4]).replace(' ', '').replace('\\"', '"'), posts[4]
            assert (project / 'inventory.rs').read_text() == 'const STOCK: u8 = 3;\n'
            frames = {}
            for cols, rows in SIZES:
                terminal('resize', str(cols), str(rows))
                terminal('wait', 'idle')
                frames[cols] = snapshot(f'{cols}x{rows}')
            if not compare_only:
                assert 'Why does inventory still show the old stock count?' in frames[160], 'opening message must fit at 160×50'
                wide = frames[160].splitlines()
                failures = []
                def check(condition, message):
                    if not condition: failures.append(message)
                check('╞╪ RIVECT' in wide[1] and 'inventory-cache' in wide[1], 'shared project and brand header')
                check(all(marker in frames[160] for marker in ('Agents', 'Processes', 'Plan', '└─ Verifier', 'check approval')), 'grouped sidebar with wait reason')
                check(all(marker in frames[160] for marker in ('├─', 'stock_matches: exit 0', 'const STOCK: u8 = 2;')),
                      'one branched history with real applied diff and check result')
                check(bool(re.search(r'[-−]\s*const STOCK: u8 = 1;', frames[160])) and
                      bool(re.search(r'\+\s*const STOCK: u8 = 2;', frames[160])), 'diff signs distinguish removal and addition')
                for cols, rows in SIZES:
                    lines = frames[cols].splitlines()
                    check(any('Message' in line for line in lines[-5:]) and 'check approval' in frames[cols],
                          f'waiting reason and anchored composer at {cols}×{rows}')
                check(all('Verify' in frame and 'context unknown tok · model offline' in frame for cols, frame in frames.items() if cols >= 80),
                      'visible active check and honest compact accounting')
                terminal('resize', '160', '50')
                for text, args in [('RIVECT', ['--fg', '#f0e2ee', '--bg', '#241b29']),
                                   ('╞╪', ['--fg', '#ffa58f']), ('Agents', ['--bg', '#241b29']),
                                   ('Main', ['--fg', '#d7b2f6', '--bg', '#1c1521']),
                                   ('──', ['--fg', '#533e58'])]:
                    try: terminal('expect', 'text', text, '--timeout', '600', *args)
                    except AssertionError: failures.append(f'painted {text!r} with {args}')
                assert not failures, '\n'.join(failures)
        except AssertionError as error:
            uri = (config / 'runtime/rivect.db').as_uri() + '?mode=ro'
            with sqlite3.connect(uri, uri=True) as db:
                print('Answers:', db.execute('SELECT outcome FROM answer_attempts').fetchall())
                print('Effects:', db.execute('SELECT effect_class,state FROM attempts').fetchall())
            raise AssertionError(f'{error}\nPOSTs: {len(posts)}\n{terminal("text")}') from error
        finally:
            terminal('close')
            server.shutdown()
            worker.join(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=lambda path: Path(path).resolve(strict=True))
    parser.add_argument('--capture', type=lambda path: Path(path).resolve(strict=True))
    parser.add_argument('--label', default='after')
    parser.add_argument('--compare-only', action='store_true')
    args = parser.parse_args()
    exercise(args.binary, args.capture, args.label, args.compare_only)
