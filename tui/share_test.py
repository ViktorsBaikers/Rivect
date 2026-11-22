"""A remote connection can request a file share; the card names it."""
import json
import os
import select
import sys
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread

from installed_test import chat_terminal, painted_text


class ShareTest(unittest.TestCase):
    def test_remote_read_requests_disclosure(self):
        class Peer(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                call = {'index': 0, 'id': 'one', 'type': 'function',
                        'function': {'name': 'read_file', 'arguments': json.dumps({'path': 'inventory.rs'})}}
                frames = [
                    {'id': 'r', 'object': 'chat.completion.chunk', 'choices': [{'index': 0, 'delta': {'role': 'assistant', 'tool_calls': [call]}, 'finish_reason': None}]},
                    {'id': 'r', 'object': 'chat.completion.chunk', 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'tool_calls'}]},
                ]
                body = (''.join('data: ' + json.dumps(frame) + '\n\n' for frame in frames) + 'data: [DONE]\n\n').encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = HTTPServer(('127.0.0.1', 0), Peer)
        worker = Thread(target=server.serve_forever)
        worker.start()
        endpoint = f'http://127.0.0.1:{server.server_port}/v1'

        def seed(home):
            runtime = home / '.rivect' / 'runtime'
            runtime.mkdir(mode=0o700)
            (runtime / 'credentials.json').write_text(json.dumps({
                'version': 1, 'entries': {'rivect/deepseek': list(b'sk-local-test-key')}}))
            os.chmod(runtime / 'credentials.json', 0o600)
            (home / 'inventory.rs').write_text('const STOCK: u8 = 41;\n')

        try:
            with chat_terminal(binary, 'deepseek', endpoint, kind='api_key',
                               args=('--terminal-client',), before_start=seed) as (master, database, _):
                os.write(master, b'Check this project for bugs\r')
                history = bytearray()
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        history.extend(os.read(master, 65536))
                    screen = painted_text(master, history)
                    if b'Share inventory.rs' in screen:
                        break
                else:
                    self.fail('remote file share card did not appear')
                self.assertIn(b'Share inventory.rs', screen)
                self.assertIn(b'deepseek', screen)
                self.assertIn(endpoint.encode(), screen)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == '__main__':
    binary = Path(sys.argv.pop(1)).resolve(strict=True)
    unittest.main()
