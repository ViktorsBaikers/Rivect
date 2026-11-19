"""Gate SSE completion on a real preview painted by the installed terminal."""
from http.client import parse_headers
import json
import os
from pathlib import Path
import select
import socket
import sqlite3
import sys
import unittest

from installed_test import chat_terminal, painted_text, wait_text
from screen_reader import terminal_reader


def chunk(delta, finish=None):
    choice = {'index': 0, 'delta': delta, 'finish_reason': finish}
    return ('data: ' + json.dumps({'id': 'r1', 'object': 'chat.completion.chunk', 'choices': [choice]}) + '\n\n').encode()


class StreamingTest(unittest.TestCase):
    def test_failed_stream_keeps_sanitized_head_and_typed_status(self):
        with socket.create_server(('127.0.0.1', 0)) as listener:
            listener.settimeout(5)
            endpoint = f'http://127.0.0.1:{listener.getsockname()[1]}/v1'
            with chat_terminal(binary, 'vllm', endpoint) as (master, database, _):
                os.write(master, b'outline a row\r')
                peer, _ = listener.accept()
                with peer, peer.makefile('rb') as request:
                    self.assertTrue(request.readline().startswith(b'POST '))
                    headers = parse_headers(request)
                    request.read(int(headers['Content-Length']))
                    peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n')
                    peer.sendall(chunk({'content':'ROW\x01\u200b42'}))
                    observed = wait_text(master, b'ROW^A42')
                    self.assertNotIn(b'ROW\x01', observed)
                    peer.sendall(b'data: not-json\n\n')
                    peer.shutdown(socket.SHUT_WR)
                    wait_text(master, 'output · error'.encode())
                    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                        self.assertEqual(db.execute('SELECT count(*) FROM usage_settlements').fetchone(), (1,))
                        self.assertIsNone(db.execute('SELECT reply FROM ui_message_replies').fetchone()[0])

    def test_inspection_during_local_send(self):
        with socket.create_server(('127.0.0.1', 0)) as listener:
            listener.settimeout(5)
            endpoint = f'http://127.0.0.1:{listener.getsockname()[1]}/v1'
            with chat_terminal(binary, 'vllm', endpoint) as (master, database, _):
                see = terminal_reader()
                os.write(master, b'inspect without interrupting\r')
                peer, _ = listener.accept()
                with peer, peer.makefile('rb') as request:
                    self.assertTrue(request.readline().startswith(b'POST /v1/chat/completions '))
                    headers = parse_headers(request)
                    self.assertIn(b'inspect without interrupting', request.read(int(headers['Content-Length'])))
                    peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n')
                    peer.sendall(chunk({'content': 'SLOW_INITIAL'}))
                    see(master, b'SLOW_INITIAL')
                    os.write(master, b'/settings\r')
                    see(master, b'context.auto_compact')
                    os.write(master, b'\x1b')
                    see(master, b'SLOW_INITIAL')
                    for command, marker in [(b'/permissions', b'Permissions:'),
                                            (b'/accounting', b'pending sends: 1'),
                                            (b'/resume', b'Recent sessions')]:
                        os.write(master, command + b'\r')
                        see(master, marker)
                    peer.sendall(chunk({'content': ' SEND_FINISHED'}, 'stop') + b'data: [DONE]\n\n')
                    peer.shutdown(socket.SHUT_WR)
                    see(master, b'waiting')
                    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                        self.assertEqual(db.execute('SELECT reply FROM ui_message_replies').fetchall(),
                                         [('SLOW_INITIAL SEND_FINISHED',)])
                        self.assertEqual(db.execute('SELECT count(*) FROM usage_settlements').fetchone(), (1,))
                    self.assertFalse(select.select([listener], [], [], .2)[0], 'inspection caused another send')

    def test_accounting_project_is_launch_directory(self):
        with chat_terminal(binary, 'loopback', '') as (master, database, _):
            project = database.parents[2].resolve()
            os.write(master, b'/accounting\r')
            wait_text(master, (project.name + ' ·').encode())

    def test_preview_is_visible_before_finish_and_never_replayed(self):
        for switch in (False, True):
            with self.subTest(switch=switch), socket.create_server(('127.0.0.1', 0)) as listener:
                listener.settimeout(5)
                endpoint = f'http://127.0.0.1:{listener.getsockname()[1]}/v1'
                with chat_terminal(binary, 'vllm', endpoint) as (master, database, _):
                    os.write(master, b'first question\r')
                    peer, _ = listener.accept()
                    with peer, peer.makefile('rb') as request, sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
                        peer.settimeout(5)
                        self.assertTrue(request.readline().startswith(b'POST /v1/chat/completions '))
                        headers = parse_headers(request)
                        self.assertIn(b'first question', request.read(int(headers['Content-Length'])))
                        session, = db.execute('SELECT session_id FROM tasks').fetchone()
                        peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n')
                        peer.sendall(chunk({'reasoning_content': 'PRIVATE_THOUGHT', 'content': '雪EARLY_MARKER'}))
                        seen = wait_text(master, b'EARLY_MARKER')
                        self.assertEqual(db.execute('SELECT lifecycle FROM tasks').fetchone(), ('running',))
                        peer.sendall(chunk({'content':' EXTRA_DELTA'}))
                        seen.extend(wait_text(master, b'EXTRA_DELTA'))
                        self.assertEqual(db.execute('SELECT count(*) FROM ui_message_replies').fetchone(), (0,))
                        if not switch:
                            peer.sendall(chunk({'content':' FINAL_WORD'}, 'stop') + b'data: [DONE]\n\n')
                            peer.shutdown(socket.SHUT_WR)
                            seen.extend(wait_text(master, b'waiting'))
                        else:
                            os.write(master, b'/cancel\r')
                            seen.extend(wait_text(master, b'cancelled'))
                        os.write(master, b'/clear\r')
                        seen.extend(wait_text(master, b'New conversation'))
                        if switch:
                            self.assertEqual(peer.recv(1), b'')
                        other, = db.execute('SELECT session_id FROM sessions WHERE session_id!=?', (session,)).fetchone()
                        os.write(master, ('/resume ' + other + '\r').encode())
                        seen.extend(wait_text(master, b'Resumed session:', seen))
                        empty = painted_text(master, seen)
                        self.assertNotIn(b'EARLY_MARKER', empty)
                        self.assertNotIn(b'EXTRA_DELTA', empty)
                        os.write(master, ('/resume ' + session + '\r').encode())
                        seen.extend(wait_text(master, b'cancelled' if switch else b'FINAL_WORD', seen))
                        restored = painted_text(master, seen)
                        if switch:
                            self.assertNotIn(b'EARLY_MARKER', restored)
                            self.assertNotIn(b'EXTRA_DELTA', restored)
                        self.assertNotIn(b'PRIVATE_THOUGHT', seen + restored)
                        self.assertEqual(db.execute('SELECT session_id,lifecycle FROM tasks').fetchall(),
                                         [(session, 'cancelled' if switch else 'waiting')])
                        self.assertEqual(db.execute('SELECT reply FROM ui_message_replies').fetchall(),
                                         [] if switch else [('雪EARLY_MARKER EXTRA_DELTA FINAL_WORD',)])
                        self.assertFalse(select.select([listener], [], [], .2)[0], 'polling or resume sent a second POST')


if __name__ == '__main__':
    binary = Path(sys.argv.pop(1)).resolve(strict=True)
    unittest.main()
