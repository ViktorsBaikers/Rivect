"""Wheel and trackpad scrolling over a completed transcript output."""
import json
import os
import re
import select
import socket
import sys
import time
import unittest
from pathlib import Path

from installed_test import chat_terminal, painted_text


def chunk(delta, finish=None):
    choice = {'index': 0, 'delta': delta, 'finish_reason': finish}
    return ('data: ' + json.dumps({'id': 'r1', 'object': 'chat.completion.chunk', 'choices': [choice]}) + '\n\n').encode()


def first_marker(screen):
    found = re.search(rb'LINE_(\d\d)', screen)
    return int(found.group(1)) if found else None


def drain(fd, received, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if select.select([fd], [], [], 0.05)[0]:
            received.extend(os.read(fd, 65536))


class ScrollTest(unittest.TestCase):
    def test_wheel_scrolls_a_completed_output(self):
        lines = ['LINE_%02d %s' % (i, 'x' * 60) for i in range(60)]
        with socket.create_server(('127.0.0.1', 0)) as listener:
            listener.settimeout(5)
            endpoint = f'http://127.0.0.1:{listener.getsockname()[1]}/v1'
            with chat_terminal(binary, 'vllm', endpoint) as (master, _database, _child):
                os.write(master, b'wheel scroll\r')
                peer, _ = listener.accept()
                with peer, peer.makefile('rb') as request:
                    request.readline()
                    from http.client import parse_headers
                    headers = parse_headers(request)
                    request.read(int(headers['Content-Length']))
                    peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n')
                    peer.sendall(chunk({'content': '\n'.join(lines)}))
                    peer.sendall(chunk({'content': ''}, 'stop') + b'data: [DONE]\n\n')
                    peer.shutdown(socket.SHUT_WR)
                seen = bytearray()
                drain(master, seen, 2)
                bottom = painted_text(master, seen)
                self.assertIn(b'LINE_59', bottom)
                self.assertNotIn(b'LINE_00', bottom)

                for _ in range(12):
                    os.write(master, b'\x1b[<64;40;15M')
                    time.sleep(.05)
                drain(master, seen, .8)
                scrolled = painted_text(master, seen)
                top = first_marker(scrolled)
                if top is None:
                    self.fail('no transcript marker after wheel up')
                self.assertLess(top, 47, 'wheel up did not move the transcript')
                self.assertNotIn(b'LINE_59', scrolled)

                for _ in range(12):
                    os.write(master, b'\x1b[<65;40;15M')
                    time.sleep(.05)
                drain(master, seen, .8)
                returned = painted_text(master, seen)
                self.assertIn(b'LINE_59', returned)


if __name__ == '__main__':
    binary = Path(sys.argv.pop(1)).resolve(strict=True)
    unittest.main()
